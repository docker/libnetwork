// +build solaris

package bridge

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/types"
)

var (
	defaultBindingIP = net.IPv4(0, 0, 0, 0)
)

const (
	maxAllocatePortAttempts = 10
)

func addPFRules(epid, bindIntf string, bs []types.PortBinding) {
	var id string

	if len(epid) > 12 {
		id = epid[:12]
	} else {
		id = epid
	}

	fname := "/var/lib/docker/network/files/pf." + id

	f, err := os.OpenFile(fname,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		logrus.Warn("cannot open temp pf file")
		return
	}
	for _, b := range bs {
		r := fmt.Sprintf(
			"pass in on %s proto %s from any to (%s) "+
				"port %d rdr-to %s port %d\n", bindIntf,
			b.Proto.String(), bindIntf, b.HostPort,
			b.IP.String(), b.Port)
		_, err = f.WriteString(r)
		if err != nil {
			logrus.Warnf("cannot write firewall rules to %s: %v", fname, err)
		}
	}
	f.Close()

	anchor := fmt.Sprintf("_auto/docker/ep%s", id)
	err = exec.Command("/usr/sbin/pfctl", "-a", anchor, "-f", fname).Run()
	if err != nil {
		logrus.Warnf("failed to add firewall rules: %v", err)
	}
	os.Remove(fname)
}

func removePFRules(epid string) {
	var id string

	if len(epid) > 12 {
		id = epid[:12]
	} else {
		id = epid
	}

	anchor := fmt.Sprintf("_auto/docker/ep%s", id)
	err := exec.Command("/usr/sbin/pfctl", "-a", anchor, "-F", "all").Run()
	if err != nil {
		logrus.Warnf("failed to remove firewall rules: %v", err)
	}
}

func (n *bridgeNetwork) allocatePorts(ep *bridgeEndpoint, reqDefBindIP net.IP) ([]types.PortBinding, error) {
	if ep.extConnConfig == nil || ep.extConnConfig.PortBindings == nil {
		return nil, nil
	}

	defHostIP := defaultBindingIP
	if reqDefBindIP != nil {
		defHostIP = reqDefBindIP
	}

	bs := make([]types.PortBinding, 0, len(ep.extConnConfig.PortBindings))
	for _, bnd := range ep.extConnConfig.PortBindings {
		cp := bnd.GetCopy()
		if len(cp.HostIP) == 0 {
			cp.HostIP = defHostIP
		}
		if cp.HostPortEnd == 0 {
			cp.HostPortEnd = cp.HostPort
		}
		cp.IP = ep.addr.IP
		bs = append(bs, cp)
	}

	err := n.portMapper.MapPorts(bs)
	return bs, err
}

func (n *bridgeNetwork) releasePorts(ep *bridgeEndpoint) error {
	err := n.releasePortsInternal(ep.portMapping)
	if err != nil {
		return nil
	}

	// remove rules if there are any port mappings
	if len(ep.portMapping) > 0 {
		removePFRules(ep.id)
	}

	return nil

}

func (n *bridgeNetwork) releasePortsInternal(bindings []types.PortBinding) error {
	var errorBuf bytes.Buffer

	// Attempt to release all port bindings, do not stop on failure
	for _, m := range bindings {
		if err := n.releasePort(m); err != nil {
			errorBuf.WriteString(
				fmt.Sprintf(
					"\ncould not release %v because of %v",
					m, err))
		}
	}

	if errorBuf.Len() != 0 {
		return errors.New(errorBuf.String())
	}
	return nil
}

func (n *bridgeNetwork) releasePort(bnd types.PortBinding) error {
	// Construct the host side transport address
	host, err := bnd.HostAddr()
	if err != nil {
		return err
	}
	return n.portMapper.Unmap(host)
}
