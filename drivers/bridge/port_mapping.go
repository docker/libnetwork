package bridge

import (
	"bytes"
	"errors"
	"fmt"
	"net"

	"github.com/docker/libnetwork/types"
)

var (
	defaultBindingIP = net.IPv4(0, 0, 0, 0)
)

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
	return n.releasePortsInternal(ep.portMapping)
}

func (n *bridgeNetwork) releasePortsInternal(bindings []types.PortBinding) error {
	var errorBuf bytes.Buffer

	// Attempt to release all port bindings, do not stop on failure
	for _, m := range bindings {
		if err := n.releasePort(m); err != nil {
			errorBuf.WriteString(fmt.Sprintf("\ncould not release %v because of %v", m, err))
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
