package bridge

import (
	"fmt"
	"math/rand"
	"net"

	log "github.com/docker/libnetwork/Godeps/_workspace/src/github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/Godeps/_workspace/src/github.com/docker/docker/pkg/parsers/kernel"
	"github.com/docker/libnetwork/Godeps/_workspace/src/github.com/vishvananda/netlink"
)

func // SetupDevice create a new bridge interface/
setupDevice(i *bridgeInterface) error {
	// We only attempt to create the bridge when the requested device name is
	// the default one.
	if i.Config.BridgeName != DefaultBridgeName {
		return fmt.Errorf("bridge device with non default name %q must be created manually", i.Config.BridgeName)
	}

	// Set the bridgeInterface netlink.Bridge.
	i.Link = &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: i.Config.BridgeName,
		},
	}

	// Only set the bridge's MAC address if the kernel version is > 3.3, as it
	// was not supported before that.
	kv, err := kernel.GetKernelVersion()
	if err == nil && (kv.Kernel >= 3 && kv.Major >= 3) {
		i.Link.Attrs().HardwareAddr = generateRandomMAC()
		log.Debugf("Setting bridge mac address to %s", i.Link.Attrs().HardwareAddr)
	}

	// Call out to netlink to create the device.
	return netlink.LinkAdd(i.Link)
}

// SetupDeviceUp ups the given bridge interface.
func setupDeviceUp(i *bridgeInterface) error {
	err := netlink.LinkSetUp(i.Link)
	if err != nil {
		return err
	}

	// Attempt to update the bridge interface to refresh the flags status,
	// ignoring any failure to do so.
	if lnk, err := netlink.LinkByName(i.Config.BridgeName); err == nil {
		i.Link = lnk
	}
	return nil
}

func generateRandomMAC() net.HardwareAddr {
	hw := make(net.HardwareAddr, 6)
	for i := 0; i < 6; i++ {
		hw[i] = byte(rand.Intn(255))
	}
	hw[0] &^= 0x1 // clear multicast bit
	hw[0] |= 0x2  // set local assignment bit (IEEE802)
	return hw
}
