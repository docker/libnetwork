package dhcp

import (
	"fmt"
	"net"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/d2g/dhcp4"
	"github.com/d2g/dhcp4client"
	"github.com/vishvananda/netlink"
)

var dummyMacAddr = net.HardwareAddr([]byte{02, 17, 17, 17, 17, 17}) // used for DHCP DISCOVER

// requestDHCPLease creates a DHCP REQUEST for a new IP address lease for a container
func requestDHCPLease(macaddr, parent string) (*dhcpLease, error) {
	hwaddr, err := net.ParseMAC(macaddr)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse a valid mac address from %s: %v", macaddr, err)
	}
	l := &dhcpLease{
		mac:    hwaddr,
		parent: parent,
	}
	link, err := netlink.LinkByName(l.parent)
	if err != nil {
		return nil, err
	}
	client, err := dhcpSocket(l.mac, link)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	if err != nil {
		return nil, fmt.Errorf("unable to create a DHCP client request: ")
	}
	ok, ack, err := client.Request()
	if !ok || err != nil {
		// replacing the dhcp4 library message of "resource temporarily unavailable" with a more informative one
		return nil, fmt.Errorf("DHCP discovery failed, ensure interface %s is in promiscous mode and an active DHCP server is available",
			link.Attrs().Name)
	}
	if err != nil {
		networkError := err.(*net.OpError)
		if ok && networkError.Timeout() {
			return nil, fmt.Errorf("Cannot find DHCP server: %v", networkError)
		}
	}
	opts := ack.ParseOptions()
	if ack == nil {
		return nil, fmt.Errorf("Null or unhandled DHCP response")
	}
	l.dpacket = &ack
	netmask := getNetMask(opts)
	// ensure the required fields are not null
	if netmask == nil || l.dpacket.YIAddr() == nil {
		return nil, fmt.Errorf("invalid DHCP configuration, network and gateway must not be empty")
	}
	// set the DHCP lease network configuration
	l.leaseIP = &net.IPNet{
		IP:   l.dpacket.YIAddr(),
		Mask: netmask,
	}

	return l, nil
}

// dhcpSocket builds the dhcp4client using the user specified dhcp_interface= link to send DHCP REQUESTS/DISCOVERS
func dhcpSocket(hwaddr net.HardwareAddr, link netlink.Link) (*dhcp4client.Client, error) {
	psock, err := dhcp4client.NewPacketSock(link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	return dhcp4client.New(
		dhcp4client.HardwareAddr(hwaddr),
		dhcp4client.Broadcast(false),
		dhcp4client.Timeout(5*time.Second),
		dhcp4client.Connection(psock),
	)
}

// release the DHCP lease back to the DHCP server pool, the data from the request ACK are used
func (dl *dhcpLease) release() error {
	logrus.Infof("Releasing lease for container address %s", dl.leaseIP.IP.String())

	link, err := netlink.LinkByName(dl.parent)
	if err != nil {
		return err
	}
	c, err := dhcpSocket(dl.mac, link)
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.Release(*dl.dpacket); err != nil {
		logrus.Debugf("failed to release the DHCP lease")
	}

	return nil
}

// dhcpDiscoverPool sends a DHCP DISCOVER out the user specified dhcp_interface= link to discover the network pool
func (dp *dhcpPool) dhcpDiscoverPool() error {
	link, err := netlink.LinkByName(dp.DhcpInterface)
	if err != nil {
		return err
	}
	// use the parent interface MAC address for DHCP pool discovery
	client, err := dhcpSocket(dummyMacAddr, link)
	if err != nil {
		return err
	}
	defer client.Close()
	if err != nil {
		return fmt.Errorf("Unable to create a DHCP client request: %v", err)
	}
	disc, err := client.SendDiscoverPacket()
	if err != nil {
		return fmt.Errorf("DHCP discover failed, ensure there is a DHCP server running on requested segment: %v", err)
	}
	if disc == nil {
		return fmt.Errorf("Null or unhandled DHCP discover response")
	}
	discovered, err := client.GetOffer(&disc)
	if err != nil {
		// replacing the dhcp4 library message of "resource temporarily unavailable" with a more informative one
		return fmt.Errorf("DHCP discovery failed, ensure interface %s is in promiscous mode and an active DHCP server is available",
			link.Attrs().Name)
	}
	// parse and bind the results of the discovery offer
	opts := discovered.ParseOptions()
	gw4 := getGateway(opts)
	netmask := getNetMask(opts)
	dp.DhcpServer = getDhcpServer(opts)
	// ensure the required fields are not null
	if gw4 == nil || netmask == nil || discovered.YIAddr() == nil {
		return fmt.Errorf("invalid DHCP configuration, network and gateway must not be empty")
	}
	dp.IPv4Subnet = &net.IPNet{
		IP:   discovered.YIAddr(),
		Mask: netmask,
	}
	// parse the network CIDR the net pool to ensure a proper CIDR net is returned
	_, dp.IPv4Subnet, err = net.ParseCIDR(dp.IPv4Subnet.String())
	if err != nil {
		return err
	}
	// set the DHCP pool gateway configuration
	dp.Gateway = &net.IPNet{
		IP:   gw4,
		Mask: netmask,
	}
	logrus.Debugf("DHCP discovered network IP: %s, Gateway: %s", dp.IPv4Subnet.String(), dp.Gateway.String())

	return nil
}

// getSubnet decodes net.IPMask from dhcp op code1
func getNetMask(opts dhcp4.Options) net.IPMask {
	if opts, ok := opts[dhcp4.OptionSubnetMask]; ok {
		return net.IPMask(opts)
	}

	return nil
}

// getSubnet decodes net.IP from dhcp op code3
func getGateway(opts dhcp4.Options) net.IP {
	if opts, ok := opts[dhcp4.OptionRouter]; ok {
		if len(opts) == 4 {
			return net.IP(opts)
		}
	}

	return nil
}

// getDhcpServer decodes net.IP from dhcp op code54 representing the DHCP server id/src_ip
func getDhcpServer(opts dhcp4.Options) net.IP {
	if opts, ok := opts[dhcp4.OptionServerIdentifier]; ok {
		return net.IP(opts)
	}

	return nil
}
