package dhcp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/d2g/dhcp4"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/ipamapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/vishvananda/netlink"
)

const (
	localAddressSpace  = "LocalDefault"
	globalAddressSpace = "GlobalDefault"
	dhcpDriverName     = "dhcp"
	dhcpSrvrOpt        = "server"         // used for --ipam-opt server
	dhcpInterface      = "dhcp_interface" // used for --ipam-opt dhcp_interface
)

type dhcpLeaseTable map[string]*dhcpLease

type dhcpPoolTable map[string]*dhcpPool

type allocator struct {
	dhcpPools dhcpPoolTable
	sync.Mutex
	store datastore.DataStore
}

type dhcpLease struct {
	mac           net.HardwareAddr
	leaseIP       *net.IPNet
	gateway       *net.IPNet
	dpacket       *dhcp4.Packet
	parent        string
	preferredAddr bool
}

type dhcpPool struct {
	ID               string
	DhcpServer       net.IP
	IPv4Subnet       *net.IPNet
	Gateway          *net.IPNet
	DhcpInterface    string
	CreatedSlaveLink bool
	dhcpLeases       dhcpLeaseTable
	dbIndex          uint64
	dbExists         bool
	sync.Mutex
}

// Init registers the DHCP ipam driver with libnetwork
func Init(ic ipamapi.Callback, l, g interface{}) error {
	a := &allocator{
		dhcpPools: dhcpPoolTable{},
	}
	cps := a.GetCapabilities()
	err := ic.RegisterIpamDriverWithCapabilities(dhcpDriverName, a, cps)
	if err != nil {
		logrus.Errorf("error registering remote ipam driver dhcp due to %v", err)
	}
	a.initStore()

	return nil
}

func (a *allocator) IsBuiltIn() bool {
	return false
}

// GetCapabilities calls for mac addresses to be passed to this driver
func (a *allocator) GetCapabilities() *ipamapi.Capability {
	return &ipamapi.Capability{RequiresMACAddress: true}
}

// RequestPool will attempt to discover a subnet for the pool with a DHCP discover
func (a *allocator) RequestPool(addressSpace, pool, subPool string, options map[string]string, v6 bool) (string, *net.IPNet, map[string]string, error) {
	logrus.Debugf("RequestPool(addressSpace: %s, pool: %s, subPool: %s, options: %v)", addressSpace, pool, subPool, options)
	dp := &dhcpPool{
		dhcpLeases: dhcpLeaseTable{},
	}
	if subPool != "" || v6 {
		return "", nil, nil, fmt.Errorf("This request is not supported by the DHCP ipam driver")
	}
	for option, value := range options {
		switch option {
		case dhcpSrvrOpt:
			// parse DHCP server option '--ipam-opt server=x.x.x.x'
			if ok := isIPv4(value); !ok {
				// check for a resolvable DNS if not an IP
				resolvedIP, err := nameLookup(value)
				if err != nil {
					return "", nil, nil, fmt.Errorf("the specified DHCP server %s is neither an IPv4 address nor a resolvable DNS address", value)
				}
				dp.DhcpServer = resolvedIP
			} else {
				dp.DhcpServer = net.ParseIP(value)
			}
		case dhcpInterface:
			// parse DHCP interface option '--ipam-opt dhcp_interface=eth0'
			dp.DhcpInterface = value
			if !parentExists(dp.DhcpInterface) {
				if pool == "" {
					return "", nil, nil, fmt.Errorf("Spanning-Tree convergence can block forwarding and thus DHCP for up to 50 seconds. If creating VLAN subinterfaces, --gateway and --subnet are required in 'docker network create'.")
				}
				// if the subinterface parent_iface.vlan_id checks do not pass, return err.
				//  a valid example is 'eth0.10' for a parent iface 'eth0' with a vlan id '10'
				err := createVlanLink(dp.DhcpInterface)
				if err != nil {
					return "", nil, nil, fmt.Errorf("failed to create the %s subinterface: %v", value, err)
				}
				dp.CreatedSlaveLink = true
			}
		}
	}
	// require an interface to send DHCP discover and requests
	if dp.DhcpInterface == "" {
		return "", nil, nil, fmt.Errorf("required DHCP IPAM option -ipam-opt dhcp_interface= to specify which interface to send a DHCP request not found")
	}
	// if the --subnet is specified, skip DHCP DISCOVER attempts
	if pool != "" {
		_, poolNet, err := net.ParseCIDR(pool)
		if err != nil {
			return "", nil, nil, err
		}
		// sanity check user specified netmasks for /0 or /32 networks
		if poolNet.Mask.String() == "ffffffff" || poolNet.Mask.String() == "00000000" {
			return "", nil, nil, fmt.Errorf("Invalid specified pool netmasks /0 or /32 not allowed")
		}
		dp.IPv4Subnet = poolNet
		dp.ID = dp.IPv4Subnet.String()
		logrus.Debugf("Creating DHCP Discovered Network: %v, Gateway: %v", dp.IPv4Subnet, dp.Gateway)
		a.addPool(dp)
		// update persistent cache for host reboots or engine restarts
		err = a.storeUpdate(dp)
		return dp.IPv4Subnet.String(), dp.IPv4Subnet, options, nil
	}
	// Probe with a DHCP DISCOVER packet for the network
	err := dp.dhcpDiscoverPool()
	if err != nil {
		// on DHCP Discover failure rollback the subinterface if one was created
		if dp.CreatedSlaveLink && parentExists(dp.DhcpInterface) {
			// TODO: remove this block if discover on subint creation is not permitted
			err := delVlanLink(dp.DhcpInterface)
			if err != nil {
				logrus.Debugf("link %s was not deleted, continuing the pool request subinterface rollback: %v", dp.DhcpInterface, err)
			}
		}
		logrus.Error("Unable to find a DHCP service on the parent interface")
		return "", nil, nil, err
	}
	// Set the gateway label from the DHCP provided gateway
	options[netlabel.Gateway] = dp.Gateway.String()
	// Parse the network address from the DHCP Probe
	_, netCidr, err := net.ParseCIDR(dp.IPv4Subnet.String())
	if err != nil {
		return "", nil, nil, err
	}
	dp.ID = dp.IPv4Subnet.String()
	logrus.Debugf("Creating DHCP Discovered Network: %v, Gateway: %v", netCidr, dp.Gateway)
	a.addPool(dp)
	// update persistent cache for host reboots or engine restarts
	err = a.storeUpdate(dp)
	if err != nil {
		logrus.Errorf("adding DHCP Pool to datastore failed: %v", err)
	}

	return dp.IPv4Subnet.String(), netCidr, options, nil
}

// RequestAddress calls the ipam driver for an IP address for a create endpoint event
func (a *allocator) RequestAddress(poolID string, prefAddress net.IP, opts map[string]string) (*net.IPNet, map[string]string, error) {
	logrus.Debugf("Received Address Request Pool ID: %s, Preffered Address: %v, Options: %v", poolID, prefAddress, opts)
	poolNetAddr, PoolNet, err := net.ParseCIDR(poolID)
	if err != nil {
		return nil, nil, err
	}
	// lookup the pool id and verify it exists
	n, err := a.getPool(poolID)
	if err != nil {
		return nil, nil, fmt.Errorf("pool ID %s not found", poolID)
	}
	// if the network create includes --subnet & --gateway the gateway will be passed as preAddress
	if opts[ipamapi.RequestAddressType] == netlabel.Gateway && prefAddress != nil {
		// append the pool v4 subnet netmask to the gateway to create a proper cidr
		n.Gateway = &net.IPNet{
			IP:   prefAddress,
			Mask: n.IPv4Subnet.Mask,
		}
		// return the requested gateway label
		return n.Gateway, nil, nil
	}
	// if the network create includes --subnet but not --gateway, infer a gateway
	if opts[ipamapi.RequestAddressType] == netlabel.Gateway {
		n.Gateway = inferGateway(poolNetAddr, PoolNet)
		logrus.Infof("no --gateway= was passed, infering a gateway of %s for the user specified --network=%s",
			n.Gateway.IP.String(), n.IPv4Subnet.String())
		// return the requested gateway label
		return n.Gateway, nil, nil
	}
	// parse the mac address that is sent due to ipam capability
	macAddr := opts[netlabel.MacAddress]
	if len(macAddr) <= 0 {
		return PoolNet, nil, fmt.Errorf("no mac address found in the request address call")
	}
	// Preferred addresses w/DHCP driver currently rejected by libnetwork since --subnet not passed by user
	if prefAddress != nil {
		staticAddr, err := a.preferredAddrHandler(prefAddress, PoolNet)
		if err != nil {
			return nil, nil, err
		}
		// return the static preferred address
		return staticAddr.leaseIP, nil, nil
	}
	// Request a DHCP lease from the DHCP server
	lease, err := requestDHCPLease(macAddr, n.DhcpInterface)
	if err != nil {
		// fail the request if a DHCP lease is unavailable
		return nil, nil, err
	}
	// verify the DHCP lease falls within the network pool. If the DHCP network has changed,
	// the discovered pool and network will be invalid and the network will need to be recreated.
	if ok := netContains(lease.leaseIP.IP, n.IPv4Subnet); !ok {
		return nil, nil, fmt.Errorf("the DHCP assigned address %s is not valid in the pool network %s If the DHCP network has changed, recreate the network for new discovery",
			lease.leaseIP.IP.String(), n.IPv4Subnet.String())
	}
	logrus.Debugf("DHCP request returned a lease of IP: %v, Gateway: %v", lease.leaseIP, lease.gateway)
	// bind the lease to the lease table and store ack details for a dhcp release
	n.addLease(lease)
	// leases are not stored in persistent datastore, ony pools are stored.
	return lease.leaseIP, nil, nil
}

// GetDefaultAddressSpaces returns the local and global default address spaces
func (a *allocator) GetDefaultAddressSpaces() (string, string, error) {
	return localAddressSpace, globalAddressSpace, nil
}

// ReleasePool releases the address pool - always succeeds
func (a *allocator) ReleasePool(poolID string) error {
	dp, err := a.getPool(poolID)
	if err != nil {
		logrus.Debugf("Pool ID %s not found", poolID)
		return nil
	}
	// if the driver created the slave interface, delete it, otherwise leave it
	if ok := dp.CreatedSlaveLink; ok {
		// if the interface exists, only delete if it matches iface.vlan or dummy.net_id naming
		if ok := parentExists(dp.DhcpInterface); ok {
			// only delete the link if it is named the net_id
			// only delete the link if it matches iface.vlan naming
			err := delVlanLink(dp.DhcpInterface)
			if err != nil {
				logrus.Debugf("link %s was not deleted, continuing the release pool operation: %v",
					dp.DhcpInterface, err)
			}
		}
	}
	a.deletePool(poolID)
	// remove the pool from persistent k/v store
	err = a.storeDelete(dp)
	if err != nil {
		logrus.Debugf("Delete Pool from datastore failed: %v", err)
	}
	logrus.Debugf("Releasing DHCP pool %s)", poolID)

	return nil
}

// ReleaseAddress releases the address - always succeeds
func (a *allocator) ReleaseAddress(poolID string, address net.IP) error {
	logrus.Debugf("Release DHCP address Pool ID: %s Address: %v", poolID, address)
	// lookup the pool the lease is stored in
	n, err := a.getPool(poolID)
	if err != nil {
		logrus.Errorf("Pool ID %s not found", poolID)
		return nil
	}
	// if the address to release is the gateway ignore it
	if n.Gateway.IP != nil {
		if address.String() == n.Gateway.IP.String() {
			logrus.Debugf("Release request is for a gateway address, no DHCP release required")
			return nil
		}
	}
	// construct cidr address+mask for lease key
	leaseID := &net.IPNet{
		IP:   address,
		Mask: n.IPv4Subnet.Mask,
	}
	// get the lease to send the dhcp ack in the release
	l, err := n.getLease(leaseID.String())
	if l == nil || l.preferredAddr {
		return nil
	}
	l.release()
	n.deleteLease(leaseID.String())

	return nil
}

// DiscoverNew informs the allocator about a new global scope datastore
func (a *allocator) DiscoverNew(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

// DiscoverDelete is a notification of no interest for the allocator
func (a *allocator) DiscoverDelete(dType discoverapi.DiscoveryType, data interface{}) error {
	return nil
}

func (a *allocator) preferredAddrHandler(prefAddress net.IP, pool *net.IPNet) (*dhcpLease, error) {
	// set preferred address so as not to attempt a DHCP release
	l := &dhcpLease{
		preferredAddr: true,
	}
	// set the preferred IP address rather then a DHCP address
	l.leaseIP = &net.IPNet{
		IP:   prefAddress,
		Mask: pool.Mask,
	}
	// verify the preferred address is a valid address in the requested pool
	if ok := netContains(l.leaseIP.IP, pool); !ok {
		return nil, fmt.Errorf("the requested IP address %s is not valid in the pool network %s If the DHCP network has changed, recreate the network for new discovery",
			l.leaseIP.IP.String(), pool.String())
	}

	return l, nil
}

// createVlanLink parses sub-interfaces and vlan id for creation
func createVlanLink(parentName string) error {
	if strings.Contains(parentName, ".") {
		parent, vidInt, err := parseVlan(parentName)
		if err != nil {
			return err
		}
		// VLAN identifier or VID is a 12-bit field specifying the VLAN to which the frame belongs
		if vidInt > 4094 || vidInt < 1 {
			return fmt.Errorf("vlan id must be between 1-4094, received: %d", vidInt)
		}
		// get the parent link to attach a vlan subinterface
		parentLink, err := netlink.LinkByName(parent)
		if err != nil {
			return fmt.Errorf("failed to find master interface %s on the Docker host: %v", parent, err)
		}
		vlanLink := &netlink.Vlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:        parentName,
				ParentIndex: parentLink.Attrs().Index,
			},
			VlanId: vidInt,
		}
		// create the subinterface
		if err := netlink.LinkAdd(vlanLink); err != nil {
			return fmt.Errorf("failed to create %s vlan link: %v", vlanLink.Name, err)
		}
		// Bring the new netlink iface up
		if err := netlink.LinkSetUp(vlanLink); err != nil {
			return fmt.Errorf("failed to enable %s the dhcp interface link %v", vlanLink.Name, err)
		}
		logrus.Debugf("Added a vlan tagged netlink subinterface: %s with a vlan id: %d", parentName, vidInt)
		return nil
	}

	return fmt.Errorf("invalid subinterface vlan name %s, example formatting is eth0.10", parentName)
}

// delVlanLink verifies only sub-interfaces with a vlan id get deleted
func delVlanLink(linkName string) error {
	if strings.Contains(linkName, ".") {
		_, _, err := parseVlan(linkName)
		if err != nil {
			return err
		}
		// delete the vlan subinterface
		vlanLink, err := netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to find interface %s on the Docker host : %v", linkName, err)
		}
		// verify a parent interface isn't being deleted
		if vlanLink.Attrs().ParentIndex == 0 {
			return fmt.Errorf("interface %s does not appear to be a slave device: %v", linkName, err)
		}
		// delete the dhcp vlan interface slave device
		if err := netlink.LinkDel(vlanLink); err != nil {
			return fmt.Errorf("failed to delete  %s link: %v", linkName, err)
		}
		logrus.Debugf("Deleted a vlan tagged netlink subinterface: %s", linkName)
	}
	// if the subinterface doesn't parse to iface.vlan_id leave the interface in
	// place since it could be a user specified name not created by the driver.
	return nil
}

// parseVlan parses and verifies a slave interface name: -o parent=eth0.10
func parseVlan(linkName string) (string, int, error) {
	// parse -o parent=eth0.10
	splitName := strings.Split(linkName, ".")
	if len(splitName) != 2 {
		return "", 0, fmt.Errorf("required interface name format is: name.vlan_id, ex. eth0.10 for vlan 10, instead received %s", linkName)
	}
	parent, vidStr := splitName[0], splitName[1]
	// validate type and convert vlan id to int
	vidInt, err := strconv.Atoi(vidStr)
	if err != nil {
		return "", 0, fmt.Errorf("unable to parse a valid vlan id from: %s (ex. eth0.10 for vlan 10)", vidStr)
	}
	// Check if the interface exists
	if !parentExists(parent) {
		return "", 0, fmt.Errorf("-o parent interface does was not found on the host: %s", parent)
	}

	return parent, vidInt, nil
}

// parentExists check if the specified interface exists in the default namespace
func parentExists(ifaceStr string) bool {
	_, err := netlink.LinkByName(ifaceStr)
	if err != nil {
		return false
	}

	return true
}

// nameLookup attempts to resolve a name to IP
func nameLookup(s string) (net.IP, error) {
	ipAddr, err := net.ResolveIPAddr("ip", s)

	return ipAddr.IP, err
}

// isIPv4 verifies the network is IPv4
func isIPv4(s string) bool {
	srvrAddr := net.ParseIP(s)

	return srvrAddr.To4() != nil
}

// ipGateway increments the next address to infer a usable gateway if not defined
func inferGateway(netAddr net.IP, poolNet *net.IPNet) *net.IPNet {
	for i := 15; i >= 0; i-- {
		b := netAddr[i]
		if b < 255 {
			netAddr[i] = b + 1
			for ii := i + 1; ii <= 15; ii++ {
				netAddr[ii] = 0
			}
			break
		}
	}
	return &net.IPNet{IP: netAddr, Mask: poolNet.Mask}
}

// netContains is used to verify the DHCP lease falls within the bounds of the pool
func netContains(addr net.IP, netPool *net.IPNet) bool {
	return netPool.Contains(addr)
}
