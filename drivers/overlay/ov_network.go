package overlay

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	"github.com/docker/libnetwork/osl"
	"github.com/docker/libnetwork/resolvconf"
	"github.com/docker/libnetwork/types"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var (
	hostMode     bool
	hostModeOnce sync.Once
)

type networkTable map[string]*network

type subnet struct {
	once      *sync.Once
	vxlanName string
	brName    string
	vni       uint32
	initErr   error
	subnetIP  *net.IPNet
	gwIP      *net.IPNet
}

type subnetJSON struct {
	SubnetIP string
	GwIP     string
	Vni      uint32
}

type network struct {
	id        string
	dbIndex   uint64
	dbExists  bool
	sbox      osl.Sandbox
	endpoints endpointTable
	driver    *driver
	joinCnt   int
	once      *sync.Once
	initEpoch int
	initErr   error
	*networkConfiguration
	sync.Mutex
}

type networkConfiguration struct {
	subnets          []*subnet
	disableDefaultGW bool
}

func (d *driver) CreateNetwork(id string, option map[string]interface{}, ipV4Data, ipV6Data []driverapi.IPAMData) error {
	if id == "" {
		return fmt.Errorf("invalid network id")
	}

	// Since we perform lazy configuration make sure we try
	// configuring the driver when we enter CreateNetwork
	if err := d.configure(); err != nil {
		return err
	}

	n := &network{
		id:                   id,
		driver:               d,
		endpoints:            endpointTable{},
		once:                 &sync.Once{},
		networkConfiguration: &networkConfiguration{subnets: []*subnet{}},
	}
	n.parseNetworkOptions(option)

	for _, ipd := range ipV4Data {
		s := &subnet{
			subnetIP: ipd.Pool,
			gwIP:     ipd.Gateway,
			once:     &sync.Once{},
		}
		n.subnets = append(n.subnets, s)
	}

	if err := n.writeToStore(); err != nil {
		return fmt.Errorf("failed to update data store for network %v: %v", n.id, err)
	}

	d.addNetwork(n)

	return nil
}

func (d *driver) DeleteNetwork(nid string) error {
	if nid == "" {
		return fmt.Errorf("invalid network id")
	}

	n := d.network(nid)
	if n == nil {
		return fmt.Errorf("could not find network with id %s", nid)
	}

	d.deleteNetwork(nid)

	return n.releaseVxlanID()
}

func (n *network) incEndpointCount() {
	n.Lock()
	defer n.Unlock()
	n.joinCnt++
}

func (n *network) joinSandbox() error {
	// If there is a race between two go routines here only one will win
	// the other will wait.
	n.once.Do(func() {
		// save the error status of initSandbox in n.initErr so that
		// all the racing go routines are able to know the status.
		n.initErr = n.initSandbox()
	})

	return n.initErr
}

func (n *network) joinSubnetSandbox(s *subnet) error {
	s.once.Do(func() {
		s.initErr = n.initSubnetSandbox(s)
	})
	return s.initErr
}

func (n *network) leaveSandbox() {
	n.Lock()
	n.joinCnt--
	if n.joinCnt != 0 {
		n.Unlock()
		return
	}

	// We are about to destroy sandbox since the container is leaving the network
	// Reinitialize the once variable so that we will be able to trigger one time
	// sandbox initialization(again) when another container joins subsequently.
	n.once = &sync.Once{}
	for _, s := range n.subnets {
		s.once = &sync.Once{}
	}
	n.Unlock()

	n.destroySandbox()
}

func (n *network) destroySandbox() {
	sbox := n.sandbox()
	if sbox != nil {
		for _, iface := range sbox.Info().Interfaces() {
			iface.Remove()
		}

		for _, s := range n.subnets {
			if hostMode {
				if err := removeFilters(n.id[:12], s.brName); err != nil {
					logrus.Warnf("Could not remove overlay filters: %v", err)
				}
			}

			if s.vxlanName != "" {
				err := deleteVxlan(s.vxlanName)
				if err != nil {
					logrus.Warnf("could not cleanup sandbox properly: %v", err)
				}
			}
		}

		if hostMode {
			if err := removeNetworkChain(n.id[:12]); err != nil {
				logrus.Warnf("could not remove network chain: %v", err)
			}
		}

		sbox.Destroy()
		n.setSandbox(nil)
	}
}

func setHostMode() {
	if os.Getenv("_OVERLAY_HOST_MODE") != "" {
		hostMode = true
		return
	}

	err := createVxlan("testvxlan", 1)
	if err != nil {
		logrus.Errorf("Failed to create testvxlan interface: %v", err)
		return
	}

	defer deleteVxlan("testvxlan")

	path := "/proc/self/ns/net"
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		logrus.Errorf("Failed to open path %s for network namespace for setting host mode: %v", path, err)
		return
	}
	defer f.Close()

	nsFD := f.Fd()

	iface, err := netlink.LinkByName("testvxlan")
	if err != nil {
		logrus.Errorf("Failed to get link testvxlan: %v", err)
		return
	}

	// If we are not able to move the vxlan interface to a namespace
	// then fallback to host mode
	if err := netlink.LinkSetNsFd(iface, int(nsFD)); err != nil {
		hostMode = true
	}
}

func (n *network) generateVxlanName(s *subnet) string {
	return "vx-" + fmt.Sprintf("%06x", n.vxlanID(s)) + "-" + n.id[:5]
}

func (n *network) generateBridgeName(s *subnet) string {
	return "ov-" + fmt.Sprintf("%06x", n.vxlanID(s)) + "-" + n.id[:5]
}

func isOverlap(nw *net.IPNet) bool {
	var nameservers []string

	if rc, err := resolvconf.Get(); err == nil {
		nameservers = resolvconf.GetNameserversAsCIDR(rc.Content)
	}

	if err := netutils.CheckNameserverOverlaps(nameservers, nw); err != nil {
		return true
	}

	if err := netutils.CheckRouteOverlaps(nw); err != nil {
		return true
	}

	return false
}

func (n *network) initSubnetSandbox(s *subnet) error {
	if hostMode && isOverlap(s.subnetIP) {
		return fmt.Errorf("overlay subnet %s has conflicts in the host while running in host mode", s.subnetIP.String())
	}

	// create a bridge and vxlan device for this subnet and move it to the sandbox
	brName := n.generateBridgeName(s)
	sbox := n.sandbox()

	if err := sbox.AddInterface(brName, "br",
		sbox.InterfaceOptions().Address(s.gwIP),
		sbox.InterfaceOptions().Bridge(true)); err != nil {
		return fmt.Errorf("bridge creation in sandbox failed for subnet %q: %v", s.subnetIP.String(), err)
	}

	vxlanName := n.generateVxlanName(s)

	// Try to delete the vxlan interface if already present
	deleteVxlan(vxlanName)

	err := createVxlan(vxlanName, n.vxlanID(s))
	if err != nil {
		return err
	}

	if err := sbox.AddInterface(vxlanName, "vxlan",
		sbox.InterfaceOptions().Master(brName)); err != nil {
		return fmt.Errorf("vxlan interface creation failed for subnet %q: %v", s.subnetIP.String(), err)
	}

	if hostMode {
		if err := addFilters(n.id[:12], brName); err != nil {
			return err
		}
	}

	n.Lock()
	s.vxlanName = vxlanName
	s.brName = brName
	n.Unlock()

	return nil
}

func (n *network) initSandbox() error {
	n.Lock()
	n.initEpoch++
	n.Unlock()

	hostModeOnce.Do(setHostMode)

	if hostMode {
		if err := addNetworkChain(n.id[:12]); err != nil {
			return err
		}
	}

	sbox, err := osl.NewSandbox(
		osl.GenerateKey(fmt.Sprintf("%d-", n.initEpoch)+n.id), !hostMode)
	if err != nil {
		return fmt.Errorf("could not create network sandbox: %v", err)
	}

	n.setSandbox(sbox)

	n.driver.peerDbUpdateSandbox(n.id)

	var nlSock *nl.NetlinkSocket
	sbox.InvokeFunc(func() {
		nlSock, err = nl.Subscribe(syscall.NETLINK_ROUTE, syscall.RTNLGRP_NEIGH)
		if err != nil {
			err = fmt.Errorf("failed to subscribe to neighbor group netlink messages")
		}
	})

	go n.watchMiss(nlSock)
	return nil
}

func (n *network) watchMiss(nlSock *nl.NetlinkSocket) {
	for {
		msgs, err := nlSock.Receive()
		if err != nil {
			logrus.Errorf("Failed to receive from netlink: %v ", err)
			continue
		}

		for _, msg := range msgs {
			if msg.Header.Type != syscall.RTM_GETNEIGH && msg.Header.Type != syscall.RTM_NEWNEIGH {
				continue
			}

			neigh, err := netlink.NeighDeserialize(msg.Data)
			if err != nil {
				logrus.Errorf("Failed to deserialize netlink ndmsg: %v", err)
				continue
			}

			if neigh.IP.To16() != nil {
				continue
			}

			if neigh.State&(netlink.NUD_STALE|netlink.NUD_INCOMPLETE) == 0 {
				continue
			}

			mac, IPmask, vtep, err := n.driver.resolvePeer(n.id, neigh.IP)
			if err != nil {
				logrus.Errorf("could not resolve peer %q: %v", neigh.IP, err)
				continue
			}

			if err := n.driver.peerAdd(n.id, "dummy", neigh.IP, IPmask, mac, vtep, true); err != nil {
				logrus.Errorf("could not add neighbor entry for missed peer %q: %v", neigh.IP, err)
			}
		}
	}
}

func (d *driver) addNetwork(n *network) {
	d.Lock()
	d.networks[n.id] = n
	d.Unlock()
}

func (d *driver) deleteNetwork(nid string) {
	d.Lock()
	delete(d.networks, nid)
	d.Unlock()
}

func (d *driver) network(nid string) *network {
	d.Lock()
	networks := d.networks
	d.Unlock()

	n, ok := networks[nid]
	if !ok {
		n = d.getNetworkFromStore(nid)
		if n != nil {
			n.driver = d
			n.endpoints = endpointTable{}
			n.once = &sync.Once{}
			networks[nid] = n
		}
	}

	return n
}

func (d *driver) getNetworkFromStore(nid string) *network {
	if d.store == nil {
		return nil
	}

	n := &network{id: nid}
	if err := d.store.GetObject(datastore.Key(n.Key()...), n); err != nil {
		return nil
	}

	return n
}

func (n *network) sandbox() osl.Sandbox {
	n.Lock()
	defer n.Unlock()

	return n.sbox
}

func (n *network) setSandbox(sbox osl.Sandbox) {
	n.Lock()
	n.sbox = sbox
	n.Unlock()
}

func (n *network) vxlanID(s *subnet) uint32 {
	n.Lock()
	defer n.Unlock()

	return s.vni
}

func (n *network) setVxlanID(s *subnet, vni uint32) {
	n.Lock()
	s.vni = vni
	n.Unlock()
}

func (n *network) Key() []string {
	return []string{"overlay", "network", n.id}
}

func (n *network) KeyPrefix() []string {
	return []string{"overlay", "network"}
}

func (n *network) Value() []byte {
	b, err := json.Marshal(n.networkConfiguration)
	if err != nil {
		return []byte{}
	}
	return b
}

func (n *network) Index() uint64 {
	return n.dbIndex
}

func (n *network) SetIndex(index uint64) {
	n.dbIndex = index
	n.dbExists = true
}

func (n *network) Exists() bool {
	return n.dbExists
}

func (n *network) Skip() bool {
	return false
}

func (n *network) SetValue(value []byte) error {
	var nc *networkConfiguration
	newNet := n.networkConfiguration == nil || len(n.subnets) == 0
	if err := json.Unmarshal(value, &nc); err != nil {
		// compatible with previous format
		nc = &networkConfiguration{subnets: []*subnet{}}
		netJSON := []*subnetJSON{}
		err := json.Unmarshal(value, &netJSON)
		if err != nil {
			return err
		}
		for _, nj := range netJSON {
			gwIP, _ := types.ParseCIDR(nj.GwIP)
			subnetIP, _ := types.ParseCIDR(nj.SubnetIP)
			nc.subnets = append(nc.subnets, &subnet{
				vni:      nj.Vni,
				gwIP:     gwIP,
				subnetIP: subnetIP,
			})
		}
	}

	if newNet {
		n.networkConfiguration = &networkConfiguration{subnets: []*subnet{}}
	}
	n.disableDefaultGW = nc.disableDefaultGW
	for _, s := range nc.subnets {
		vni := s.vni
		subnetIP := s.subnetIP
		gwIP := s.gwIP

		if newNet {
			s := &subnet{
				subnetIP: subnetIP,
				gwIP:     gwIP,
				vni:      vni,
				once:     &sync.Once{},
			}
			n.subnets = append(n.subnets, s)
		} else {
			sNet := n.getMatchingSubnet(subnetIP)
			if sNet != nil {
				sNet.vni = vni
			}
		}
	}
	return nil
}

func (n *network) DataScope() string {
	return datastore.GlobalScope
}

func (n *network) writeToStore() error {
	return n.driver.store.PutObjectAtomic(n)
}

func (n *network) releaseVxlanID() error {
	if n.driver.store == nil {
		return fmt.Errorf("no datastore configured. cannot release vxlan id")
	}

	if len(n.subnets) == 0 {
		return nil
	}

	if err := n.driver.store.DeleteObjectAtomic(n); err != nil {
		if err == datastore.ErrKeyModified || err == datastore.ErrKeyNotFound {
			// In both the above cases we can safely assume that the key has been removed by some other
			// instance and so simply get out of here
			return nil
		}

		return fmt.Errorf("failed to delete network to vxlan id map: %v", err)
	}

	for _, s := range n.subnets {
		n.driver.vxlanIdm.Release(uint64(n.vxlanID(s)))
		n.setVxlanID(s, 0)
	}
	return nil
}

func (n *network) obtainVxlanID(s *subnet) error {
	//return if the subnet already has a vxlan id assigned
	if s.vni != 0 {
		return nil
	}

	if n.driver.store == nil {
		return fmt.Errorf("no datastore configured. cannot obtain vxlan id")
	}

	for {
		if err := n.driver.store.GetObject(datastore.Key(n.Key()...), n); err != nil {
			return fmt.Errorf("getting network %q from datastore failed %v", n.id, err)
		}

		if s.vni == 0 {
			vxlanID, err := n.driver.vxlanIdm.GetID()
			if err != nil {
				return fmt.Errorf("failed to allocate vxlan id: %v", err)
			}

			n.setVxlanID(s, uint32(vxlanID))
			if err := n.writeToStore(); err != nil {
				n.driver.vxlanIdm.Release(uint64(n.vxlanID(s)))
				n.setVxlanID(s, 0)
				if err == datastore.ErrKeyModified {
					continue
				}
				return fmt.Errorf("network %q failed to update data store: %v", n.id, err)
			}
			return nil
		}
		return nil
	}
}

// getSubnetforIP returns the subnet to which the given IP belongs
func (n *network) getSubnetforIP(ip *net.IPNet) *subnet {
	for _, s := range n.subnets {
		// first check if the mask lengths are the same
		i, _ := s.subnetIP.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if s.subnetIP.Contains(ip.IP) {
			return s
		}
	}
	return nil
}

// getMatchingSubnet return the network's subnet that matches the input
func (n *network) getMatchingSubnet(ip *net.IPNet) *subnet {
	if ip == nil {
		return nil
	}
	for _, s := range n.subnets {
		// first check if the mask lengths are the same
		i, _ := s.subnetIP.Mask.Size()
		j, _ := ip.Mask.Size()
		if i != j {
			continue
		}
		if s.subnetIP.IP.Equal(ip.IP) {
			return s
		}
	}
	return nil
}

func (n *network) parseNetworkOptions(option map[string]interface{}) {
	if genData, ok := option[netlabel.GenericData]; ok && genData != nil {
		if m, ok := genData.(map[string]string); ok {
			if _, ok := m[netlabel.DisableDefaultGW]; ok {
				n.disableDefaultGW = true
			}
		}
	}
}

func (s *subnet) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["vni"] = s.vni
	m["gwIP"] = s.gwIP.String()
	m["subnetIP"] = s.subnetIP.String()
	return json.Marshal(m)
}

func (s *subnet) UnmarshalJSON(b []byte) error {
	var (
		err  error
		nMap map[string]interface{}
	)
	if err = json.Unmarshal(b, &nMap); err != nil {
		return err
	}
	s.vni = uint32(nMap["vni"].(float64))
	if s.gwIP, err = types.ParseCIDR(nMap["gwIP"].(string)); err != nil {
		return types.InternalErrorf("failed to decode overlay gateway address IPv4 after json unmarshal: %s", nMap["gwIP"].(string))
	}
	if s.subnetIP, err = types.ParseCIDR(nMap["subnetIP"].(string)); err != nil {
		return types.InternalErrorf("failed to decode overlay subnet address IPv4 after json unmarshal: %s", nMap["subnetIP"].(string))
	}
	return nil
}

func (nc *networkConfiguration) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["disableDefaultGW"] = nc.disableDefaultGW
	m["subnets"] = nc.subnets
	return json.Marshal(m)
}

func (nc *networkConfiguration) UnmarshalJSON(b []byte) error {
	var (
		err     error
		nMap    map[string]interface{}
		subnets []*subnet
	)
	if err = json.Unmarshal(b, &nMap); err != nil {
		return err
	}
	nc.disableDefaultGW = nMap["disableDefaultGW"].(bool)
	sj, _ := json.Marshal(nMap["subnets"])
	json.Unmarshal(sj, &subnets)
	nc.subnets = subnets
	return nil
}
