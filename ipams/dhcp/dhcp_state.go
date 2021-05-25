package dhcp

import (
	"fmt"

	"github.com/Sirupsen/logrus"
)

func (a *allocator) pool(p string) *dhcpPool {
	a.Lock()
	dp, ok := a.dhcpPools[p]
	a.Unlock()
	if !ok {
		logrus.Errorf("dhcp pool id %s not found", p)
	}

	return dp
}

func (a *allocator) addPool(dp *dhcpPool) {
	a.Lock()
	a.dhcpPools[dp.IPv4Subnet.String()] = dp
	a.Unlock()
}

func (a *allocator) deletePool(dp string) {
	a.Lock()
	delete(a.dhcpPools, dp)
	a.Unlock()
}

func (a *allocator) getPools() []*dhcpPool {
	a.Lock()
	defer a.Unlock()

	ls := make([]*dhcpPool, 0, len(a.dhcpPools))
	for _, nw := range a.dhcpPools {
		ls = append(ls, nw)
	}

	return ls
}

func (a *allocator) getPool(p string) (*dhcpPool, error) {
	a.Lock()
	defer a.Unlock()
	if p == "" {
		return nil, fmt.Errorf("invalid dhcp pool id: %s", p)
	}
	if dp, ok := a.dhcpPools[p]; ok {
		return dp, nil
	}

	return nil, fmt.Errorf("dhcp pool not found: %s", p)
}

func (dp *dhcpPool) lease(dl string) *dhcpLease {
	dp.Lock()
	defer dp.Unlock()

	return dp.dhcpLeases[dl]
}

func (dp *dhcpPool) addLease(dl *dhcpLease) {
	dp.Lock()
	dp.dhcpLeases[dl.leaseIP.String()] = dl
	dp.Unlock()
}

func (dp *dhcpPool) deleteLease(dl string) {
	dp.Lock()
	delete(dp.dhcpLeases, dl)
	dp.Unlock()
}

func (dp *dhcpPool) getLease(l string) (*dhcpLease, error) {
	dp.Lock()
	defer dp.Unlock()
	if l == "" {
		return nil, fmt.Errorf("dhcp lease for IP %s not found", l)
	}
	if dl, ok := dp.dhcpLeases[l]; ok {
		return dl, nil
	}

	return nil, nil
}
