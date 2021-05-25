package netutils

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestCheckRouteOverlaps(t *testing.T) {
	networkGetRoutesFct = func(netlink.Link, int) ([]netlink.Route, error) {
		routesData := []string{"10.0.2.0/32", "10.0.3.0/24", "10.0.42.0/24", "172.16.42.0/24", "192.168.142.0/24"}
		routes := []netlink.Route{}
		for _, addr := range routesData {
			_, netX, _ := net.ParseCIDR(addr)
			routes = append(routes, netlink.Route{Dst: netX})
		}
		return routes, nil
	}
	defer func() { networkGetRoutesFct = nil }()

	_, netX, _ := net.ParseCIDR("172.16.0.1/24")
	if err := CheckRouteOverlaps(netX); err != nil {
		t.Fatal(err)
	}

	_, netX, _ = net.ParseCIDR("10.0.2.0/24")
	if err := CheckRouteOverlaps(netX); err == nil {
		t.Fatal("10.0.2.0/24 and 10.0.2.0 should overlap but it doesn't")
	}
}
