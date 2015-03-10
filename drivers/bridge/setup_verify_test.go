package bridge

import (
	"net"
	"testing"

	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/Godeps/_workspace/src/github.com/vishvananda/netlink"
)

func setupVerifyTest(t *testing.T) *bridgeInterface {
	inf := &bridgeInterface{Config: &Configuration{}}

	br := netlink.Bridge{}
	br.LinkAttrs.Name = "default0"
	if err := netlink.LinkAdd(&br); err == nil {
		inf.Link = &br
	} else {
		t.Fatalf("Failed to create bridge interface: %v", err)
	}

	return inf
}

func TestSetupVerify(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()

	addrv4 := net.IPv4(192, 168, 1, 1)
	inf := setupVerifyTest(t)
	inf.Config.AddressIPv4 = &net.IPNet{IP: addrv4, Mask: addrv4.DefaultMask()}

	if err := netlink.AddrAdd(inf.Link, &netlink.Addr{IPNet: inf.Config.AddressIPv4}); err != nil {
		t.Fatalf("Failed to assign IPv4 %s to interface: %v", inf.Config.AddressIPv4, err)
	}

	if err := setupVerifyConfiguredAddresses(inf); err != nil {
		t.Fatalf("Address verification failed: %v", err)
	}
}

func TestSetupVerifyBad(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()

	addrv4 := net.IPv4(192, 168, 1, 1)
	inf := setupVerifyTest(t)
	inf.Config.AddressIPv4 = &net.IPNet{IP: addrv4, Mask: addrv4.DefaultMask()}

	ipnet := &net.IPNet{IP: net.IPv4(192, 168, 1, 2), Mask: addrv4.DefaultMask()}
	if err := netlink.AddrAdd(inf.Link, &netlink.Addr{IPNet: ipnet}); err != nil {
		t.Fatalf("Failed to assign IPv4 %s to interface: %v", ipnet, err)
	}

	if err := setupVerifyConfiguredAddresses(inf); err == nil {
		t.Fatal("Address verification was expected to fail")
	}
}

func TestSetupVerifyMissing(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()

	addrv4 := net.IPv4(192, 168, 1, 1)
	inf := setupVerifyTest(t)
	inf.Config.AddressIPv4 = &net.IPNet{IP: addrv4, Mask: addrv4.DefaultMask()}

	if err := setupVerifyConfiguredAddresses(inf); err == nil {
		t.Fatal("Address verification was expected to fail")
	}
}

func TestSetupVerifyIPv6(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()

	addrv4 := net.IPv4(192, 168, 1, 1)
	inf := setupVerifyTest(t)
	inf.Config.AddressIPv4 = &net.IPNet{IP: addrv4, Mask: addrv4.DefaultMask()}
	inf.Config.EnableIPv6 = true

	if err := netlink.AddrAdd(inf.Link, &netlink.Addr{IPNet: bridgeIPv6}); err != nil {
		t.Fatalf("Failed to assign IPv6 %s to interface: %v", bridgeIPv6, err)
	}
	if err := netlink.AddrAdd(inf.Link, &netlink.Addr{IPNet: inf.Config.AddressIPv4}); err != nil {
		t.Fatalf("Failed to assign IPv4 %s to interface: %v", inf.Config.AddressIPv4, err)
	}

	if err := setupVerifyConfiguredAddresses(inf); err != nil {
		t.Fatalf("Address verification failed: %v", err)
	}
}

func TestSetupVerifyIPv6Missing(t *testing.T) {
	defer libnetwork.SetupTestNetNS(t)()

	addrv4 := net.IPv4(192, 168, 1, 1)
	inf := setupVerifyTest(t)
	inf.Config.AddressIPv4 = &net.IPNet{IP: addrv4, Mask: addrv4.DefaultMask()}
	inf.Config.EnableIPv6 = true

	if err := netlink.AddrAdd(inf.Link, &netlink.Addr{IPNet: inf.Config.AddressIPv4}); err != nil {
		t.Fatalf("Failed to assign IPv4 %s to interface: %v", inf.Config.AddressIPv4, err)
	}

	if err := setupVerifyConfiguredAddresses(inf); err == nil {
		t.Fatal("Address verification was expected to fail")
	}
}
