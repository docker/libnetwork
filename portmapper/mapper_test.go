package portmapper

import (
	"net"
	"strings"
	"testing"

	"github.com/docker/libnetwork/iptables"
	_ "github.com/docker/libnetwork/testutils"
	"github.com/docker/libnetwork/types"
)

func init() {
	// override this func to mock out the proxy server
	newProxy = newMockProxyCommand
}

func TestSetIptablesChain(t *testing.T) {
	pm := New()

	c := &iptables.ChainInfo{
		Name: "TEST",
	}

	if pm.chain != nil {
		t.Fatal("chain should be nil at init")
	}

	pm.SetIptablesChain(c, "lo")
	if pm.chain == nil {
		t.Fatal("chain should not be nil after set")
	}
}

func TestMapTCPPorts(t *testing.T) {
	pm := New(WithUserlandProxy(true, ""))
	dstIP1 := net.ParseIP("192.168.0.1")
	dstIP2 := net.ParseIP("192.168.0.2")
	srcIP1 := net.ParseIP("172.16.0.1")
	srcIP2 := net.ParseIP("172.16.0.2")

	binding := types.PortBinding{
		Proto:    types.TCP,
		IP:       srcIP1,
		Port:     1080,
		HostIP:   dstIP1,
		HostPort: 80,
	}

	b := binding.GetCopy()
	host1, err := pm.mapPort(&b)
	if err != nil {
		t.Fatalf("Failed to allocate port: %s", err)
	}

	if _, err := pm.mapPort(&b); err == nil {
		t.Fatalf("Port is in use - mapping should have failed")
	}

	b = binding.GetCopy()
	b.IP = srcIP2
	if host, err := pm.mapPort(&b); err == nil {
		t.Fatalf("Port is in use - mapping should have failed: %v", host)
	}

	b = binding.GetCopy()
	b.HostIP = dstIP2
	b.IP = srcIP2
	host2, err := pm.mapPort(&b)
	if err != nil {
		t.Fatalf("Failed to allocate port: %s", err)
	}

	if pm.Unmap(host1) != nil {
		t.Fatalf("Failed to release port")
	}

	if pm.Unmap(host2) != nil {
		t.Fatalf("Failed to release port")
	}

	if pm.Unmap(host2) == nil {
		t.Fatalf("Port already released, but no error reported")
	}
}

func TestGetUDPKey(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 53}

	key := getKey(addr)

	if expected := "192.168.1.5:53/udp"; key != expected {
		t.Fatalf("expected key %s got %s", expected, key)
	}
}

func TestGetTCPKey(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.5"), Port: 80}

	key := getKey(addr)

	if expected := "192.168.1.5:80/tcp"; key != expected {
		t.Fatalf("expected key %s got %s", expected, key)
	}
}

func TestGetUDPIPAndPort(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.5"), Port: 53}

	ip, port := getIPAndPort(addr)
	if expected := "192.168.1.5"; ip.String() != expected {
		t.Fatalf("expected ip %s got %s", expected, ip)
	}

	if ep := 53; port != ep {
		t.Fatalf("expected port %d got %d", ep, port)
	}
}

func TestMapUDPPorts(t *testing.T) {
	pm := New(WithUserlandProxy(true, ""))
	dstIP1 := net.ParseIP("192.168.0.1")
	dstIP2 := net.ParseIP("192.168.0.2")
	srcIP1 := net.ParseIP("172.16.0.1")
	srcIP2 := net.ParseIP("172.16.0.2")

	binding := types.PortBinding{
		Proto:    types.UDP,
		IP:       srcIP1,
		Port:     1080,
		HostIP:   dstIP1,
		HostPort: 80,
	}

	b := binding.GetCopy()
	host1, err := pm.mapPort(&b)
	if err != nil {
		t.Fatalf("Failed to allocate port: %s", err)
	}

	if _, err := pm.mapPort(&b); err == nil {
		t.Fatalf("Port is in use - mapping should have failed")
	}

	b = binding.GetCopy()
	b.IP = srcIP2
	if _, err := pm.mapPort(&b); err == nil {
		t.Fatalf("Port is in use - mapping should have failed")
	}

	b = binding.GetCopy()
	b.IP = srcIP2
	b.HostIP = dstIP2
	host2, err := pm.mapPort(&b)
	if err != nil {
		t.Fatalf("Failed to allocate port: %s", err)
	}

	if pm.Unmap(host1) != nil {
		t.Fatalf("Failed to release port")
	}

	if pm.Unmap(host2) != nil {
		t.Fatalf("Failed to release port")
	}

	if pm.Unmap(host2) == nil {
		t.Fatalf("Port already released, but no error reported")
	}
}

func TestMapAllPortsSingleInterface(t *testing.T) {
	pm := New(WithUserlandProxy(true, ""))
	binding := types.PortBinding{
		Proto:  types.TCP,
		IP:     net.ParseIP("172.16.0.1"),
		Port:   1080,
		HostIP: net.ParseIP("0.0.0.0"),
	}

	var hosts []net.Addr

	cleanup := func() error {
		for _, val := range hosts {
			if err := pm.Unmap(val); err != nil {
				return err
			}
		}
		hosts = []net.Addr{}
		return nil
	}
	defer cleanup()

	for i := 0; i < 10; i++ {
		start, end := pm.Allocator.Begin, pm.Allocator.End
		for j := start; j < end; j++ {
			b := binding.GetCopy()
			host, err := pm.mapPort(&b)
			if err != nil {
				t.Fatalf("Failed to allocate port from pool %d-%d for binding %v on iteration %d(%d): %v", start, end, binding, i, j, err)
			}
			hosts = append(hosts, host)
		}

		b := binding.GetCopy()
		b.HostPort = uint16(start)
		if _, err := pm.mapPort(&b); err == nil {
			t.Fatalf("Port %d should be bound but is not", start)
		}

		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMapTCPDummyListen(t *testing.T) {
	pm := New()
	binding := types.PortBinding{
		Proto:    types.TCP,
		IP:       net.ParseIP("172.16.0.1"),
		Port:     1080,
		HostIP:   net.ParseIP("0.0.0.0"),
		HostPort: 80,
	}

	b := binding.GetCopy()
	if _, err := pm.mapPort(&b); err != nil {
		t.Fatalf("Failed to allocate port: %s", err)
	}
	if _, err := net.Listen("tcp", "0.0.0.0:80"); err == nil {
		t.Fatal("Listen on mapped port without proxy should fail")
	} else {
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Error should be about address already in use, got %v", err)
		}
	}
	if _, err := net.Listen("tcp", "0.0.0.0:81"); err != nil {
		t.Fatal(err)
	}

	b = binding.GetCopy()
	b.HostPort = 81
	if host, err := pm.mapPort(&b); err == nil {
		t.Fatalf("Bound port shouldn't be allocated, but it was on: %v", host)
	} else {
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Error should be about address already in use, got %v", err)
		}
	}
}

func TestMapUDPDummyListen(t *testing.T) {
	pm := New()
	binding := types.PortBinding{
		Proto:    types.UDP,
		IP:       net.ParseIP("172.16.0.1"),
		Port:     1080,
		HostIP:   net.ParseIP("0.0.0.0"),
		HostPort: 80,
	}

	b := binding.GetCopy()
	if _, err := pm.mapPort(&b); err != nil {
		t.Fatalf("Failed to allocate port: %s", err)
	}

	if _, err := net.ListenUDP("udp", &net.UDPAddr{IP: binding.HostIP, Port: 80}); err == nil {
		t.Fatal("Listen on mapped port without proxy should fail")
	} else {
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Error should be about address already in use, got %v", err)
		}
	}
	if _, err := net.ListenUDP("udp", &net.UDPAddr{IP: binding.HostIP, Port: 81}); err != nil {
		t.Fatal(err)
	}

	b = binding.GetCopy()
	b.HostPort = 81
	if host, err := pm.mapPort(&b); err == nil {
		t.Fatalf("Bound port shouldn't be allocated, but it was on: %v", host)
	} else {
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Error should be about address already in use, got %v", err)
		}
	}
}
