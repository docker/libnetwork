package portmapper

import (
	"fmt"
	"net"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libnetwork/iptables"
	"github.com/docker/libnetwork/portallocator"
	"github.com/docker/libnetwork/types"
	"github.com/pkg/errors"
)

const maxAllocatePortAttempts = 10

type mapping struct {
	proto         string
	userlandProxy userlandProxy
	host          net.Addr
	container     net.Addr
}

var newProxy = newProxyCommand

var (
	// ErrUnknownBackendAddressType refers to an unknown container or unsupported address type
	ErrUnknownBackendAddressType = errors.New("unknown container address type not supported")
	// ErrPortMappedForIP refers to a port already mapped to an ip address
	ErrPortMappedForIP = errors.New("port is already mapped to ip")
	// ErrPortNotMapped refers to an unmapped port
	ErrPortNotMapped = errors.New("port is not mapped")
	// ErrProtocolNotSupported is used when a requested protocol is not supported
	ErrProtocolNotSupported = errors.New("protocol not supported")
)

// PortMapper manages the network address translation
type PortMapper struct {
	chain      *iptables.ChainInfo
	bridgeName string

	// udp:ip:port
	currentMappings map[string]*mapping
	lock            sync.Mutex

	proxyPath           string
	enableUserlandProxy bool

	Allocator *portallocator.PortAllocator
}

// CreateOption represents functional options passed to the PortMapper initializer.
type CreateOption func(*PortMapper)

// WithPortAllocator is a functional option passed to the PortMapper initializer.
// It allows passing in a custom PortAllocator rather than using the default.
func WithPortAllocator(pa *portallocator.PortAllocator) CreateOption {
	return func(pm *PortMapper) {
		pm.Allocator = pa
	}
}

// WithUserlandProxy sets if the userland proxy should be enabled.
// When enabled requested port forwards will be proxied to the backend address.
// When disabled only a listener will be created on the specified frontend address.
func WithUserlandProxy(enabled bool, proxyPath string) CreateOption {
	return func(pm *PortMapper) {
		pm.enableUserlandProxy = enabled
		pm.proxyPath = proxyPath
	}
}

// New returns a new instance of PortMapper
func New(opts ...CreateOption) *PortMapper {
	pm := &PortMapper{
		currentMappings: make(map[string]*mapping),
	}

	for _, o := range opts {
		o(pm)
	}

	if pm.Allocator == nil {
		pm.Allocator = portallocator.Get()
	}

	return pm
}

// SetIptablesChain sets the specified chain into portmapper
func (pm *PortMapper) SetIptablesChain(c *iptables.ChainInfo, bridgeName string) {
	pm.chain = c
	pm.bridgeName = bridgeName
}

// MapPorts creates port forwards for each of the passed in ports
// TODO: This could be optimized by grouping ports for the same source/target IP's
//   for 1 call out to iptables.
func (pm *PortMapper) MapPorts(binds []types.PortBinding) error {
	for i, bind := range binds {
		_, err := pm.mapPort(&bind)
		if err != nil {
			return err
		}
		binds[i] = bind
	}
	return nil
}

func (pm *PortMapper) mapPort(bind *types.PortBinding) (frontend net.Addr, err error) {
	if bind.HostPort > 0 && bind.HostPortEnd == 0 {
		bind.HostPortEnd = bind.HostPort
	}
	allocatedHostPort, err := tryAllocPort(pm.Allocator, bind.Proto.String(), bind.HostIP, int(bind.HostPort), int(bind.HostPortEnd))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			pm.Allocator.ReleasePort(bind.HostIP, bind.Proto.String(), allocatedHostPort)
		}
	}()

	bind.HostPort = uint16(allocatedHostPort)
	frontend, backend, err := portBindingToAddrs(bind)
	if err != nil {
		return nil, err
	}

	return frontend, pm.create(frontend, backend)
}

func portBindingToAddrs(bind *types.PortBinding) (frontend, backend net.Addr, err error) {
	switch bind.Proto {
	case types.TCP:
		frontend = &net.TCPAddr{IP: bind.HostIP, Port: int(bind.HostPort)}
		backend = &net.TCPAddr{IP: bind.IP, Port: int(bind.Port)}
	case types.UDP:
		frontend = &net.UDPAddr{IP: bind.HostIP, Port: int(bind.HostPort)}
		backend = &net.UDPAddr{IP: bind.IP, Port: int(bind.Port)}
	default:
		err = ErrProtocolNotSupported
	}
	return
}

func (pm *PortMapper) create(frontend, backend net.Addr) (err error) {
	m := &mapping{
		proto:     frontend.Network(),
		container: backend,
		host:      frontend,
	}

	pm.lock.Lock()
	defer pm.lock.Unlock()

	key := getKey(m.host)
	if _, exists := pm.currentMappings[key]; exists {
		return ErrPortMappedForIP
	}

	frontendIP, frontendPort := getIPAndPort(frontend)
	backendIP, backendPort := getIPAndPort(backend)

	if pm.enableUserlandProxy {
		m.userlandProxy, err = newProxy(m.proto, frontendIP, frontendPort, backendIP, backendPort, pm.proxyPath)
	} else {
		m.userlandProxy = newDummyProxy(m.proto, frontendIP, frontendPort)
	}

	if err != nil {
		return err
	}

	if frontendIP.To4() != nil {
		if err := pm.forward(iptables.Append, m.proto, frontendIP, frontendPort, backendIP, backendPort); err != nil {
			return err
		}
	}

	defer func() {
		if err != nil {
			if frontendIP.To4() != nil {
				pm.forward(iptables.Delete, m.proto, frontendIP, frontendPort, backendIP, backendPort)
			}
		}
	}()

	if err := m.userlandProxy.Start(); err != nil {
		return err
	}

	pm.currentMappings[key] = m
	return nil
}

func tryAllocPort(pa *portallocator.PortAllocator, proto string, ip net.IP, rangeStart, rangeEnd int) (allocPort int, err error) {
	for i := 0; i < maxAllocatePortAttempts; i++ {
		allocPort, err = pa.RequestPortInRange(ip, proto, rangeStart, rangeEnd)
		if err == nil {
			break
		}

		if rangeStart != 0 && rangeStart == rangeEnd {
			// No point in trying to allocate a user-requested port over and over
			return 0, errors.Errorf("failed to allocate and map port %d", rangeStart)
		}
	}
	return
}

// Unmap removes stored mapping for the specified host transport address
func (pm *PortMapper) Unmap(host net.Addr) error {
	pm.lock.Lock()
	defer pm.lock.Unlock()

	key := getKey(host)
	data, exists := pm.currentMappings[key]
	if !exists {
		return ErrPortNotMapped
	}

	if data.userlandProxy != nil {
		data.userlandProxy.Stop()
	}

	delete(pm.currentMappings, key)

	containerIP, containerPort := getIPAndPort(data.container)
	hostIP, hostPort := getIPAndPort(data.host)
	if err := pm.forward(iptables.Delete, data.proto, hostIP, hostPort, containerIP, containerPort); err != nil {
		logrus.Errorf("Error on iptables delete: %s", err)
	}

	switch a := host.(type) {
	case *net.TCPAddr:
		return pm.Allocator.ReleasePort(a.IP, "tcp", a.Port)
	case *net.UDPAddr:
		return pm.Allocator.ReleasePort(a.IP, "udp", a.Port)
	}
	return nil
}

//ReMapAll will re-apply all port mappings
func (pm *PortMapper) ReMapAll() {
	pm.lock.Lock()
	defer pm.lock.Unlock()
	logrus.Debugln("Re-applying all port mappings.")
	for _, data := range pm.currentMappings {
		containerIP, containerPort := getIPAndPort(data.container)
		hostIP, hostPort := getIPAndPort(data.host)
		if err := pm.forward(iptables.Append, data.proto, hostIP, hostPort, containerIP, containerPort); err != nil {
			logrus.Errorf("Error on iptables add: %s", err)
		}
	}
}

func getKey(a net.Addr) string {
	switch t := a.(type) {
	case *net.TCPAddr:
		return fmt.Sprintf("%s:%d/%s", t.IP.String(), t.Port, "tcp")
	case *net.UDPAddr:
		return fmt.Sprintf("%s:%d/%s", t.IP.String(), t.Port, "udp")
	}
	return ""
}

func getIPAndPort(a net.Addr) (net.IP, int) {
	switch t := a.(type) {
	case *net.TCPAddr:
		return t.IP, t.Port
	case *net.UDPAddr:
		return t.IP, t.Port
	}
	return nil, 0
}

func (pm *PortMapper) forward(action iptables.Action, proto string, sourceIP net.IP, sourcePort int, containerIP net.IP, containerPort int) error {
	if pm.chain == nil {
		return nil
	}
	return pm.chain.Forward(action, sourceIP, sourcePort, proto, containerIP.String(), containerPort, pm.bridgeName)
}
