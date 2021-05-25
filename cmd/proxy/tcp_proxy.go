package main

import (
	"io"
	"log"
	"net"
	"time"
)

// TCPProxy is a proxy for TCP connections. It implements the Proxy interface to
// handle TCP traffic forwarding between the frontend and backend addresses.
type TCPProxy struct {
	listener     *net.TCPListener
	frontendAddr *net.TCPAddr
	backendAddr  *net.TCPAddr
}

// NewTCPProxy creates a new TCPProxy.
func NewTCPProxy(frontendAddr, backendAddr *net.TCPAddr) (*TCPProxy, error) {
	// detect version of hostIP to bind only to correct version
	ipVersion := ipv4
	if frontendAddr.IP.To4() == nil {
		ipVersion = ipv6
	}
	listener, err := net.ListenTCP("tcp"+string(ipVersion), frontendAddr)
	if err != nil {
		return nil, err
	}
	// If the port in frontendAddr was 0 then ListenTCP will have a picked
	// a port to listen on, hence the call to Addr to get that actual port:
	return &TCPProxy{
		listener:     listener,
		frontendAddr: listener.Addr().(*net.TCPAddr),
		backendAddr:  backendAddr,
	}, nil
}

func (proxy *TCPProxy) clientLoop(client *net.TCPConn, quit chan bool) {
	backend, err := net.DialTCP("tcp", nil, proxy.backendAddr)
	if err != nil {
		log.Printf("Can't forward traffic to backend tcp/%v: %s\n", proxy.backendAddr, err)
		client.Close()
		return
	}

	// Use this channel to follow the execution status
	// of our goroutines :D
	done := make(chan bool)

	var broker = func(to, from *net.TCPConn) {
		io.Copy(to, from)
		from.CloseRead()
		to.CloseWrite()
		done <- true

	}

	go broker(client, backend)
	go broker(backend, client)

	finish := make(chan struct{})
	go func() {

		//Wait until at least one function exits
		<-done

		//After one end of the connection is closed wait for max 30 sec
		//until the other end is closed as well
		//This is to prevent that CLOSE_WAIT and SYN_WAIT2 socket states
		//accumulate the open sockets by docker-proxy
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		}

		close(finish)
	}()

	select {
	case <-quit:
	case <-finish:
	}
	client.Close()
	backend.Close()
	<-finish
}

// Run starts forwarding the traffic using TCP.
func (proxy *TCPProxy) Run() {
	quit := make(chan bool)
	defer close(quit)
	for {
		client, err := proxy.listener.Accept()
		if err != nil {
			log.Printf("Stopping proxy on tcp/%v for tcp/%v (%s)", proxy.frontendAddr, proxy.backendAddr, err)
			return
		}
		go proxy.clientLoop(client.(*net.TCPConn), quit)
	}
}

// Close stops forwarding the traffic.
func (proxy *TCPProxy) Close() { proxy.listener.Close() }

// FrontendAddr returns the TCP address on which the proxy is listening.
func (proxy *TCPProxy) FrontendAddr() net.Addr { return proxy.frontendAddr }

// BackendAddr returns the TCP proxied address.
func (proxy *TCPProxy) BackendAddr() net.Addr { return proxy.backendAddr }
