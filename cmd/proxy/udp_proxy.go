package main

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// UDPConnTrackTimeout is the timeout used for UDP connection tracking
	UDPConnTrackTimeout = 90 * time.Second
	// UDPBufSize is the buffer size for the UDP proxy
	UDPBufSize = 65507
)

// A net.Addr where the IP is split into two fields so you can use it as a key
// in a map:
type connTrackKey struct {
	IPHigh uint64
	IPLow  uint64
	Port   int
}

func newConnTrackKey(addr *net.UDPAddr) *connTrackKey {
	if len(addr.IP) == net.IPv4len {
		return &connTrackKey{
			IPHigh: 0,
			IPLow:  uint64(binary.BigEndian.Uint32(addr.IP)),
			Port:   addr.Port,
		}
	}
	return &connTrackKey{
		IPHigh: binary.BigEndian.Uint64(addr.IP[:8]),
		IPLow:  binary.BigEndian.Uint64(addr.IP[8:]),
		Port:   addr.Port,
	}
}

type connTrackMap map[connTrackKey]*net.UDPConn

// UDPProxy is proxy for which handles UDP datagrams. It implements the Proxy
// interface to handle UDP traffic forwarding between the frontend and backend
// addresses.
type UDPProxy struct {
	listener       *net.UDPConn
	frontendAddr   *net.UDPAddr
	backendAddr    *net.UDPAddr
	connTrackTable connTrackMap
	connTrackLock  sync.Mutex
	inet6Socket    bool
}

// NewUDPProxy creates a new UDPProxy.
func NewUDPProxy(frontendAddr, backendAddr *net.UDPAddr) (*UDPProxy, error) {
	// detect version of hostIP to bind only to correct version
	ipVersion := ipVer4
	if frontendAddr.IP.To4() == nil {
		ipVersion = ipVer6
	}
	listener, err := net.ListenUDP("udp"+string(ipVersion), frontendAddr)
	if err != nil {
		return nil, err
	}

	frontendUDPAddr := listener.LocalAddr().(*net.UDPAddr)
	inet6Socket := frontendUDPAddr.IP.To4() == nil

	// INET_6 sockets (which are bound by default) serve
	// both udp6 and udp4 packets, and provide IPv4 dst IPs
	// in IPv6 CMSGs
	if inet6Socket {
		err = ipv6.NewPacketConn(listener).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	} else {
		err = ipv4.NewPacketConn(listener).SetControlMessage(ipv4.FlagDst, true)
	}

	if err != nil {
		log.Printf("Setting FlagDst on frontend socket %s failed, %s, was inet6? %t", frontendUDPAddr.String(), err, inet6Socket)
	}

	return &UDPProxy{
		listener:       listener,
		frontendAddr:   frontendUDPAddr,
		backendAddr:    backendAddr,
		connTrackTable: make(connTrackMap),
		inet6Socket:    inet6Socket,
	}, nil
}

func (proxy *UDPProxy) replyLoop(proxyConn *net.UDPConn, clientAddr *net.UDPAddr, srcAddr *net.IP, clientKey *connTrackKey) {
	defer func() {
		proxy.connTrackLock.Lock()
		delete(proxy.connTrackTable, *clientKey)
		proxy.connTrackLock.Unlock()
		proxyConn.Close()
	}()

	readBuf := make([]byte, UDPBufSize)

	// set the src IP of the response to match the DST of the
	// initial client packet. Reuse the OOB buffer to prevent subsequent marshal calls
	var oobProto []byte // serialised
	var oobBuf []byte

	if srcAddr != nil {
		if srcAddr.To4() != nil {
			cm := new(ipv4.ControlMessage)
			cm.Src = *srcAddr
			oobProto = cm.Marshal()
		} else {
			cm := new(ipv6.ControlMessage)
			cm.Src = *srcAddr
			oobProto = cm.Marshal()
		}

		// pre-allocate a buffer for passing into WriteMsgUDP
		oobBuf = make([]byte, len(oobProto))
	}

	for {
		proxyConn.SetReadDeadline(time.Now().Add(UDPConnTrackTimeout))
	again:
		read, err := proxyConn.Read(readBuf)
		if err != nil {
			if err, ok := err.(*net.OpError); ok && err.Err == syscall.ECONNREFUSED {
				// This will happen if the last write failed
				// (e.g: nothing is actually listening on the
				// proxied port on the container), ignore it
				// and continue until UDPConnTrackTimeout
				// expires:
				goto again
			}
			return
		}
		for i := 0; i != read; {
			written := 0

			if oobProto != nil {
				// clone oobBuf as it will be mutated by WriteMsgUDP
				copy(oobBuf, oobProto)
				written, _, err = proxy.listener.WriteMsgUDP(readBuf[i:read], oobBuf, clientAddr)
			} else {
				written, err = proxy.listener.WriteToUDP(readBuf[i:read], clientAddr)
			}

			if err != nil {
				return
			}
			i += written
		}
	}
}

// Run starts forwarding the traffic using UDP.
func (proxy *UDPProxy) Run() {
	readBuf := make([]byte, UDPBufSize)
	for {
		// Use oob data/ControlMessages to get the dst IP of the
		// received packet. This is used to ensure the src IP of the
		// response matches when bound to 0.0.0.0 on  multi-homed
		// machines.
		var oobBuf []byte

		if proxy.inet6Socket {
			oobBuf = ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)
		} else {
			oobBuf = ipv4.NewControlMessage(ipv4.FlagDst)
		}

		read, _, _, from, err := proxy.listener.ReadMsgUDP(readBuf, oobBuf)

		if err != nil {
			// NOTE: Apparently ReadFrom doesn't return
			// ECONNREFUSED like Read do (see comment in
			// UDPProxy.replyLoop)
			if !isClosedError(err) {
				log.Printf("Stopping proxy on udp/%v for udp/%v (%s)", proxy.frontendAddr, proxy.backendAddr, err)
			}
			break
		}

		// Parse and extract the ControlMessage to get the dst IP.
		// nil is a valid value and will result in the OS selecting
		// the appropriate src IP automatically
		var to *net.IP = nil

		if from.IP.To4() == nil {
			cm := new(ipv6.ControlMessage)
			err = cm.Parse(oobBuf)

			if err == nil {
				to = &cm.Dst
			}
		} else {
			cm := new(ipv4.ControlMessage)
			err = cm.Parse(oobBuf)

			if err == nil {
				to = &cm.Dst
			}
		}

		fromKey := newConnTrackKey(from)
		proxy.connTrackLock.Lock()
		proxyConn, hit := proxy.connTrackTable[*fromKey]
		if !hit {
			proxyConn, err = net.DialUDP("udp", nil, proxy.backendAddr)
			if err != nil {
				log.Printf("Can't proxy a datagram to udp/%s: %s\n", proxy.backendAddr, err)
				proxy.connTrackLock.Unlock()
				continue
			}
			proxy.connTrackTable[*fromKey] = proxyConn
			go proxy.replyLoop(proxyConn, from, to, fromKey)
		}
		proxy.connTrackLock.Unlock()
		for i := 0; i != read; {
			written, err := proxyConn.Write(readBuf[i:read])
			if err != nil {
				log.Printf("Can't proxy a datagram to udp/%s: %s\n", proxy.backendAddr, err)
				break
			}
			i += written
		}
	}
}

// Close stops forwarding the traffic.
func (proxy *UDPProxy) Close() {
	proxy.listener.Close()
	proxy.connTrackLock.Lock()
	defer proxy.connTrackLock.Unlock()
	for _, conn := range proxy.connTrackTable {
		conn.Close()
	}
}

// FrontendAddr returns the UDP address on which the proxy is listening.
func (proxy *UDPProxy) FrontendAddr() net.Addr { return proxy.frontendAddr }

// BackendAddr returns the proxied UDP address.
func (proxy *UDPProxy) BackendAddr() net.Addr { return proxy.backendAddr }

func isClosedError(err error) bool {
	/* This comparison is ugly, but unfortunately, net.go doesn't export errClosing.
	 * See:
	 * http://golang.org/src/pkg/net/net.go
	 * https://code.google.com/p/go/issues/detail?id=4337
	 * https://groups.google.com/forum/#!msg/golang-nuts/0_aaCvBmOcM/SptmDyX1XJMJ
	 */
	return strings.HasSuffix(err.Error(), "use of closed network connection")
}
