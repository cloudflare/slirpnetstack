package main

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func FirewallRoutingBlock(state *State, addr net.Addr) (_block bool) {
	if state.denyRange.Contains(addr) {
		return true
	}

	if state.allowRange.Contains(addr) {
		return false
	}

	addrIP := netAddrIP(addr)
	// Is the IP on hard deny list?
	if IPNetContains(state.StaticRoutingDeny, addrIP) {
		// Firewall deny
		return true
	}

	// Is the ip in local routes?
	if state.localRoutes.Contains(addrIP) {
		return !state.enableHostRouting
	}

	return !state.enableInternetRouting
}

func UdpRoutingHandler(s *stack.Stack, state *State) func(*udp.ForwarderRequest) {
	h := func(r *udp.ForwarderRequest) {
		// Create endpoint as quickly as possible to avoid UDP
		// race conditions, when user sends multiple frames
		// one after another.
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", err)
			return
		}

		id := r.ID()
		loc := &net.UDPAddr{
			IP:   netParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf, ok := state.remoteUdpFwd[loc.String()]
		if !ok {
			if block := FirewallRoutingBlock(state, loc); block {
				ep.Close()
				return
			}
		}

		xconn := gonet.NewUDPConn(&wq, ep)
		conn := &KaUDPConn{Conn: xconn}

		if rf != nil && rf.kaEnable && rf.kaInterval == 0 {
			conn.closeOnWrite = true
		}

		go func() {
			if rf != nil {
				RemoteForward(conn, state, rf)
			} else {
				RoutingForward(conn, state, loc)
			}
		}()
	}
	return h
}

func TcpRoutingHandler(state *State) func(*tcp.ForwarderRequest) {
	h := func(r *tcp.ForwarderRequest) {
		id := r.ID()
		loc := &net.TCPAddr{
			IP:   netParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf, ok := state.remoteTcpFwd[loc.String()]
		if !ok {
			if block := FirewallRoutingBlock(state, loc); block {
				// In theory we could pass a bit of
				// data to the guest here. Like:
				// blocked on firewall - never send
				// RST, end host is failing - always
				// send RST. But this is wrong. If on
				// firewall we know the end host is
				// unreachable - just tell the guest.
				// Maybe we could use parametrized
				// ICMP / RST in future.
				r.Complete(true)
				return
			}
		}

		var wq waiter.Queue
		ep, errx := r.CreateEndpoint(&wq)
		if errx != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", errx)
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetDelayOption(true)

		xconn := gonet.NewTCPConn(&wq, ep)
		conn := &GonetTCPConn{xconn, ep}

		go func() {
			if rf != nil {
				RemoteForward(conn, state, rf)
			} else {
				RoutingForward(conn, state, loc)
			}
		}()
	}
	return h
}

func RoutingForward(guest KaConn, state *State, loc net.Addr) {
	// Cache guest.RemoteAddr() because it becomes nil on
	// guest.Close().
	guestRemoteAddr := guest.RemoteAddr()

	var pe ProxyError
	xhost, err := OutboundDial(state, loc)
	if err != nil {
		SetResetOnClose(guest)
		guest.Close()
		pe.RemoteRead = err
		pe.First = 2
		if logConnections {
			fmt.Printf("[!] %s://%s/%s Routing conn error: %s\n",
				loc.Network(),
				guestRemoteAddr,
				loc.String(),
				pe)
		}
	} else {
		if logConnections {
			fmt.Printf("[+] %s://%s/%s-%s Routing conn new\n",
				loc.Network(),
				guestRemoteAddr,
				xhost.LocalAddr(),
				xhost.RemoteAddr())
		}
		var host KaConn
		switch v := xhost.(type) {
		case *net.TCPConn:
			host = &KaTCPConn{v}
		case *net.UDPConn:
			host = &KaUDPConn{Conn: v}
		}
		pe = connSplice(guest, host, nil)
		if logConnections {
			fmt.Printf("[-] %s://%s/%s-%s Routing conn done: %s\n",
				loc.Network(),
				guestRemoteAddr,
				xhost.LocalAddr(),
				xhost.RemoteAddr(),
				pe)
		}
	}
}

func RemoteForward(guest KaConn, state *State, rf *FwdAddr) {
	// Cache guest.RemoteAddr() because it becomes nil on
	// guest.Close().
	guestRemoteAddr := guest.RemoteAddr()

	var pe ProxyError
	hostAddr, err := rf.HostAddr()
	if err != nil {
		// dns lookup error
		fmt.Printf("[!] %s://%s-%s/%s remote-fwd %v\n",
			rf.network,
			guestRemoteAddr,
			guest.LocalAddr(),
			rf.host.String(),
			err)
		return
	}
	xhost, err := OutboundDial(state, hostAddr)
	if err != nil {
		SetResetOnClose(guest)
		guest.Close()
		pe.RemoteRead = err
		pe.First = 2
		if logConnections {
			fmt.Printf("[!] %s://%s-%s/%s remote-fwd conn error: %s\n",
				rf.network,
				guestRemoteAddr,
				guest.LocalAddr(),
				rf.host.String(),
				pe)
		}
	} else {
		if logConnections {
			fmt.Printf("[+] %s://%s-%s/%s-%s remote-fwd conn new\n",
				rf.network,
				guestRemoteAddr,
				guest.LocalAddr(),
				xhost.LocalAddr(),
				xhost.RemoteAddr())
		}
		var host KaConn
		switch v := xhost.(type) {
		case *net.TCPConn:
			host = &KaTCPConn{v}
		case *net.UDPConn:
			host = &KaUDPConn{Conn: v}
		}
		pe = connSplice(guest, host, nil)
		if logConnections {
			fmt.Printf("[-] %s://%s-%s/%s-%s remote-fwd conn done: %s\n",
				rf.network,
				guestRemoteAddr,
				guest.LocalAddr(),
				xhost.LocalAddr(),
				xhost.RemoteAddr(),
				pe)
		}
	}
}
