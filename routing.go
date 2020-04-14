package main

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func UdpRoutingHandler(s *stack.Stack, state *State) func(*udp.ForwarderRequest) {
	h := func(r *udp.ForwarderRequest) {
		id := r.ID()
		loc := &net.UDPAddr{
			IP:   netParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf, ok := state.remoteUdpFwd[loc.String()]
		if ok == false && IPNetContains(state.RoutingDeny, loc.IP) {
			// Firewall deny
			return
		}

		if ok == false && state.denyLocalRoutes != nil && state.denyLocalRoutes.Contains(loc.IP) {
			// Firewall deny
			return
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", err)
			return
		}

		xconn := gonet.NewUDPConn(s, &wq, ep)
		conn := &KaUDPConn{Conn: xconn}

		if rf != nil && rf.kaEnable && rf.kaInterval == 0 {
			conn.closeOnWrite = true
		}

		go func() {
			if rf != nil {
				RemoteForward(conn, rf)
			} else {
				RoutingForward(conn, loc)
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
		if ok == false && IPNetContains(state.RoutingDeny, loc.IP) {
			// Firewall deny
			r.Complete(true)
			return
		}
		if ok == false && state.denyLocalRoutes != nil && state.denyLocalRoutes.Contains(loc.IP) {
			// Firewall deny
			r.Complete(false)
			return
		}

		var wq waiter.Queue
		ep, errx := r.CreateEndpoint(&wq)
		if errx != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", errx)
			return
		}
		r.Complete(false)
		ep.SetSockOptInt(tcpip.DelayOption, 0)

		xconn := gonet.NewTCPConn(&wq, ep)
		conn := &GonetTCPConn{xconn, ep}

		go func() {
			if rf != nil {
				RemoteForward(conn, rf)
			} else {
				RoutingForward(conn, loc)
			}
		}()
	}
	return h
}

func RoutingForward(guest KaConn, loc net.Addr) {
	ga := guest.RemoteAddr()
	if logConnections {
		fmt.Printf("[+] %s://%s/%s Routing conn new\n",
			loc.Network(),
			ga,
			loc.String())
	}

	var pe ProxyError
	xhost, err := net.Dial(loc.Network(), loc.String())
	if err != nil {
		SetResetOnClose(guest)
		guest.Close()
		pe.RemoteRead = err
		pe.First = 2
	} else {
		var host KaConn
		switch v := xhost.(type) {
		case *net.TCPConn:
			host = &KaTCPConn{v}
		case *net.UDPConn:
			host = &KaUDPConn{Conn: v}
		}
		pe = connSplice(guest, host, nil)
	}
	if logConnections {
		fmt.Printf("[-] %s://%s/%s Routing conn done: %s\n",
			loc.Network(),
			ga,
			loc.String(),
			pe)
	}
}

func RemoteForward(guest KaConn, rf *FwdAddr) {
	ga := guest.RemoteAddr()
	if logConnections {
		fmt.Printf("[+] %s://%s/%s %s-remote-fwd conn new\n",
			rf.network,
			guest.RemoteAddr(),
			guest.LocalAddr(),
			rf.HostAddr().String())
	}
	var pe ProxyError
	xhost, err := net.Dial(rf.network, rf.HostAddr().String())
	if err != nil {
		SetResetOnClose(guest)
		guest.Close()
		pe.RemoteRead = err
		pe.First = 2
	} else {
		var host KaConn
		switch v := xhost.(type) {
		case *net.TCPConn:
			host = &KaTCPConn{v}
		case *net.UDPConn:
			host = &KaUDPConn{Conn: v}
		}
		pe = connSplice(guest, host, nil)
	}
	if logConnections {
		fmt.Printf("[-] %s://%s/%s %s-remote-fwd conn done: %s\n",
			rf.network,
			ga,
			guest.LocalAddr(),
			rf.HostAddr().String(),
			pe)
	}
}
