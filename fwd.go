package main

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Listener interface {
	Close() error
	Addr() net.Addr
}

func LocalForwardTCP(state *State, s *stack.Stack, rf *FwdAddr) (Listener, error) {
	tmpBind := &net.TCPAddr{
		IP:   net.IP(rf.bind.Addr),
		Port: int(rf.bind.Port),
	}

	host := &net.TCPAddr{
		IP:   net.IP(rf.host.Addr),
		Port: int(rf.host.Port),
	}

	srv, err := net.ListenTCP(rf.network, tmpBind)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			nRemote, err := srv.Accept()
			if err != nil {
				// Most likely socket is closed.
				// Not sure when Accept() can error otherwise,
				if logConnections {
					fmt.Printf("[!] TCP local-fwd error: %s\n", err)
				}
				return
			}
			remote := &KaTCPConn{nRemote.(*net.TCPConn)}

			go func() {
				LocalForward(state, s, remote, host, nil, rf.proxyProtocol)
			}()
		}
	}()

	sa := srv.Addr().(*net.TCPAddr)
	rf.bind.Port = uint16(sa.Port)
	rf.listener = srv
	state.localTcpFwd[rf.HostAddr().String()] = rf
	return srv, nil
}

type UDPListner struct {
	*net.UDPConn
}

func (u *UDPListner) Addr() net.Addr {
	return u.UDPConn.LocalAddr()
}

func LocalForwardUDP(state *State, s *stack.Stack, rf *FwdAddr) (Listener, error) {
	tmpBind := &net.UDPAddr{
		IP:   net.IP(rf.bind.Addr),
		Port: int(rf.bind.Port),
	}

	host := &net.UDPAddr{
		IP:   net.IP(rf.host.Addr),
		Port: int(rf.host.Port),
	}

	srv, err := net.ListenUDP(rf.network, tmpBind)
	if err != nil {
		return nil, err
	}

	SetReuseaddr(srv)

	laddr := srv.LocalAddr().(*net.UDPAddr)

	go func() error {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := srv.ReadFrom(buf)
			if err != nil {
				return err
			}
			raddr := addr.(*net.UDPAddr)

			// Warning, this is racy, what if two packets are in the queue?
			remote, err := MagicDialUDP(laddr, raddr)
			if rf.kaEnable && rf.kaInterval == 0 {
				remote.closeOnWrite = true
			}

			if err != nil {
				// This actually can totally happen in
				// the said race. Just drop the packet then.
				continue
			}

			go func() {
				LocalForward(state, s, remote, host, buf[:n], rf.proxyProtocol)
			}()
		}
	}()

	rf.listener = &UDPListner{srv}
	state.localUdpFwd[rf.HostAddr().String()] = rf

	return rf.listener, nil
}

func LocalForward(state *State, s *stack.Stack, local KaConn, gaddr net.Addr, buf []byte, proxyProtocol bool) {
	var (
		err          error
		raddr        = local.RemoteAddr()
		ppSrc, ppDst net.Addr
		sppHeader    []byte
	)
	if proxyProtocol && buf == nil {
		buf = make([]byte, 4096)
		n, err := local.Read(buf)
		if err != nil {
			goto pperror
		}
		buf = buf[:n]
	}

	if proxyProtocol {
		var (
			n int
		)
		if gaddr.Network() == "tcp" {
			n, ppSrc, ppDst, err = DecodePP(buf)
			buf = buf[n:]
		} else {
			n, ppSrc, ppDst, err = DecodeSPP(buf)
			sppHeader = make([]byte, n)
			copy(sppHeader, buf[:n])
			buf = buf[n:]
		}
		if err != nil {
			goto pperror
		}
	}

	{
		var (
			srcIP    net.Addr
			ppPrefix = ""
		)
		if proxyProtocol == false {
			// When doing local forward, if the source IP of local
			// connection had routable IP (unlike
			// 127.0.0.1)... well... spoof it! The client might find it
			// useful who launched the connection in the first place.
			if IPNetContains(state.RoutingDeny, netAddrIP(raddr)) == false {
				srcIP = raddr
			}
		} else {
			ppPrefix = "PP "
			if IPNetContains(state.RoutingDeny, netAddrIP(ppSrc)) == false {
				srcIP = ppSrc
			} else {
				// If the source IP as reported by PP
				// is not routable, still forward
				// connection. Just don't use/leak the
				// original IP.
			}
		}

		if srcIP != nil {
			// It's very nice the proxy-protocol (or just
			// client) gave us client port number, but we
			// don't want it. Spoofing the same port
			// number on our side is not safe, useless,
			// confusing and very bug prone.
			srcIP = netAddrSetPort(srcIP, 0)

		}

		if netAddrPort(gaddr) == 0 {
			// If the guest has dport equal to zero, fill
			// it up somehow. First guess - use dport of
			// local connection.
			localPort := netAddrPort(local.LocalAddr())

			// Alternatively if we got dport from PP, use that
			if ppDst != nil {
				localPort = netAddrPort(ppDst)
			}

			gaddr = netAddrSetPort(gaddr, localPort)
		}

		if logConnections {
			fmt.Printf("[+] %s://%s/%s/%s local-fwd %sconn\n",
				gaddr.Network(),
				raddr,
				local.LocalAddr(),
				gaddr.String(),
				ppPrefix)
		}

		guest, err := GonetDial(s, srcIP, gaddr)

		if buf != nil {
			guest.Write(buf)
		}

		var pe ProxyError
		if err != nil {
			SetResetOnClose(local)
			local.Close()
			pe.LocalRead = fmt.Errorf("%s", err)
			pe.First = 0
		} else {
			pe = connSplice(local, guest, sppHeader)
		}
		if logConnections {
			fmt.Printf("[-] %s://%s/%s/%s local-fwd %sdone: %s\n",
				gaddr.Network(),
				raddr,
				local.LocalAddr(),
				gaddr.String(),
				ppPrefix,
				pe)
		}
	}
	return
pperror:
	if logConnections {
		fmt.Printf("[!] %s://%s/%s/%s local-fwd PP error: %s\n",
			gaddr.Network(),
			raddr,
			local.LocalAddr(),
			gaddr.String(),
			err)
	}
	local.Close()
	return
}
