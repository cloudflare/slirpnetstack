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

func LocalForwardTCP(state *State, s *stack.Stack, rf *FwdAddr, doneChannel <-chan bool) (Listener, error) {
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

	go func() error {
		for {
			nRemote, err := srv.Accept()
			if err != nil {
				// Not sure when Accept() can error,
				// nor what the correct resolution
				// is. Most likely socket is closed.
				return err
			}
			remote := &KaTCPConn{nRemote.(*net.TCPConn)}

			go func() {
				LocalForward(state, s, remote, host, nil)
			}()
		}
	}()

	return srv, nil
}

type UDPListner struct {
	*net.UDPConn
}

func (u *UDPListner) Addr() net.Addr {
	return u.UDPConn.LocalAddr()
}

func LocalForwardUDP(state *State, s *stack.Stack, rf *FwdAddr, doneChannel <-chan bool) (Listener, error) {
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
				LocalForward(state, s, remote, host, buf[:n])
			}()
		}
	}()
	return &UDPListner{srv}, nil
}

func LocalForward(state *State, s *stack.Stack, host KaConn, gaddr net.Addr, buf []byte) {
	raddr := host.RemoteAddr()
	if logConnections {
		fmt.Printf("[+] %s://%s/%s/%s local-fwd conn\n",
			gaddr.Network(),
			raddr,
			host.LocalAddr(),
			gaddr.String())
	}
	var srcIP net.Addr
	// When doing local forward, if the source IP of local
	// connection had routable IP (unlike
	// 127.0.0.1)... well... spoof it! The client might find it
	// useful who launched the connection in the first place.
	if IPNetContains(state.RoutingDeny, netAddrIP(raddr)) == false {
		srcIP = raddr
	}

	local, err := GonetDial(s,
		srcIP,
		gaddr)

	if buf != nil {
		local.Write(buf)
	}

	var pe ProxyError
	if err != nil {
		SetResetOnClose(host)
		host.Close()
		pe.LocalRead = fmt.Errorf("%s", err)
		pe.First = 0
	} else {
		pe = connSplice(local, host)
	}
	if logConnections {
		fmt.Printf("[-] %s://%s/%s/%s local-fwd done: %s\n",
			gaddr.Network(),
			raddr,
			host.LocalAddr(),
			gaddr.String(), pe)
	}
}
