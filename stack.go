package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func GetTunTap(netNsPath string, ifName string) (int, bool, uint, error) {
	var (
		err error
	)

	type tunState struct {
		fd      int
		tapMode bool
		mtu     uint32
		err     error
	}

	ch := make(chan tunState, 2)
	run := func() {
		fmt.Fprintf(os.Stderr, "[.] Opening tun interface %s\n", ifName)
		mtu, err := rawfile.GetMTU(ifName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] GetMTU(%s) = %s\n", ifName, err)
			ch <- tunState{err: err}
			return
		}

		tapMode := false

		fd, err := tun.Open(ifName)
		if err != nil {
			tapMode = true
			fd, err = tun.OpenTAP(ifName)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] open(%s) = %s\n", ifName, err)
				ch <- tunState{err: err}
				return
			}
		}
		ch <- tunState{fd, tapMode, mtu, nil}
	}

	if netNsPath != "" {
		fmt.Fprintf(os.Stderr, "[.] Joininig netns %s\n", netNsPath)
		err = joinNetNS(netNsPath, run)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Can't join netns %s: %s\n", netNsPath, err)
			return 0, false, 0, err
		}
	} else {
		run()
	}

	s := <-ch
	return s.fd, s.tapMode, uint(s.mtu), s.err
}

func NewStack(rcvBufferSize, sndBufferSize int) *stack.Stack {
	// Create the stack with ipv4 and tcp protocols, then add a tun-based
	// NIC and ipv4 address.
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
			arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6},
		HandleLocal: false,
	}

	s := stack.New(opts)
	s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	{
		opt := tcpip.TCPSACKEnabled(true)
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
	}
	{
		opt := tcpip.DefaultTTLOption(64)
		s.SetNetworkProtocolOption(ipv4.ProtocolNumber, &opt)
		s.SetNetworkProtocolOption(ipv6.ProtocolNumber, &opt)
	}

	// We expect no packet loss, therefore we can bump
	// buffers. Too large buffers thrash cache, so there is litle
	// point in too large buffers.
	{
		opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: rcvBufferSize, Max: rcvBufferSize}
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
	}
	{
		opt := tcpip.TCPSendBufferSizeRangeOption{Min: 1, Default: sndBufferSize, Max: sndBufferSize}
		s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt)
	}

	// Enable Receive Buffer Auto-Tuning, see:
	// https://github.com/google/gvisor/issues/1666
	{
		opt := tcpip.TCPModerateReceiveBufferOption(true)
		s.SetTransportProtocolOption(tcp.ProtocolNumber,
			&opt)
	}
	return s
}

func createLinkEP(_ *stack.Stack, tunFd int, tapMode bool, macAddress net.HardwareAddr, tapMtu uint32) (stack.LinkEndpoint, error) {
	parms := fdbased.Options{FDs: []int{tunFd},
		MTU:               tapMtu,
		RXChecksumOffload: true,
	}
	if tapMode {
		parms.EthernetHeader = true
		parms.Address = tcpip.LinkAddress(macAddress)
	}

	return fdbased.New(&parms)
}

func createNIC(s *stack.Stack, nic tcpip.NICID, linkEP stack.LinkEndpoint) error {
	if err := s.CreateNIC(nic, linkEP); err != nil {
		fmt.Fprintf(os.Stderr, "[!] CreateNIC(%s) = %s\n", ifName, err)
		return fmt.Errorf("%s", err)
	}

	s.SetSpoofing(nic, true)

	// In past we did s.AddAddressRange to assign 0.0.0.0/0 onto
	// the interface. We need that to be able to terminate all the
	// incoming connections - to any ip. AddressRange API has been
	// removed and the suggested workaround is to use Promiscous
	// mode. https://github.com/google/gvisor/issues/3876
	s.SetPromiscuousMode(nic, true)
	return nil
}

func MustSubnet(ipNet *net.IPNet) *tcpip.Subnet {
	subnet, errx := tcpip.NewSubnet(tcpip.AddrFromSlice(ipNet.IP), tcpip.MaskFromBytes(ipNet.Mask))
	if errx != nil {
		panic(fmt.Sprintf("Unable to MustSubnet(%s): %s", ipNet, errx))
	}
	return &subnet
}

func StackRoutingSetup(s *stack.Stack, nic tcpip.NICID, assignNet string) {
	ipAddr, ipNet, err := net.ParseCIDR(assignNet)
	if err != nil {
		panic(fmt.Sprintf("Unable to ParseCIDR(%s): %s", assignNet, err))
	}

	if ipAddr.To4() != nil {
		s.AddProtocolAddress(nic, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ipAddr.To4()).WithPrefix(),
		}, stack.AddressProperties{})
	} else {
		s.AddProtocolAddress(nic, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddrFromSlice(ipAddr).WithPrefix(),
		}, stack.AddressProperties{})
	}

	rt := s.GetRouteTable()
	rt = append(rt, tcpip.Route{
		Destination: *MustSubnet(ipNet),
		NIC:         nic,
	})
	s.SetRouteTable(rt)
}

func StackPrimeArp(s *stack.Stack, nic tcpip.NICID, ip net.IP) {
	// Prime the arp cache. Otherwise we get "no remote link
	// address" on first write.
	if ip.To4() != nil {
		s.GetLinkAddress(nic,
			tcpip.AddrFromSlice(ip.To4()),
			tcpip.AddrFromSlice([]byte{}),
			ipv4.ProtocolNumber,
			nil)
	}

}

func GonetDialTCP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*GonetTCPConn, error) {
	// Create TCP endpoint, then connect.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	if laddr != nil {
		if err := ep.Bind(*laddr); err != nil {
			ep.Close()
			return nil, errors.New(err.String())
		}
	}

	// Create wait queue entry that notifies a channel.
	//
	// We do this unconditionally as Connect will always return an error.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventOut)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	err = ep.Connect(*raddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh

		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, errors.New(err.String())
	}

	return &GonetTCPConn{gonet.NewTCPConn(&wq, ep), ep}, nil
}

type GonetTCPConn struct {
	*gonet.TCPConn
	ep tcpip.Endpoint
}

func (c *GonetTCPConn) SetTimeouts(kaInterval time.Duration, kaCount int) error {
	c.ep.SocketOptions().SetKeepAlive(true)
	{
		opt := tcpip.KeepaliveIdleOption(kaInterval)
		c.ep.SetSockOpt(&opt)
	}
	{
		opt := tcpip.KeepaliveIntervalOption(kaInterval)
		c.ep.SetSockOpt(&opt)
	}
	c.ep.SetSockOptInt(tcpip.KeepaliveCountOption, kaCount)
	{
		opt := tcpip.TCPUserTimeoutOption(UserTimeoutFromKeepalive(kaInterval, kaCount))
		c.ep.SetSockOpt(&opt)
	}
	return nil
}

func networkProtocolNumberFromIP(ip net.IP) tcpip.NetworkProtocolNumber {
	var nn tcpip.NetworkProtocolNumber
	switch {
	case ip == nil:
	case ip.To4() != nil:
		nn = ipv4.ProtocolNumber
	case ip.To16() != nil:
		nn = ipv6.ProtocolNumber
	}
	return nn
}

func GonetDialUDP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*KaUDPConn, error) {
	c, err := gonet.DialUDP(
		s,
		laddr,
		raddr,
		network)
	if err != nil {
		return nil, err
	}
	return &KaUDPConn{Conn: c}, nil
}

func GonetDial(s *stack.Stack, laddr, raddr net.Addr) (KaConn, error) {
	switch raddr.Network() {
	case "tcp":
		return GonetDialTCP(s,
			FullAddressFromAddr(laddr),
			FullAddressFromAddr(raddr),
			networkProtocolNumberFromIP(netAddrIP(raddr)),
		)
	case "udp":
		return GonetDialUDP(s,
			FullAddressFromAddr(laddr),
			FullAddressFromAddr(raddr),
			networkProtocolNumberFromIP(netAddrIP(raddr)),
		)
	}
	return nil, nil
}
