package main

import (
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"net"
	"strconv"
)

func IPNetContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func MustParseCIDR(n string) *net.IPNet {
	_, r, err := net.ParseCIDR(n)
	if err != nil {
		panic(fmt.Sprintf("Unable to ParseCIDR %s = %s", n, err))
	}
	return r
}

func MustParseMAC(m string) net.HardwareAddr {
	mac, err := net.ParseMAC(m)
	if err != nil {
		panic(fmt.Sprintf("Unable to ParseCIDR %s = %s", m, err))
	}
	return mac
}

func SetResetOnClose(conn net.Conn) {
	switch v := conn.(type) {
	case *net.TCPConn:
		v.SetLinger(0)
		// case *gonet.Conn:
		// TODO: gonet doesn't support SO_LINGER yet
	}
}

// The problem with standard net.ParseIP is that it can return
// ::ffff:x.x.x.x IPv4-mapped address. We don't like the lack of
// uniformity.
func netParseIP(h string) net.IP {
	ip := net.ParseIP(h)
	if ip == nil {
		return nil
	}
	if ip.To4() != nil {
		ip = ip.To4()
	}
	return ip
}

type defAddress struct {
	static tcpip.FullAddress
}

func ParseDefAddress(ipS string, portS string) (*defAddress, error) {
	da := &defAddress{}
	if ipS != "" {
		ip := netParseOrResolveIP(ipS)
		if ip == nil {
			return nil, fmt.Errorf("Unable to parse IP address %q", ip)
		}
		da.static.Addr = tcpip.Address(ip)
	}

	if portS != "" {
		var err error
		port, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			return nil, err
		}
		da.static.Port = uint16(port)
	}
	return da, nil
}

func (da *defAddress) SetDefaultAddr(a net.IP) {
	if da.static.Addr == "" {
		da.static.Addr = tcpip.Address(a)
	}
}

func (da *defAddress) String() string {
	return fmt.Sprintf("%s:%d", net.IP(da.static.Addr).String(), da.static.Port)
}

func (da *defAddress) GetTCPAddr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IP(da.static.Addr),
		Port: int(da.static.Port),
	}
}

func (da *defAddress) GetUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IP(da.static.Addr),
		Port: int(da.static.Port),
	}
}

func netParseOrResolveIP(h string) net.IP {
	ip := netParseIP(h)
	if ip != nil {
		if ip.To4() != nil {
			ip = ip.To4()
		}
		return ip
	}
	addrs, err := net.LookupHost(h)
	if err != nil || len(addrs) < 1 {
		return nil
	}

	// prefer IPv4. No real reason.
	for _, addr := range addrs {
		ip := netParseIP(addr)
		if ip.To4() != nil {
			return ip.To4()
		}
	}
	return netParseIP(addrs[0])
}

func OutboundDial(srcIPs *SrcIPs, dst net.Addr) (net.Conn, error) {
	network := dst.Network()
	if network == "tcp" {
		dstTcp := dst.(*net.TCPAddr)
		var srcTcp *net.TCPAddr
		if srcIPs != nil && dstTcp.IP.To4() != nil && srcIPs.srcIPv4 != nil {
			srcTcp = &net.TCPAddr{IP: srcIPs.srcIPv4}
		}
		if srcIPs != nil && dstTcp.IP.To4() == nil && srcIPs.srcIPv6 != nil {
			srcTcp = &net.TCPAddr{IP: srcIPs.srcIPv6}
		}
		return net.DialTCP(network, srcTcp, dstTcp)
	}
	if network == "udp" {
		dstUdp := dst.(*net.UDPAddr)
		var srcUdp *net.UDPAddr
		if srcIPs != nil && dstUdp.IP.To4() != nil && srcIPs.srcIPv4 != nil {
			srcUdp = &net.UDPAddr{IP: srcIPs.srcIPv4}
		}
		if srcIPs != nil && dstUdp.IP.To4() == nil && srcIPs.srcIPv6 != nil {
			srcUdp = &net.UDPAddr{IP: srcIPs.srcIPv6}
		}
		return net.DialUDP(network, srcUdp, dstUdp)
	}
	return nil, fmt.Errorf("not tcp/udp")
}
