package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
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

// Deferrred Address. Either just an ip, in which case 'static' is
// filled and we are done, or something we need to retrieve from DNS.
type defAddress struct {
	sync.Mutex

	// Static hardcoded IP/port OR previously retrieved one. In
	// other words it's never empty for a valid address.
	static    tcpip.FullAddress
	label     string
	timestamp time.Time
}

func ParseDefAddress(ipS string, portS string) (*defAddress, error) {
	da := &defAddress{}
	if ipS != "" {
		ip, resolved := netParseOrResolveIP(ipS)
		if ip == nil {
			return nil, fmt.Errorf("Unable to parse IP address %q", ip)
		}
		da.static.Addr = tcpip.Address(ip)
		if resolved {
			da.label = ipS
			da.timestamp = time.Now()
		}
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

func (da *defAddress) Retrieve() {
	da.Lock()
	defer da.Unlock()
	if da.label == "" || time.Now().Sub(da.timestamp) <= dnsTTL {
		return
	}
	da.timestamp = time.Now()

	ip, port := FullResolve(da.label)
	if ip == nil {
		// Failed to resolve
		fmt.Fprintf(os.Stderr, "[!] Failed to resolve %q, using stale\n", da.label)
	} else {
		da.static.Addr = tcpip.Address(ip)
		if port != 0 {
			da.static.Port = uint16(port)
		}
	}
}

func (da *defAddress) String() string {
	da.Retrieve()
	return fmt.Sprintf("%s:%d", net.IP(da.static.Addr).String(), da.static.Port)
}

func (da *defAddress) GetTCPAddr() *net.TCPAddr {
	da.Retrieve()
	return &net.TCPAddr{
		IP:   net.IP(da.static.Addr),
		Port: int(da.static.Port),
	}
}

func (da *defAddress) GetUDPAddr() *net.UDPAddr {
	da.Retrieve()
	return &net.UDPAddr{
		IP:   net.IP(da.static.Addr),
		Port: int(da.static.Port),
	}
}

func FullResolve(label string) (net.IP, uint16) {
	p := strings.SplitN(label, "@", 2)
	if len(p) == 2 {
		label, dnsSrv := p[0], p[1]
		if !strings.HasPrefix(dnsSrv, "srv-") {
			return nil, 0
		}
		dnsPort, err := strconv.ParseUint(dnsSrv[4:], 10, 16)
		if err != nil {
			return nil, 0
		}
		dnsSrvAddr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(3 * time.Second),
				}
				return d.DialContext(ctx, "udp", dnsSrvAddr)
			},
		}
		_, srvAddrs, err := r.LookupSRV(context.Background(), "", "", label)
		if err != nil || len(srvAddrs) == 0 {
			return nil, 0
		}
		addrs, err := net.LookupHost(srvAddrs[0].Target)
		if err != nil || len(addrs) < 1 {
			// On resolution failure, error out
			return nil, 0
		}
		return netParseIP(addrs[0]), srvAddrs[0].Port

	}

	addrs, err := net.LookupHost(label)
	if err != nil || len(addrs) < 1 {
		// On resolution failure, error out
		return nil, 0
	}

	// prefer IPv4. No real reason.
	for _, addr := range addrs {
		ip := netParseIP(addr)
		if ip.To4() != nil {
			return ip.To4(), 0
		}
	}

	return netParseIP(addrs[0]), 0
}

func netParseOrResolveIP(h string) (_ip net.IP, _resolved bool) {
	ip := netParseIP(h)
	if ip != nil {
		return ip, false
	}

	ip, _ = FullResolve(h)
	return ip, true
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
