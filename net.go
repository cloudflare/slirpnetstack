package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

// Deferred Address. Either just an ip, in which case 'static' is
// filled and we are done, or something we need to retrieve from DNS.
type defAddress struct {
	sync.Mutex

	// Static hardcoded IP/port OR previously retrieved one. In
	// other words it's never empty for a valid address.
	static  tcpip.FullAddress
	label   string
	fetched time.Time
	error   error
}

func ParseDefAddress(ipS string, portS string) (_da *defAddress, _err error) {
	da := &defAddress{}
	if ipS != "" {
		if ip := netParseIP(ipS); ip != nil {
			// ipS is an IP literal
			da.static.Addr = tcpip.AddrFromSlice(ip)
		} else {
			// ipS is a hostname to resolve later
			da.label = ipS
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

func (da *defAddress) Retrieve() *tcpip.FullAddress {
	da.Lock()
	defer da.Unlock()
	if da.label == "" || time.Since(da.fetched) <= dnsTTL {
		return &da.static
	}
	da.fetched = time.Now()

	ip, port, err := FullResolve(da.label)
	if err != nil {
		// Failed to resolve
		da.error = err
		return nil
	} else {
		da.static.Addr = tcpip.AddrFromSlice(ip)
		if port != 0 {
			da.static.Port = uint16(port)
		}
		da.error = nil
	}
	return &da.static
}

func (da *defAddress) SetDefaultAddr(a net.IP) {
	if da.static.Addr.Len() == 0 {
		da.static.Addr = tcpip.AddrFromSlice(a)
	}
}

func (da *defAddress) String() string {
	static := da.Retrieve()
	if static == nil {
		return fmt.Sprintf("%s-failed", da.label)
	}
	return fmt.Sprintf("%s:%d", da.static.Addr.String(), da.static.Port)
}

func (da *defAddress) GetTCPAddr() *net.TCPAddr {
	static := da.Retrieve()
	if static == nil {
		return nil
	}

	return &net.TCPAddr{
		IP:   static.Addr.AsSlice(),
		Port: int(static.Port),
	}
}

func (da *defAddress) GetUDPAddr() *net.UDPAddr {
	static := da.Retrieve()
	if static == nil {
		return nil
	}

	return &net.UDPAddr{
		IP:   static.Addr.AsSlice(),
		Port: int(static.Port),
	}
}

func simpleLookupHost(resolver *net.Resolver, label string) (net.IP, error) {
	addrs, err := resolver.LookupHost(context.Background(), label)
	if err != nil {
		// On resolution failure, error out
		return nil, err
	}
	if len(addrs) < 1 {
		return nil, fmt.Errorf("empty dns reponse for %q", label)
	}

	// prefer IPv4. No real reason.
	for _, addr := range addrs {
		ip := netParseIP(addr)
		if ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	ip := netParseIP(addrs[0])
	if ip == nil {
		return nil, fmt.Errorf("empty dns reponse for %q", label)
	}
	return ip, nil
}

func FullResolve(label string) (net.IP, uint16, error) {
	port := uint16(0)
	p := strings.SplitN(label, "@", 2)
	if len(p) == 2 {
		srvQuery, dnsSrv := p[0], p[1]
		if !strings.HasPrefix(dnsSrv, "srv-") {
			return nil, 0, fmt.Errorf("unknown dns type %q", dnsSrv)
		}

		dnsSrvAddr := dnsSrv[4:]
		if !strings.Contains(dnsSrvAddr, ":") {
			dnsSrvAddr = fmt.Sprintf("127.0.0.1:%s", dnsSrvAddr)
		}
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Duration(3 * time.Second),
				}
				return d.DialContext(ctx, "udp", dnsSrvAddr)
			},
		}
		_, srvAddrs, err := r.LookupSRV(context.Background(), "", "", srvQuery)
		if err != nil || len(srvAddrs) == 0 {
			return nil, 0, fmt.Errorf("failed to lookup SRV %q on %q", srvQuery, dnsSrvAddr)
		}

		// For effective resolution, allowing to utilize
		// /etc/hosts, trim the trailing dot if present.
		serviceLabel := srvAddrs[0].Target
		servicePort := srvAddrs[0].Port
		serviceLabel = strings.TrimSuffix(serviceLabel, ".")

		ip, err := simpleLookupHost(r, serviceLabel)
		if err == nil && ip != nil {
			return ip, servicePort, nil
		}

		// Fallthrough and try the OS resolver
		label = serviceLabel
		port = servicePort
	}

	ip, err := simpleLookupHost(net.DefaultResolver, label)
	if err != nil {
		return nil, 0, err
	}
	return ip, port, nil
}

func netParseOrResolveIP(h string) (_ip net.IP, _resolved bool, _err error) {
	ip := netParseIP(h)
	if ip != nil {
		return ip, false, nil
	}

	ip, _, err := FullResolve(h)
	return ip, true, err
}

func OutboundDial(state *State, dst net.Addr) (net.Conn, error) {
	srcIPs := &state.srcIPs
	network := dst.Network()
	dialer := &net.Dialer{}
	if state.fwmark != 0 {
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, state.fwmark)
			})
			if err != nil {
				return err
			}
			return controlErr
		}
	}
	if network == "tcp" {
		dstTcp := dst.(*net.TCPAddr)
		var srcTcp *net.TCPAddr
		if srcIPs != nil && dstTcp.IP.To4() != nil && srcIPs.srcIPv4 != nil {
			srcTcp = &net.TCPAddr{IP: srcIPs.srcIPv4}
		}
		if srcIPs != nil && dstTcp.IP.To4() == nil && srcIPs.srcIPv6 != nil {
			srcTcp = &net.TCPAddr{IP: srcIPs.srcIPv6}
		}
		dialer.LocalAddr = srcTcp
		return dialer.Dial(network, dstTcp.String())
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
		dialer.LocalAddr = srcUdp
		return dialer.Dial(network, dstUdp.String())
	}
	return nil, fmt.Errorf("not tcp/udp")
}
