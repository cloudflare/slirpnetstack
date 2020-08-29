package main

import (
	"context"
	"fmt"
	"net"
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

// Deferrred Address. Either just an IP, in which case 'static' is
// filled and we are done, or something we need to retrieve from DNS.
// This may contain an IPv4 and/or IPv6 address.
type defAddress struct {
	sync.Mutex

	// Static hardcoded IP/port OR previously retrieved one. In
	// other words it's never empty for a valid address.
	static4 tcpip.FullAddress
	static6 tcpip.FullAddress
	label   string
	fetched time.Time
	error   error
}

func ParseDefAddress(ipS string, portS string) (_da *defAddress, _err error) {
	da := &defAddress{}
	if ipS != "" {
		da.label = ipS
	}

	if portS != "" {
		var err error
		port, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			return nil, err
		}
		da.static4.Port = uint16(port)
		da.static6.Port = uint16(port)
	}

	return da, nil
}

// hasIPv4 checks for the presence of an IPv4 address and may perform DNS resolution.
func (da *defAddress) hasIPv4() bool {
	if da.label != "" {
		if da.resolve() != nil {
			// DNS error
			return false
		}
	}
	return da.static4.Addr != ""
}

// hasIPv6 checks for the presence of an IPv6 address and may perform DNS resolution.
func (da *defAddress) hasIPv6() bool {
	if da.label != "" {
		if da.resolve() != nil {
			// DNS error
			return false
		}
	}
	return da.static6.Addr != ""
}

// SetDefaultAddr sets the IP addresses that are used if label is unset. Either argument may be omitted.
func (da *defAddress) SetDefaultAddr(v4 net.IP, v6 net.IP) {
	if da.static4.Addr == "" && da.static6.Addr == "" {
		da.static4.Addr = tcpip.Address(v4).To4()
		da.static6.Addr = tcpip.Address(v6)
	}
}

// Retreive returns a static address or resolves the label in DNS. Prefers to return IPv4 over IPv6.
func (da *defAddress) Retrieve() *tcpip.FullAddress {
	if da.label == "" {
		// Return IPv4 or IPv6
		if da.static4.Addr != "" {
			return &da.static4
		}
		return &da.static6
	}

	da.error = da.resolve()
	if da.error != nil {
		return nil
	}

	// Return IPv4 or IPv6
	if da.static4.Addr != "" {
		return &da.static4
	}
	return &da.static6
}

// resolve performs a DNS resolution of label and populates static4 and/or static6, or returns an error.
// May return a cached result according to dnsTTL.
func (da *defAddress) resolve() error {
	da.Lock()
	defer da.Unlock()

	if da.label == "" {
		return fmt.Errorf("DNS resolution attempted on empty defAddress label")
	}
	if time.Now().Sub(da.fetched) <= dnsTTL {
		return nil // Use cached result
	}
	da.fetched = time.Now()

	ipv4, ipv6, port, err := FullResolve(da.label)
	if err != nil {
		// Failed to resolve
		return err
	}
	da.static4.Addr = tcpip.Address(ipv4)
	da.static6.Addr = tcpip.Address(ipv6)
	if port != 0 {
		da.static4.Port = uint16(port)
		da.static6.Port = uint16(port)
	}
	return nil
}

// String returns host:port of the IPv4 or IPv6 address, or host-failed on DNS resoluton failure.
// If both IPv6 and IPv6 exist, IPv4 only is returned.
func (da *defAddress) String() string {
	static := da.Retrieve()
	if static == nil {
		return fmt.Sprintf("%s-failed", da.label)
	}
	return fmt.Sprintf("%s:%d", net.IP(static.Addr).String(), static.Port)
}

// GetTCPAddr returns a TCPAddr for IPv4 and/or IPv6, or neither if DNS resolution fails.
func (da *defAddress) GetTCPAddr() (tcpv4, tcpv6 *net.TCPAddr) {
	if da.hasIPv4() { // hasIPv4 performs DNS resolution if necessary
		tcpv4 = &net.TCPAddr{
			IP:   net.IP(da.static4.Addr),
			Port: int(da.static4.Port),
		}
	}
	if da.hasIPv6() {
		tcpv6 = &net.TCPAddr{
			IP:   net.IP(da.static6.Addr),
			Port: int(da.static6.Port),
		}
	}
	return
}

// GetUDPAddr returns a UDPAddr for IPv4 and/or IPv6, or neither if DNS resolution fails.
func (da *defAddress) GetUDPAddr() (udpv4, udpv6 *net.UDPAddr) {
	if da.hasIPv4() { // hasIPv4 performs DNS resolution if necessary
		udpv4 = &net.UDPAddr{
			IP:   net.IP(da.static4.Addr),
			Port: int(da.static4.Port),
		}
	}
	if da.hasIPv6() {
		udpv6 = &net.UDPAddr{
			IP:   net.IP(da.static6.Addr),
			Port: int(da.static6.Port),
		}
	}
	return
}

// simpleLookupHost resolves an IPv4 and/or IPv6 address
func simpleLookupHost(resolver *net.Resolver, label string) (net.IP, net.IP, error) {
	addrs, err := resolver.LookupHost(context.Background(), label)
	if err != nil {
		// On resolution failure, error out
		return nil, nil, err
	}
	if len(addrs) < 1 {
		return nil, nil, fmt.Errorf("Empty dns reponse for %q", label)
	}

	var ipv4, ipv6 net.IP
	// prefer IPv4. No real reason.
	for _, addr := range addrs {
		ip := netParseIP(addr)
		if ip.To4() != nil {
			if ipv4 == nil {
				ipv4 = ip.To4()
			}
		} else if ip.To16() != nil {
			if ipv6 == nil {
				ipv6 = ip.To16()
			}
		}

		if ipv4 != nil && ipv6 != nil {
			return ipv4, ipv6, nil
		}
	}

	if ipv4 == nil && ipv6 == nil {
		return nil, nil, fmt.Errorf("Empty dns reponse for %q", label)
	}
	return ipv4, ipv6, nil
}

// FullResolve attempts a DNS lookup on label and returns an IPv4 and/or IPv6 result.
// Optionally resolves the format 'label@srv-1234:0', which means to retrieve the target label
// from DNS on localhost on port 1234 from SRV record.
func FullResolve(label string) (net.IP, net.IP, uint16, error) {
	port := uint16(0)
	p := strings.SplitN(label, "@", 2)
	if len(p) == 2 {
		srvQuery, dnsSrv := p[0], p[1]
		if !strings.HasPrefix(dnsSrv, "srv-") {
			return nil, nil, 0, fmt.Errorf("Unknown dns type %q", dnsSrv)
		}
		dnsPort, err := strconv.ParseUint(dnsSrv[4:], 10, 16)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("Cant parse dns server port %q", dnsSrv[4:])
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
		_, srvAddrs, err := r.LookupSRV(context.Background(), "", "", srvQuery)
		if err != nil || len(srvAddrs) == 0 {
			return nil, nil, 0, fmt.Errorf("Failed to lookup SRV %q on %q", srvQuery, dnsSrvAddr)
		}

		// For effective resolution, allowing to utilize
		// /etc/hosts, trim the trailing dot if present.
		serviceLabel := srvAddrs[0].Target
		servicePort := srvAddrs[0].Port
		if strings.HasSuffix(serviceLabel, ".") {
			serviceLabel = serviceLabel[:len(serviceLabel)-1]
		}

		ipv4, ipv6, err := simpleLookupHost(r, serviceLabel)
		if err == nil && (ipv4 != nil || ipv6 != nil) {
			return ipv4, ipv6, servicePort, nil
		}

		// Fallthrough and try the OS resolver
		label = serviceLabel
		port = servicePort
	}

	ipv4, ipv6, err := simpleLookupHost(net.DefaultResolver, label)
	if err != nil {
		return nil, nil, 0, err
	}
	return ipv4, ipv6, port, nil
}

// netParseOrResolveIP attempted to convert h to an IP address, otherwise performs DNS resolution.
// If both IPv4 and IPv6 DNS records exist, the IPv4 is returned.
func netParseOrResolveIP(h string) (_ip net.IP, _resolved bool, _err error) {
	ip := netParseIP(h)
	if ip != nil {
		return ip, false, nil
	}

	ipv4, ipv6, _, err := FullResolve(h)
	if err != nil {
		return nil, true, err
	}
	if ipv4 != nil {
		return ipv4, true, nil
	}
	return ipv6, true, nil
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
