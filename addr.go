package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

/* SSH supports this syntax:
-R ... connections to given TCP port ... on the remote host are to be forwarded to the local side...
-L ... on the local host are to be forwarded to the given port... on the remote side...

  -L [bind_address:]port:host:hostport
  -R [bind_address:]port:host:hostport
  -R [bind_address:]port

  -L [bind_address:]port:remote_socket
  -L local_socket:remote_socket
  -L local_socket:host:hostport
  -R [bind_address:]port:local_socket
  -R remote_socket:host:hostport
  -R remote_socket:local_socket

*/
type FwdAddr struct {
	network       string
	bind          defAddress
	host          defAddress
	kaEnable      bool
	kaInterval    time.Duration
	proxyProtocol bool
}

type FwdAddrSlice []FwdAddr

func (f *FwdAddrSlice) String() string {
	s := make([]string, 0, 10)
	for _, fa := range *f {
		x := fmt.Sprintf("%s://%s-%s",
			fa.network,
			fa.bind.String(),
			fa.host.String())
		s = append(s, x)
	}
	return strings.Join(s, " ")
}

func (f *FwdAddrSlice) Set(value string) error {
	var (
		bindPort, bindIP string
		network          string
		rest             string
		hostIP, hostPort string
	)

	p := strings.SplitN(value, "://", 2)
	switch len(p) {
	case 2:
		network = p[0]
		rest = p[1]
	case 1:
		network = "tcp"
		rest = p[0]
	}

	var fwa FwdAddr
	switch network {
	case "udprpc":
		fwa.network = "udp"
		fwa.kaEnable = true
		fwa.kaInterval = 0
	case "udpspp":
		fwa.network = "udp"
		fwa.proxyProtocol = true
	case "tcppp":
		fwa.network = "tcp"
		fwa.proxyProtocol = true
	case "tcp", "udp":
		fwa.network = network
	default:
		return fmt.Errorf("unknown network type %q", network)
	}

	p = SplitHostPort(rest)
	switch len(p) {
	case 1:
		bindPort = p[0]
	case 2:
		bindIP = p[0]
		bindPort = p[1]
	case 3:
		bindPort = p[0]
		hostIP = p[1]
		hostPort = p[2]
	case 4:
		bindIP = p[0]
		bindPort = p[1]
		hostIP = p[2]
		hostPort = p[3]
	}

	if bindIP != "" || bindPort != "" {
		bind, err := ParseDefAddress(bindIP, bindPort)
		if err != nil {
			return err
		}
		fwa.bind = *bind
	}

	if bindPort != "" && hostPort == "" {
		// in case only bindPort is set, and not hostPort, set the default:
		hostPort = bindPort
	}

	if hostIP != "" || hostPort != "" {
		host, err := ParseDefAddress(hostIP, hostPort)
		if err != nil {
			return err
		}
		fwa.host = *host
	}

	*f = append(*f, fwa)
	return nil
}

// SetDefaultAddrs populates any unset endpoint with the provided default value.
// IPv6 values are only used if the one of the existing addresses is IPv6.
func (f *FwdAddrSlice) SetDefaultAddrs(bindAddrDef net.IP, bindAddr6Def net.IP, hostAddrDef net.IP, hostAddr6Def net.IP) {
	for i := range *f {
		fa := &(*f)[i]
		if (fa.bind.static.Addr != "" && fa.bind.static.Addr.To4() == "") ||
			(fa.host.static.Addr != "" && fa.host.static.Addr.To4() == "") {
			// Bind and/or host is IPv6
			fa.bind.SetDefaultAddr(bindAddr6Def)
			fa.host.SetDefaultAddr(hostAddr6Def)
		} else {
			// Neither address is IPv6
			fa.bind.SetDefaultAddr(bindAddrDef)
			fa.host.SetDefaultAddr(hostAddrDef)
		}
	}
}

func (f *FwdAddr) BindAddr() (net.Addr, error) {
	switch f.network {
	case "tcp":
		x := f.bind.GetTCPAddr()
		if x == nil {
			return nil, fmt.Errorf("dns lookup error of tcp addr: %w", f.bind.error)
		}
		return x, nil
	case "udp":
		x := f.bind.GetUDPAddr()
		if x == nil {
			return nil, fmt.Errorf("dns lookup error of udp addr: %w", f.bind.error)
		}
		return x, nil
	}
	return nil, fmt.Errorf("unknown network type: %v", f.network)
}

func (f *FwdAddr) HostAddr() (net.Addr, error) {
	switch f.network {
	case "tcp":
		x := f.host.GetTCPAddr()
		if x == nil {
			return nil, fmt.Errorf("dns lookup error of tcp addr: %w", f.host.error)
		}
		return x, nil
	case "udp":
		x := f.host.GetUDPAddr()
		if x == nil {
			return nil, fmt.Errorf("dns lookup error of udp addr: %w", f.host.error)
		}
		return x, nil
	}
	return nil, fmt.Errorf("unknown network type: %v", f.network)
}

func FullAddressFromAddr(a net.Addr) *tcpip.FullAddress {
	switch v := a.(type) {
	case *net.TCPAddr:
		return &tcpip.FullAddress{
			Addr: tcpip.Address(v.IP),
			Port: uint16(v.Port),
		}
	case *net.UDPAddr:
		return &tcpip.FullAddress{
			Addr: tcpip.Address(v.IP),
			Port: uint16(v.Port),
		}
	}
	return nil
}

func netAddrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	}
	return nil
}

func netAddrPort(a net.Addr) int {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.Port
	case *net.UDPAddr:
		return v.Port
	}
	return 0
}

func netAddrSetPort(a net.Addr, port int) net.Addr {
	switch v := a.(type) {
	case *net.TCPAddr:
		x := *v
		x.Port = port
		return &x
	case *net.UDPAddr:
		x := *v
		x.Port = port
		return &x
	}
	return nil
}

// Addr that can be set from flag.Var. For example:
//	flag.Var(&metricAddr, "m", "Metrics address")
type AddrFlags struct {
	net.Addr
}

func (a *AddrFlags) String() string {
	if a.Addr == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", a.Network(), a.Addr)
}

func (a *AddrFlags) Set(value string) error {
	if addr, err := AddrFromString(value); err != nil {
		return err
	} else {
		a.Addr = addr
		return nil
	}
}

func AddrFromString(value string) (net.Addr, error) {
	p := strings.SplitN(value, "://", 2)
	if len(p) != 2 {
		return nil, fmt.Errorf("Address must be in form net://address, where net is one of unix/tcp/udp")
	}
	var addr net.Addr
	switch p[0] {
	case "tcp":
		if v, err := net.ResolveTCPAddr(p[0], p[1]); err != nil {
			return nil, err
		} else {
			addr = v
		}

	case "udp":
		if v, err := net.ResolveUDPAddr(p[0], p[1]); err != nil {
			return nil, err
		} else {
			addr = v
		}

	case "unix":
		if v, err := net.ResolveUnixAddr(p[0], p[1]); err != nil {
			return nil, err
		} else {
			addr = v
		}
	default:
		return nil, fmt.Errorf("Address must be in form net://address, where net is one of unix/tcp/udp")
	}
	return addr, nil
}

func SplitHostPort(buf string) []string {
	sliceOfParts := make([]string, 0)
	part := make([]byte, 0)
	in := false
	for _, c := range []byte(buf) {
		switch {
		case in == false && c == '[':
			in = true
		case in == true && c == ']':
			in = false
		case in == false && c == ':':
			sliceOfParts = append(sliceOfParts, string(part))
			part = make([]byte, 0)
		default:
			part = append(part, c)
		}
	}
	sliceOfParts = append(sliceOfParts, string(part))
	return sliceOfParts
}

type IPFlag struct {
	ip net.IP
}

func (f *IPFlag) String() string {
	return fmt.Sprintf("%s", f.ip)
}

func (f *IPFlag) Set(value string) error {
	var err error
	f.ip, _, err = netParseOrResolveIP(value)
	if err != nil {
		return err
	}
	return nil
}

type IPPortRange struct {
	network string
	ipRange *net.IPNet
	portMin uint16
	portMax uint16
}

type IPPortRangeSlice []IPPortRange

func (p *IPPortRange) String() string {
	a := []string{
		p.network,
		"://",
	}
	if p.ipRange.IP.To4() == nil {
		a = append(a, "[")
	}
	a = append(a, p.ipRange.String())
	if p.ipRange.IP.To4() == nil {
		a = append(a, "]")
	}
	if p.portMin != 0 || p.portMax != 0 {
		a = append(a, ":", fmt.Sprintf("%d-%d", p.portMin, p.portMax))
	}
	return strings.Join(a, "")
}

func (f *IPPortRangeSlice) String() string {
	var a []string
	for _, p := range *f {
		a = append(a, p.String())
	}
	return strings.Join(a, ",")
}

func (f *IPPortRangeSlice) Set(commaValue string) error {
	for _, value := range strings.Split(commaValue, ",") {
		network, rest := "", ""
		p := strings.SplitN(value, "://", 2)
		switch len(p) {
		case 2:
			network = p[0]
			rest = p[1]
		case 1:
			network = "tcp"
			rest = p[0]
		}

		var (
			pMin, pMax uint64
			err1, err2 error
		)

		p = SplitHostPort(rest)
		if len(p) < 1 || len(p) > 2 {
			return fmt.Errorf("error parsing ipportrange")
		}
		host := p[0]

		if len(p) == 2 {
			portRange := p[1]
			pn := strings.SplitN(portRange, "-", 2)
			switch len(pn) {
			case 2:
				pMin, err1 = strconv.ParseUint(pn[0], 10, 16)
				pMax, err2 = strconv.ParseUint(pn[1], 10, 16)
			case 1:
				pMin, err1 = strconv.ParseUint(pn[0], 10, 16)
				pMax, err2 = pMin, err1
			}
			if err1 != nil {
				return err1
			}
			if err2 != nil {
				return err2
			}
			if pMax < pMin {
				return fmt.Errorf("min port must be smaller equal than max")
			}
		}

		_, ipnet, err := net.ParseCIDR(host)
		if err != nil {
			ip, _, err := netParseOrResolveIP(host)
			if err != nil {
				return err
			}
			var mask net.IPMask
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			} else {
				mask = net.CIDRMask(32, 32)
			}

			ipnet = &net.IPNet{
				IP:   ip,
				Mask: mask,
			}
		}

		pr := IPPortRange{
			network: network,
			ipRange: ipnet,
			portMin: uint16(pMin),
			portMax: uint16(pMax),
		}

		*f = append(*f, pr)
	}
	return nil
}

func (f *IPPortRangeSlice) Contains(addr net.Addr) bool {
	addrNetwork := addr.Network()
	addrPort := uint16(netAddrPort(addr))
	addrIP := netAddrIP(addr)
	for _, p := range *f {
		if p.network != addrNetwork {
			// wrong proto
			continue
		}
		if p.portMin != 0 || p.portMax != 0 {
			if addrPort < p.portMin || addrPort > p.portMax {
				// port out of range if ports are in the selector
				continue
			}
		}
		if !p.ipRange.Contains(addrIP) {
			continue
		}
		return true
	}
	return false
}
