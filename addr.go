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
	bind          tcpip.FullAddress
	host          tcpip.FullAddress
	kaEnable      bool
	kaInterval    time.Duration
	proxyProtocol bool
}

type FwdAddrSlice []FwdAddr

func (f *FwdAddrSlice) String() string {
	s := make([]string, 0, 10)
	for _, fa := range *f {
		x := fmt.Sprintf("%s://%s:%d-%s:%d",
			fa.network,
			net.IP(fa.bind.Addr).String(), fa.bind.Port,
			net.IP(fa.host.Addr).String(), fa.host.Port)
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
	default:
		fwa.network = network
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

	if bindIP != "" {
		ip := netParseOrResolveIP(bindIP)
		if ip == nil {
			return fmt.Errorf("Unable to parse IP address %q", bindIP)
		}
		if ip.To4() != nil {
			ip = ip.To4()
		}
		fwa.bind.Addr = tcpip.Address(ip)
	}

	if bindPort != "" {
		port, err := strconv.ParseUint(bindPort, 10, 16)
		if err != nil {
			return err
		}

		// in case only bindPort is set, and not hostPort, set the default:
		fwa.bind.Port = uint16(port)
		fwa.host.Port = uint16(port)
	}

	if hostIP != "" {
		ip := netParseOrResolveIP(hostIP)
		if ip == nil {
			return fmt.Errorf("Unable to parse IP address %q", hostIP)
		}
		if ip.To4() != nil {
			ip = ip.To4()
		}
		fwa.host.Addr = tcpip.Address(ip)
	}
	if hostPort != "" {
		port, err := strconv.ParseUint(hostPort, 10, 16)
		if err != nil {
			return err
		}
		fwa.host.Port = uint16(port)
	}

	*f = append(*f, fwa)
	return nil
}

func (f *FwdAddrSlice) SetDefaultAddrs(bindAddrDef net.IP, hostAddrDef net.IP) {
	for i, _ := range *f {
		fa := &(*f)[i]
		if fa.bind.Addr == "" {
			fa.bind.Addr = tcpip.Address(bindAddrDef)
		}
		if fa.host.Addr == "" {
			fa.host.Addr = tcpip.Address(hostAddrDef)
		}
	}
}

func (f *FwdAddr) BindAddr() net.Addr {
	switch f.network {
	case "tcp":
		return &net.TCPAddr{
			IP:   net.IP(f.bind.Addr),
			Port: int(f.bind.Port),
		}
	case "udp":
		return &net.UDPAddr{
			IP:   net.IP(f.bind.Addr),
			Port: int(f.bind.Port),
		}
	}
	return nil
}

func (f *FwdAddr) HostAddr() net.Addr {
	switch f.network {
	case "tcp":
		return &net.TCPAddr{
			IP:   net.IP(f.host.Addr),
			Port: int(f.host.Port),
		}
	case "udp":
		return &net.UDPAddr{
			IP:   net.IP(f.host.Addr),
			Port: int(f.host.Port),
		}
	}
	return nil
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
	f.ip = net.ParseIP(value)
	if f.ip == nil {
		return fmt.Errorf("Not a valid IP %s", value)
	}
	return nil
}
