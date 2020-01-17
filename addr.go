package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

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
	network string
	bind    tcpip.FullAddress
	host    tcpip.FullAddress
	rpc     bool
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
	if network == "udprpc" {
		fwa.network = "udp"
		fwa.rpc = true
	} else {
		fwa.network = network
	}

	p = strings.Split(rest, ":")
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
		ip := netParseIP(bindIP)
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
		ip := netParseIP(hostIP)
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
