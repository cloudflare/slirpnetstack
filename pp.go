package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
)

var (
	ErrUnexpectedEOF = io.ErrUnexpectedEOF
	ErrBadMagic      = errors.New("spp: bad magic number")
)

// Coverts IP address to its IPv6 representation.  Nil or wrong length
// IP addresses map to :: (all zeros).
func MustTo16(ip net.IP) net.IP {
	ip = ip.To16()
	if ip != nil {
		return ip
	}
	return net.IPv6zero
}

func DecodeSPP(b []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	if len(b) < 38 {
		return 0, nil, nil, ErrUnexpectedEOF
	}

	var (
		clientIP [16]byte
		proxyIP  [16]byte
	)

	if b[0] != 0x56 || b[1] != 0xec {
		return 0, nil, nil, ErrBadMagic
	}
	copy(clientIP[:], b[2:18])
	copy(proxyIP[:], b[18:34])
	clientPort := (int(b[34]) << 8) | int(b[35])
	proxyPort := (int(b[36]) << 8) | int(b[37])

	c := &net.UDPAddr{
		IP:   net.IP(clientIP[:]),
		Port: clientPort,
	}
	p := &net.UDPAddr{
		IP:   net.IP(proxyIP[:]),
		Port: proxyPort,
	}

	return 38, c, p, nil
}

func EncodeSPP(b []byte, c, p *net.UDPAddr) (int, error) {
	if len(b) < 38 {
		return 0, ErrUnexpectedEOF
	}

	b[0] = 0x56
	b[1] = 0xec
	copy(b[2:18], MustTo16(c.IP))
	copy(b[18:34], MustTo16(p.IP))
	b[34] = byte(c.Port >> 8)
	b[35] = byte(c.Port)
	b[36] = byte(p.Port >> 8)
	b[37] = byte(p.Port)
	return 38, nil
}

func DecodePP(b []byte) (int, *net.TCPAddr, *net.TCPAddr, error) {
	var line []byte
	var n int
	for i, c := range b {
		if c == '\n' {
			line = b[:i+1]
			n = i + 1
			break
		}
	}

	if line == nil {
		return 0, nil, nil, ErrUnexpectedEOF
	}
	switch {
	case bytes.HasPrefix(line, []byte("PROXY TCP4 ")) && bytes.HasSuffix(line, []byte("\r\n")):
		line = line[11 : len(line)-2]
	case bytes.HasPrefix(line, []byte("PROXY TCP6 ")) && bytes.HasSuffix(line, []byte("\r\n")):
		line = line[11 : len(line)-2]
	default:
		return n, nil, nil, ErrBadMagic
	}

	p := bytes.SplitN(line, []byte(" "), 4)
	if len(p) != 4 {
		return n, nil, nil, ErrBadMagic
	}

	srcIP := net.ParseIP(string(p[0]))
	dstIP := net.ParseIP(string(p[1]))
	srcPort, e1 := strconv.ParseUint(string(p[2]), 10, 16)
	dstPort, e2 := strconv.ParseUint(string(p[3]), 10, 16)
	if srcIP == nil || dstIP == nil || e1 != nil || e2 != nil {
		return n, nil, nil, ErrBadMagic
	}
	s := &net.TCPAddr{
		IP:   srcIP,
		Port: int(srcPort),
	}

	d := &net.TCPAddr{
		IP:   dstIP,
		Port: int(dstPort),
	}
	return n, s, d, nil
}
