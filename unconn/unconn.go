package unconn

import (
	"net"
	"syscall"
)

const (
	IPV6_RECVORIGDSTADDR = 74
	IPV6_ORIGDSTADDR     = 74
)

func Prime(udpConn *net.UDPConn) error {
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return err
	}
	return rawConn.Control(func(_fd uintptr) {
		fd := int(_fd)
		// IP_RECVORIGDSTADDR triggers IP_ORIGDSTADDR CMSG on recv. Ions.
		syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)

		// IPV6_RECVORIGDSTADDR triggers IPV6_ORIGDSTADDR CMSG on
		// recv. It gives us server IP and sever Port for IPv6
		// connections.
		syscall.SetsockoptInt(fd, syscall.SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)
	})
}

func ExtractCMSGDestinationAddr(oob []byte) (net.UDPAddr, bool) {
	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return net.UDPAddr{}, false
	}

	var (
		a  net.UDPAddr
		ok bool
	)
	for _, m := range scms {
		h := m.Header
		if h.Level == syscall.SOL_IP && h.Type == syscall.IP_ORIGDSTADDR {
			var ip [4]byte
			copy(ip[:], m.Data[4:8])
			a.IP = net.IP(ip[:])
			a.Port = (int(m.Data[2]) << 8) | int(m.Data[3])
			ok = true
		} else if h.Level == syscall.SOL_IPV6 && h.Type == IPV6_ORIGDSTADDR {
			var ip [16]byte
			copy(ip[:], m.Data[8:24])
			a.IP = net.IP(ip[:])
			a.Port = (int(m.Data[2]) << 8) | int(m.Data[3])
			ok = true
		}
	}
	return a, ok
}

func Write(udpConn *net.UDPConn, src net.IP, dst *net.UDPAddr, b []byte) (int, error) {
	var oob []byte
	var ifi []byte
	if src.To4() != nil {
		// Blob contains ready CMSG with IP_PKTINFO and dst_ip
		// is 127.0.0.2 and dst interface is uint32(1)
		oob = []byte("\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\b\x00\x00\x00\x01\x00\x00\x00\x7f\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00")
		ifi = oob[16:20]
		copy(oob[20:24], src.To4())
	} else {
		// Blob contains ready CMSG with IPV6_PKTINFO and
		// dst_ip is ::2 and dst interface is uint32(1)
		oob = []byte("$\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x002\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\x00\x00\x00\x00\x00\x00\x00")
		ifi = oob[32:36]
		copy(oob[16:32], src.To16())
	}

	// Overwrite target interface to uint32(0)
	copy(ifi, []byte("\x00\x00\x00\x00"))

	n, _, err := udpConn.WriteMsgUDP(b, oob, dst)
	return n, err
}

func Read(udpConn *net.UDPConn, buf []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	oob := make([]byte, 1024)
	n, oobn, _, raddr, err := udpConn.ReadMsgUDP(buf, oob)

	if err != nil {
		return 0, nil, nil, err
	}

	laddr, ok := ExtractCMSGDestinationAddr(oob[:oobn])
	if ok == false {
		return n, nil, raddr, err
	}
	return n, &laddr, raddr, err
}
