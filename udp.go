package main

import (
	"net"
	"syscall"
)

type SyscallConner interface {
	SyscallConn() (syscall.RawConn, error)
}

func SetReuseaddr(fd SyscallConner) error {
	rawConn, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
}

func MagicDialUDP(laddr, raddr *net.UDPAddr) (*KaUDPConn, error) {
	setDialerOptions := func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(s_ uintptr) {
			s := int(s_)
			syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
	}

	dialer := net.Dialer{LocalAddr: laddr, Control: setDialerOptions}
	c, err := dialer.Dial(raddr.Network(), raddr.String())
	if err != nil {
		return nil, err
	}
	cx := c.(*net.UDPConn)
	return &KaUDPConn{Conn: cx}, nil
}
