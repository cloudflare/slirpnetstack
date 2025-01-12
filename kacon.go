package main

import (
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type KaConn interface {
	net.Conn
	SetTimeouts(kaInterval time.Duration, kaCount int) error
}

type KaTCPConn struct {
	*net.TCPConn
}

func (c *KaTCPConn) SetTimeouts(kaInterval time.Duration, kaCount int) error {
	err := c.TCPConn.SetKeepAlive(true)
	if err != nil {
		return err
	}

	err = c.TCPConn.SetKeepAlivePeriod(kaInterval)
	if err != nil {
		return err
	}

	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}

	// Configures the connection to time out after peer has been idle for a
	// while, that is it has not sent or acknowledged any data or not replied to
	// keep-alive probes.
	userTimeout := UserTimeoutFromKeepalive(kaInterval, kaCount)

	return raw.Control(func(s_ uintptr) {
		s := int(s_)
		syscall.SetsockoptInt(s, syscall.SOL_TCP, unix.TCP_KEEPCNT, kaCount)
		userTimeoutMillis := int(userTimeout / time.Millisecond)
		syscall.SetsockoptInt(s, syscall.SOL_TCP, unix.TCP_USER_TIMEOUT, userTimeoutMillis)
	})
}

func UserTimeoutFromKeepalive(kaInterval time.Duration, kaCount int) time.Duration {
	// The idle timeout period is determined from the keep-alive probe interval
	// and the total number of probes to sent, that is
	//
	//   TCP_USER_TIMEOUT = TCP_KEEPIDLE + TCP_KEEPINTVL * TCP_KEEPCNT
	//
	// in Go, TCPConn.SetKeepAlivePeriod(d) sets the value for both TCP_KEEPIDLE
	// and TCP_KEEPINTVL
	//
	// More info: https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
	//
	return kaInterval + (kaInterval * time.Duration(kaCount))
}

type UDPKeepAliveError struct{ error }

type KaUDPConn struct {
	net.Conn
	keepAlive       bool
	keepAlivePeriod time.Duration
	closeOnWrite    bool
	periodMu        sync.RWMutex
}

func (c *KaUDPConn) SetTimeouts(kaInterval time.Duration, kaCount int) error {
	c.periodMu.Lock()
	c.keepAlive = true
	c.keepAlivePeriod = kaInterval
	c.periodMu.Unlock()
	return nil
}

func (c *KaUDPConn) Read(buf []byte) (int, error) {
	var t time.Time

	// IsZero means deadline is disabled. Good.
	c.periodMu.RLock()
	if c.keepAlive {
		t = time.Now().Add(c.keepAlivePeriod)
	}
	c.periodMu.RUnlock()

	// Zero is fine. Will cancel deadline.
	c.Conn.SetReadDeadline(t)

	n, err := c.Conn.Read(buf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		// On Keepalive raise special error
		return 0, &UDPKeepAliveError{err}
	} else {
		// Otherwise (other error or deadline timeout) just pass
		// direct to user.
		return n, err
	}
}

func (c *KaUDPConn) Write(buf []byte) (int, error) {
	// Here is the deal. The UDP conn doesn't have a notion of
	// half-closed. Instead, let's keep both directions alive,
	// even if only one of them is live. On Write, let's grant
	// more time to reader.
	c.periodMu.RLock()
	if c.keepAlive {
		t := time.Now().Add(c.keepAlivePeriod)
		c.Conn.SetReadDeadline(t)
	}
	closeOnWrite := c.closeOnWrite
	c.periodMu.RUnlock()

	n, err := c.Conn.Write(buf)
	if closeOnWrite {
		c.Conn.Close()
	}
	return n, err
}
