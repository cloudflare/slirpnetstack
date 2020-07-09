package main

import (
	"fmt"
	"strings"
	"time"
)

// For each pair of connections, there may be four errors. Error on
// reading the local/host conn, error on writing to local/host conn,
// error on reading from remote/guest end, error on writing to
// remote/guest end. It's important to distinguish which one was
// first, so 0 means LocalRead, 1 means LocalWrite, 2 means RemoteRead
// and 3 means RemoteWrite was first.
type ProxyError struct {
	LocalRead   error
	LocalWrite  error
	RemoteRead  error
	RemoteWrite error
	First       int
}

// See this and cry: https://github.com/golang/go/issues/4373
func ErrIsMyFault(err error) bool {
	s := err.Error()
	return strings.HasSuffix(s, "use of closed network connection")
}

func (pe ProxyError) String() string {
	x := []string{
		fmt.Sprintf("%s", pe.LocalRead),
		fmt.Sprintf("%s", pe.LocalWrite),
		fmt.Sprintf("%s", pe.RemoteRead),
		fmt.Sprintf("%s", pe.RemoteWrite),
	}
	if pe.LocalRead == nil || ErrIsMyFault(pe.LocalRead) {
		x[0] = "0"
	}
	if pe.LocalWrite == nil || ErrIsMyFault(pe.LocalWrite) {
		x[1] = "0"
	}
	if pe.RemoteRead == nil || ErrIsMyFault(pe.RemoteRead) {
		x[2] = "0"
	}
	if pe.RemoteWrite == nil || ErrIsMyFault(pe.RemoteWrite) {
		x[3] = "0"
	}
	x[pe.First] = fmt.Sprintf("[%s]", x[pe.First])

	return fmt.Sprintf("l=%s/%s r=%s/%s", x[0], x[1], x[2], x[3])
}

const (
	MINPROXYBUFSIZE = 2 * 1024
	MAXPROXYBUFSIZE = 256 * 1024
)

type Closer interface {
	CloseRead() error
	CloseWrite() error
}

func proxyOneFlow(
	in, out KaConn,
	readErrPtr, writeErrPtr *error,
	doneCh chan int,
	scDir int, sppHeader []byte) {
	var (
		tmpBuf []byte
		buf    = make([]byte, MINPROXYBUFSIZE)
	)

	for {
		n, err := in.Read(buf[:])
		if err != nil {
			*readErrPtr = err
			break
		}

		wbuf := buf[:n]
		if sppHeader != nil {
			if scDir == 0 {
				if len(wbuf) >= len(sppHeader) {
					wbuf = wbuf[len(sppHeader):]
				} else {
					// swallow the packet on error
					continue
				}
			}
			if scDir == 1 {
				if cap(tmpBuf) < cap(buf) {
					tmpBuf = make([]byte, cap(buf))
				}
				copy(tmpBuf, sppHeader)
				copy(tmpBuf[len(sppHeader):], wbuf)
				wbuf = tmpBuf[:len(sppHeader)+len(wbuf)]
			}
		}

		// Write must return n==len(buf) or err
		// https://golang.org/pkg/io/#Writer
		_, err = out.Write(wbuf)
		if err != nil {
			*writeErrPtr = err
			break
		}

		// Heuristics: Start with small buffer and bump it up
		// if full reads, up to some defined max.
		if n == len(buf) && len(buf) < MAXPROXYBUFSIZE {
			buf = make([]byte, len(buf)*2)
		}
	}

	// Synchronize with parent. It's important to do this _before_
	// closing sockets, since .Close() might trigger the other
	// proxy goroutine to exit with "use of closed fd"
	// error. There is no race here. We can push to channel
	// without closing yet.
	doneCh <- scDir

	in.SetTimeouts(5*time.Second, 2)
	out.SetTimeouts(5*time.Second, 2)

	if c, ok := in.(Closer); ok {
		c.CloseRead()
	} else {
		in.Close()
	}
	if c, ok := out.(Closer); ok {
		c.CloseWrite()
	} else {
		out.Close()
	}
}

func connSplice(local KaConn, remote KaConn, sppHeader []byte) ProxyError {
	var (
		pe     ProxyError
		doneCh = make(chan int, 2)
	)

	local.SetTimeouts(125*time.Second, 4)
	remote.SetTimeouts(125*time.Second, 4)

	go proxyOneFlow(local, remote, &pe.LocalRead,
		&pe.RemoteWrite, doneCh, 0, sppHeader)
	proxyOneFlow(remote, local, &pe.RemoteRead,
		&pe.LocalWrite, doneCh, 1, sppHeader)
	first := <-doneCh
	_ = <-doneCh
	switch {
	case first == 0 && pe.LocalRead != nil:
		pe.First = 0
	case first == 0 && pe.RemoteWrite != nil:
		pe.First = 3
	case first == 1 && pe.RemoteRead != nil:
		pe.First = 2
	case first == 1 && pe.LocalWrite != nil:
		pe.First = 1
	}
	local.Close()
	remote.Close()
	return pe
}
