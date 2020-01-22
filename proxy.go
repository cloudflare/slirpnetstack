package main

import (
	"fmt"
	"time"
)

type ProxyError struct {
	LocalRead   error
	LocalWrite  error
	RemoteRead  error
	RemoteWrite error
	First       int
}

func (pe ProxyError) String() string {
	x := []string{
		fmt.Sprintf("%s", pe.LocalRead),
		fmt.Sprintf("%s", pe.LocalWrite),
		fmt.Sprintf("%s", pe.RemoteRead),
		fmt.Sprintf("%s", pe.RemoteWrite),
	}
	if pe.LocalRead == nil {
		x[0] = "0"
	}
	if pe.LocalWrite == nil {
		x[1] = "0"
	}
	if pe.RemoteRead == nil {
		x[2] = "0"
	}
	if pe.RemoteWrite == nil {
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

func proxyOneFlow(in, out KaConn, readErrPtr, writeErrPtr *error, doneCh chan int, scDir int) {
	buf := make([]byte, MINPROXYBUFSIZE)

	for {
		n, err := in.Read(buf[:])
		if err != nil {
			*readErrPtr = err
			break
		}

		// Write must return n==len(buf) or err
		// https://golang.org/pkg/io/#Writer
		_, err = out.Write(buf[:n])
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

	in.SetTimeouts(5*time.Second, 2)
	out.SetTimeouts(5*time.Second, 2)

	// Synchronize with parent.
	doneCh <- scDir
}

func connSplice(local KaConn, remote KaConn) ProxyError {
	var (
		pe     ProxyError
		doneCh = make(chan int, 2)
	)

	local.SetTimeouts(125*time.Second, 4)
	remote.SetTimeouts(125*time.Second, 4)

	go proxyOneFlow(local, remote, &pe.LocalRead,
		&pe.RemoteWrite, doneCh, 0)
	proxyOneFlow(remote, local, &pe.RemoteRead,
		&pe.LocalWrite, doneCh, 1)
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
	return pe
}
