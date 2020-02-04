package main

import (
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"syscall"
	"time"
)

func init() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
}

type Metrics struct {
	err  chan error
	stop chan struct{}

	ln  net.Listener
	srv *http.Server
}

func StartMetrics(addr net.Addr) (*Metrics, error) {
	metrics := &Metrics{}
	if addr == nil || addr.Network() == "" {
		return nil, fmt.Errorf("invalid address: %v", addr)
	}

	metrics.err = make(chan error)
	metrics.stop = make(chan struct{})
	metrics.srv = &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 35 * time.Second,
	}

	var err error
	metrics.ln, err = net.Listen(addr.Network(), addr.String())
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[ ] #%d Running metrics on %s\n", syscall.Getpid(), metrics.ln.Addr())

	go func() {
		err := metrics.srv.Serve(metrics.ln)
		select {
		case <-metrics.stop:
		case metrics.err <- err:
		}
		close(metrics.err)
	}()

	return metrics, nil
}

func (metrics *Metrics) Err() <-chan error {
	return metrics.err
}

func (metrics *Metrics) Close() {
	close(metrics.stop)
	if metrics.ln != nil {
		fmt.Fprintf(os.Stderr, "[ ] #%d Stopping metrics\n", syscall.Getpid())
		metrics.ln.Close()
	}
}
