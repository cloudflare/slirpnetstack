package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/pin/tftp"
)

func setupTFTP(s *stack.Stack, state *State, rootPath string) error {
	if rootPath == "" {
		return nil
	}

	if abs, err := filepath.Abs(rootPath); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid TFTP root path: %v\n", err)
		return err
	} else {
		rootPath = abs
	}

	server := tftp.NewServer(func(filename string, rf io.ReaderFrom) error {
		filename = filepath.Join(rootPath, filename)
		if !strings.HasPrefix(filename, rootPath) {
			fmt.Fprintf(os.Stderr, "Invalid filename %v\n", filename)
			return errors.New("Invalid filename")
		}

		file, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return err
		}
		if _, err := rf.ReadFrom(file); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return err
		}
		return nil
	}, nil)
	server.EnableSinglePort()

	addr := tcpip.FullAddress{1, tcpip.Address(state.Host), 69}
	if conn, e := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber); e != nil {
		return e
	} else {
		go server.Serve(conn)
	}

	return nil
}
