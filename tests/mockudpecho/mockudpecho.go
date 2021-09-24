package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cloudflare/slirpnetstack/unconn"
)

func main() {
	port := flag.Int("port", 0, "port to run on")
	addr := flag.String("addr", "", "addr to run on")
	log := flag.Bool("log", false, "logline per packet")
	flag.Parse()

	var as string
	if !strings.Contains(*addr, ":") {
		as = fmt.Sprintf("%s:%d", *addr, *port)
	} else {
		as = fmt.Sprintf("[%s]:%d", *addr, *port)
	}
	a, err := net.ResolveUDPAddr("udp", as)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] resolve failed: %s\n", err)
		os.Exit(-1)
	}

	ln, err := net.ListenUDP("udp", a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] couldn't start listening: %s\n", err)
		os.Exit(-1)
	}

	lnAddr := ln.LocalAddr()
	udpAddr := lnAddr.(*net.UDPAddr)
	fmt.Printf("%d\n", udpAddr.Port)

	unconn.Prime(ln)

	var buf [64*1024]byte
	for {
		n, laddr, raddr, err := unconn.Read(ln, buf[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] read failed: %s\n", err)
			continue
		}
		unconn.Write(ln, laddr.IP, raddr, buf[:n])
		if *log {
			fmt.Printf("%s\n", raddr.String())
		}
	}
}
