package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
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
	a, err := net.ResolveTCPAddr("tcp", as)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] resolve failed: %s\n", err)
		os.Exit(-1)
	}

	var ln net.Listener
	tcpLn, err := net.ListenTCP("tcp", a)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] couldn't start listening: %s\n", err)
		os.Exit(-1)
	}
	ln = tcpLn

	lnAddr := ln.Addr()
	tcpAddr := lnAddr.(*net.TCPAddr)
	fmt.Printf("%d\n", tcpAddr.Port)

	for {
		conn, err := ln.Accept()
		if conn == nil {
			fmt.Fprintf(os.Stderr, "[-] accept failed: %s\n", err)
			continue
		}
		if *log {
			fmt.Printf("%s\n", conn.RemoteAddr())
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	var buf [4096]byte
	for {
		n, err := conn.Read(buf[:])
		if err != nil {
			break
		}
		_, err = conn.Write(buf[:n])
		if err != nil {
			break
		}
	}
	conn.Close()
}
