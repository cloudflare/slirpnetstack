package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
	"strings"
)

var records = map[string]string{}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	if len(m.Question) != 1 {
		return
	}

	q := m.Question[0]

	v := records[q.Name]
	fmt.Printf("%q -> %q\n", q.Name, v)
	p := strings.SplitN(v, ":", 2)
	ip, port := "localhost.", "1234"
	switch len(p) {
	case 2:
		ip = p[0]
		port = p[1]
	}

	if r.Opcode == dns.OpcodeQuery {
		switch q.Qtype {
		case dns.TypeSRV:
			rr, _ := dns.NewRR(fmt.Sprintf("%s 0 IN	SRV 1 1 %s %s",
				q.Name,
				port,
				ip,
			))
			m.Answer = append(m.Answer, rr)
		}
	}
	w.WriteMsg(m)
}

func main() {
	port := flag.Int("port", 0, "port to run on")
	addr := flag.String("addr", "", "addr to run on")
	flag.Parse()

	for _, f := range flag.Args() {
		p := strings.SplitN(f, "=", 2)
		k, v := "", ""
		switch len(p) {
		case 1:
			k = p[0]
		case 2:
			k = p[0]
			v = p[1]
		}
		if !strings.HasSuffix(k, ".") {
			k = k + "."
		}
		records[k] = v
	}

	if *port == 0 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		*port = 20000 + r.Intn(32000-20000)
	}
	fmt.Printf("%d\n", *port)

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *addr, *port))
	if err != nil {
		fmt.Printf("Failed to set udp listener: %s\n", err.Error())
		os.Exit(-1)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Printf("Failed to set udp listener: %s\n", err.Error())
		os.Exit(-1)
	}

	// attach request handler func
	dns.HandleFunc(".", handleDnsRequest)

	server := &dns.Server{PacketConn: conn}
	err = server.ActivateAndServe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start server: %s\n ", err.Error())
		os.Exit(1)
	}
}
