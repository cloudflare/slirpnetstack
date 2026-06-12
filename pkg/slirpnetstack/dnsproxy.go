package slirpnetstack

// DNS proxy for gateway addresses: guests send ordinary DNS queries to
// the gateway IP :53 and the proxy resolves them through the host
// system's resolver path.
//
// On Android that path is the DnsResolver service behind
// /dev/socket/dnsproxyd: raw queries are passed through the `resnsend`
// command (the same mechanism as the public android_res_nsend() NDK
// API), so Private DNS (DoT/DoH), per-network DNS selection, VPN DNS and
// the system cache all apply, for every record type (A, AAAA, SRV, TXT,
// ...). This requires no privileges beyond the `inet` group that comes
// with the INTERNET permission.
//
// On plain Linux (development hosts) queries are forwarded verbatim to
// the resolvers from /etc/resolv.conf.

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	dnsProxydSocket = "/dev/socket/dnsproxyd"
	dnsProxyPort    = 53
	// FrameworkListener commands are limited to a 1024-byte buffer;
	// "resnsend <netid> <flags> <b64>" leaves room for ~740 query bytes.
	dnsProxydMaxQuery = 700
	dnsQueryTimeout   = 5 * time.Second
	dnsIdleTimeout    = 30 * time.Second
	dnsMaxMessage     = 65535
)

// DNSProxy answers DNS on the gateway's own addresses.
type DNSProxy struct {
	ips     []net.IP
	android bool
	proxyd  string
	fb      *fallbackResolver
}

func NewDNSProxy(ips []net.IP) *DNSProxy {
	p := &DNSProxy{
		ips:    ips,
		proxyd: dnsProxydSocket,
		fb:     &fallbackResolver{path: "/etc/resolv.conf"},
	}
	if _, err := os.Stat(p.proxyd); err == nil {
		p.android = true
	}
	return p
}

// Matches reports whether dst ip:port is this gateway's DNS service.
func (p *DNSProxy) Matches(ip net.IP, port int) bool {
	if port != dnsProxyPort {
		return false
	}
	for _, own := range p.ips {
		if own.Equal(ip) {
			return true
		}
	}
	return false
}

// ServeUDP answers queries on one guest UDP flow until it goes idle.
func (p *DNSProxy) ServeUDP(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		query := buf[:n]
		answer, err := p.Resolve(query, false)
		if err != nil {
			fmt.Printf("dnsproxy: resolve failed: %v\n", err)
			answer = synthesizeDNSError(query, 2 /* SERVFAIL */)
			if answer == nil {
				continue
			}
		}
		conn.SetWriteDeadline(time.Now().Add(dnsQueryTimeout))
		if _, err := conn.Write(answer); err != nil {
			return
		}
	}
}

// ServeTCP answers length-framed queries on one guest TCP connection.
func (p *DNSProxy) ServeTCP(conn net.Conn) {
	defer conn.Close()
	for {
		conn.SetReadDeadline(time.Now().Add(dnsIdleTimeout))
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 || msgLen > dnsMaxMessage {
			return
		}
		query := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		answer, err := p.Resolve(query, true)
		if err != nil {
			fmt.Printf("dnsproxy: resolve failed: %v\n", err)
			answer = synthesizeDNSError(query, 2 /* SERVFAIL */)
			if answer == nil {
				return
			}
		}
		if len(answer) > dnsMaxMessage {
			return
		}
		out := make([]byte, 2+len(answer))
		binary.BigEndian.PutUint16(out, uint16(len(answer)))
		copy(out[2:], answer)
		conn.SetWriteDeadline(time.Now().Add(dnsQueryTimeout))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// Resolve passes one raw query through the system resolver and returns
// the raw answer.
func (p *DNSProxy) Resolve(query []byte, viaTCP bool) ([]byte, error) {
	if p.android && len(query) <= dnsProxydMaxQuery {
		answer, err := resnsend(p.proxyd, query)
		if err == nil {
			return answer, nil
		}
		fmt.Printf("dnsproxy: resnsend failed, using fallback: %v\n", err)
	}
	return p.fb.query(query, viaTCP)
}

// resnsend performs one query through the Android DnsResolver service:
// "resnsend <netId> <flags> <base64 query>\0", answered with a
// big-endian int32 rcode (or -errno), an int32 length and the raw DNS
// answer (see AOSP system/netd/client/NetdClient.cpp).
func resnsend(socketPath string, query []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	c, err := d.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dnsproxyd dial: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsQueryTimeout))
	// netId 0 = NETID_UNSET: the resolver picks the caller's network
	cmd := fmt.Sprintf("resnsend 0 0 %s\x00",
		base64.StdEncoding.EncodeToString(query))
	if _, err := c.Write([]byte(cmd)); err != nil {
		return nil, fmt.Errorf("dnsproxyd write: %w", err)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		uc.CloseWrite()
	}
	var result int32
	if err := binary.Read(c, binary.BigEndian, &result); err != nil {
		return nil, fmt.Errorf("dnsproxyd read rcode: %w", err)
	}
	if result < 0 {
		return nil, fmt.Errorf("dnsproxyd resolver errno %d", -result)
	}
	var size int32
	if err := binary.Read(c, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("dnsproxyd read length: %w", err)
	}
	if size < 0 || size > dnsMaxMessage {
		return nil, fmt.Errorf("dnsproxyd bad answer length %d", size)
	}
	if size == 0 {
		// rcode-only reply (e.g. timeout upstream); synthesize it
		if answer := synthesizeDNSError(query, int(result)); answer != nil {
			return answer, nil
		}
		return nil, fmt.Errorf("dnsproxyd empty answer, rcode %d", result)
	}
	answer := make([]byte, size)
	if _, err := io.ReadFull(c, answer); err != nil {
		return nil, fmt.Errorf("dnsproxyd read answer: %w", err)
	}
	return answer, nil
}

// synthesizeDNSError turns the query into a minimal response carrying
// only an rcode (QR+RA set, counts cleared, question echoed).
func synthesizeDNSError(query []byte, rcode int) []byte {
	if len(query) < 12 {
		return nil
	}
	answer := make([]byte, len(query))
	copy(answer, query)
	answer[2] |= 0x80                              // QR
	answer[3] = byte(rcode&0x0F) | 0x80            // RA + rcode
	answer[6], answer[7] = 0, 0                    // ANCOUNT
	answer[8], answer[9] = 0, 0                    // NSCOUNT
	answer[10], answer[11] = 0, 0                  // ARCOUNT
	return answer
}

// fallbackResolver forwards raw queries to the /etc/resolv.conf
// nameservers (non-Android hosts).
type fallbackResolver struct {
	mu       sync.Mutex
	path     string
	servers  []string
	loadedAt time.Time
}

func (r *fallbackResolver) upstreams() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.loadedAt) < 30*time.Second && len(r.servers) > 0 {
		return r.servers
	}
	r.servers = parseResolvConf(r.path)
	if len(r.servers) == 0 {
		r.servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	r.loadedAt = time.Now()
	return r.servers
}

func parseResolvConf(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr := fields[1]
		if ip := net.ParseIP(addr); ip == nil {
			continue
		} else if ip.To4() == nil {
			addr = "[" + addr + "]"
		}
		out = append(out, addr+":53")
	}
	return out
}

func (r *fallbackResolver) query(query []byte, viaTCP bool) ([]byte, error) {
	var lastErr error
	for _, server := range r.upstreams() {
		var answer []byte
		var err error
		if viaTCP {
			answer, err = forwardDNSTCP(server, query)
		} else {
			answer, err = forwardDNSUDP(server, query)
			// truncated answer: retry the same upstream over TCP
			if err == nil && len(answer) >= 4 && answer[2]&0x02 != 0 {
				if tcpAnswer, tcpErr := forwardDNSTCP(server, query); tcpErr == nil {
					answer = tcpAnswer
				}
			}
		}
		if err == nil {
			return answer, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all DNS upstreams failed: %w", lastErr)
}

func forwardDNSUDP(server string, query []byte) ([]byte, error) {
	c, err := net.DialTimeout("udp", server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsQueryTimeout))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func forwardDNSTCP(server string, query []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsQueryTimeout))
	out := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(out, uint16(len(query)))
	copy(out[2:], query)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	answer := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(c, answer); err != nil {
		return nil, err
	}
	return answer, nil
}
