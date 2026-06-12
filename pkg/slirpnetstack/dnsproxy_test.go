package slirpnetstack

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildQuery crafts a minimal DNS query for name (qtype in wire order).
func buildQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	b.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	binary.Write(&b, binary.BigEndian, qtype)
	binary.Write(&b, binary.BigEndian, uint16(1)) // IN
	return b.Bytes()
}

func TestDNSProxyMatches(t *testing.T) {
	p := NewDNSProxy([]net.IP{net.ParseIP("10.181.7.1"), net.ParseIP("fd00:7::1")})
	if !p.Matches(net.ParseIP("10.181.7.1"), 53) {
		t.Error("gateway v4 :53 should match")
	}
	if !p.Matches(net.ParseIP("fd00:7::1"), 53) {
		t.Error("gateway v6 :53 should match")
	}
	if p.Matches(net.ParseIP("10.181.7.1"), 54) {
		t.Error("port 54 must not match")
	}
	if p.Matches(net.ParseIP("10.181.7.2"), 53) {
		t.Error("non-gateway ip must not match")
	}
}

func TestSynthesizeDNSError(t *testing.T) {
	query := buildQuery(t, "example.com", 1)
	answer := synthesizeDNSError(query, 3 /* NXDOMAIN */)
	if answer == nil {
		t.Fatal("no answer synthesized")
	}
	if answer[0] != query[0] || answer[1] != query[1] {
		t.Error("transaction id not preserved")
	}
	if answer[2]&0x80 == 0 {
		t.Error("QR bit not set")
	}
	if answer[3]&0x0F != 3 {
		t.Errorf("rcode = %d, want 3", answer[3]&0x0F)
	}
	if answer[6] != 0 || answer[7] != 0 {
		t.Error("ANCOUNT not cleared")
	}
	if synthesizeDNSError([]byte{1, 2, 3}, 2) != nil {
		t.Error("short query must yield nil")
	}
}

func TestParseResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	os.WriteFile(path, []byte(
		"# comment\nnameserver 192.168.1.1\nnameserver fd00::1\nsearch lan\nnameserver bogus\n",
	), 0644)
	servers := parseResolvConf(path)
	want := []string{"192.168.1.1:53", "[fd00::1]:53"}
	if len(servers) != len(want) {
		t.Fatalf("servers = %v, want %v", servers, want)
	}
	for i := range want {
		if servers[i] != want[i] {
			t.Errorf("servers[%d] = %q, want %q", i, servers[i], want[i])
		}
	}
}

// fakeUpstream answers every UDP query with a canned response that echoes
// the transaction id and sets one answer record.
func fakeUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			answer := append([]byte{}, buf[:n]...)
			answer[2] |= 0x80 // QR
			conn.WriteToUDP(answer, peer)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

func TestFallbackResolverUDP(t *testing.T) {
	upstream, stop := fakeUpstream(t)
	defer stop()
	fb := &fallbackResolver{
		path:     "/nonexistent",
		servers:  []string{upstream},
		loadedAt: time.Now(),
	}
	query := buildQuery(t, "example.com", 33 /* SRV */)
	answer, err := fb.query(query, false)
	if err != nil {
		t.Fatal(err)
	}
	if answer[0] != query[0] || answer[1] != query[1] {
		t.Error("transaction id mismatch")
	}
	if answer[2]&0x80 == 0 {
		t.Error("QR bit not set in relayed answer")
	}
}

func TestResolveFallsBackWithoutProxyd(t *testing.T) {
	upstream, stop := fakeUpstream(t)
	defer stop()
	p := &DNSProxy{
		ips:     []net.IP{net.ParseIP("10.0.0.1")},
		android: false,
		fb: &fallbackResolver{
			path:     "/nonexistent",
			servers:  []string{upstream},
			loadedAt: time.Now(),
		},
	}
	query := buildQuery(t, "mc.example.com", 33 /* SRV */)
	answer, err := p.Resolve(query, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(answer) < 12 || answer[2]&0x80 == 0 {
		t.Error("bad relayed answer")
	}
}

// fakeDnsproxyd implements the resnsend wire protocol on a unix socket.
func fakeDnsproxyd(t *testing.T, rcode int32, answer []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsproxyd")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 2048)
				n, _ := c.Read(buf)
				cmd := strings.TrimRight(string(buf[:n]), "\x00")
				parts := strings.Fields(cmd)
				if len(parts) != 4 || parts[0] != "resnsend" {
					return
				}
				if _, err := base64.StdEncoding.DecodeString(parts[3]); err != nil {
					return
				}
				binary.Write(c, binary.BigEndian, rcode)
				binary.Write(c, binary.BigEndian, int32(len(answer)))
				c.Write(answer)
			}(c)
		}
	}()
	return path
}

func TestResnsend(t *testing.T) {
	canned := buildQuery(t, "example.com", 1)
	canned[2] |= 0x80
	path := fakeDnsproxyd(t, 0, canned)
	answer, err := resnsend(path, buildQuery(t, "example.com", 1))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(answer, canned) {
		t.Error("answer not relayed verbatim")
	}
}

func TestResnsendRcodeOnly(t *testing.T) {
	path := fakeDnsproxyd(t, 3 /* NXDOMAIN */, nil)
	query := buildQuery(t, "nx.example.com", 1)
	answer, err := resnsend(path, query)
	if err != nil {
		t.Fatal(err)
	}
	if answer[3]&0x0F != 3 {
		t.Errorf("rcode = %d, want 3", answer[3]&0x0F)
	}
}
