package slirpnetstack

import (
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func pingSocketsAvailable() bool {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

func echoProbe(seq uint16) *pingProbe {
	msg := make([]byte, header.ICMPv4MinimumSize+4)
	h := header.ICMPv4(msg)
	h.SetType(header.ICMPv4Echo)
	h.SetIdent(0x1234)
	h.SetSequence(seq)
	h.SetChecksum(^checksum.Checksum(msg, 0))
	return &pingProbe{
		guest:   tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
		dst:     tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
		ident:   0x1234,
		seq:     seq,
		icmpMsg: msg,
		ttl:     64,
		expires: time.Now().Add(pingTimeout),
	}
}

// TestPingFlowReuse sends two probes of one guest series and verifies they
// share a single host socket (one flow = one kernel ident = ECMP-stable
// path) and that loopback echo replies drain the probe map by sequence.
func TestPingFlowReuse(t *testing.T) {
	if !pingSocketsAvailable() {
		t.Skip("ping sockets unavailable (net.ipv4.ping_group_range)")
	}
	s := NewStack(212992, 212992)
	f := NewPingForwarder(s, 1, &State{}, tcpip.Address{}, tcpip.Address{})
	defer f.Close()

	f.forward(echoProbe(1))
	f.forward(echoProbe(2))

	f.mu.Lock()
	flows := len(f.flows)
	var fl *pingFlow
	for _, v := range f.flows {
		fl = v
	}
	f.mu.Unlock()
	if flows != 1 {
		t.Fatalf("flows = %d, want 1 (probe series must share one socket)", flows)
	}

	// loopback answers echo requests; replies must drain the probe map
	deadline := time.Now().Add(3 * time.Second)
	for {
		fl.mu.Lock()
		outstanding := len(fl.probes)
		fl.mu.Unlock()
		if outstanding == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("probes not drained: %d outstanding", outstanding)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPingFlowSeparateIdents verifies that different guest idents (different
// ping processes) get their own flows.
func TestPingFlowSeparateIdents(t *testing.T) {
	if !pingSocketsAvailable() {
		t.Skip("ping sockets unavailable (net.ipv4.ping_group_range)")
	}
	s := NewStack(212992, 212992)
	f := NewPingForwarder(s, 1, &State{}, tcpip.Address{}, tcpip.Address{})
	defer f.Close()

	a := echoProbe(1)
	b := echoProbe(1)
	b.ident = 0x5678
	f.forward(a)
	f.forward(b)

	f.mu.Lock()
	flows := len(f.flows)
	f.mu.Unlock()
	if flows != 2 {
		t.Fatalf("flows = %d, want 2 (distinct idents must not share a socket)", flows)
	}
}

func TestParseEchoSeq(t *testing.T) {
	p := echoProbe(0xBEEF)
	seq, ok := parseEchoSeq(p.icmpMsg)
	if !ok || seq != 0xBEEF {
		t.Fatalf("parseEchoSeq = %d,%v want 0xBEEF,true", seq, ok)
	}
	if _, ok := parseEchoSeq([]byte{1, 2, 3}); ok {
		t.Fatal("short message must not parse")
	}
}
