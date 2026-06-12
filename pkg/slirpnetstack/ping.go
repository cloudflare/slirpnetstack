package slirpnetstack

// Outbound ICMP echo ("ping") forwarding.
//
// Guest echo requests to non-gateway addresses are relayed to the real
// network through unprivileged SOCK_DGRAM ICMP sockets (Linux "ping
// sockets", gated by the net.ipv4.ping_group_range sysctl - it covers
// ICMPv6 too).
//
// One host socket is opened per flow (guest, destination, guest ident):
// the kernel assigns the on-wire ident per socket, so keeping a probe
// series on one socket keeps the ident (and the IPv6 flow label)
// constant, which is what ECMP routers hash on - a traceroute through
// the gateway then follows one stable path instead of jumping between
// equal-cost paths on every probe. The kernel still demuxes replies to
// the right socket; probes within a flow are told apart by their echo
// sequence number. Each send sets the socket TTL first (serialized per
// flow), so every probe still carries the guest's TTL, which is what
// makes traceroute work at all. IP_RECVERR/IPV6_RECVERR puts ICMP errors
// (TTL exceeded, destination unreachable) on the socket error queue, and
// we translate them back into ICMP errors towards the guest, embedding
// the guest's original headers like a real router would.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// pingMaxFlows caps the number of open host sockets, so a guest
	// flooding pings to many destinations can't exhaust host file
	// descriptors.
	pingMaxFlows = 128
	// pingMaxProbesPerFlow caps outstanding probes within one flow.
	pingMaxProbesPerFlow = 256
	// pingTimeout is how long a probe waits for an echo reply or an ICMP
	// error before being forgotten.
	pingTimeout = 10 * time.Second
	// pingFlowIdle is how long a flow socket lingers after its last
	// probe, keeping the on-wire ident stable across traceroute rounds.
	pingFlowIdle = 60 * time.Second
)

type PingForwarder struct {
	s        *stack.Stack
	nic      tcpip.NICID
	state    *State
	gw4, gw6 tcpip.Address
	mu       sync.Mutex
	flows    map[pingFlowKey]*pingFlow
	closed   bool
	warnOnce sync.Once
}

func NewPingForwarder(s *stack.Stack, nic tcpip.NICID, state *State, gw4, gw6 tcpip.Address) *PingForwarder {
	return &PingForwarder{
		s: s, nic: nic, state: state, gw4: gw4, gw6: gw6,
		flows: make(map[pingFlowKey]*pingFlow),
	}
}

// pingFlowKey identifies one guest ping series: everything that must map
// to one host socket so the on-wire flow stays ECMP-stable.
type pingFlowKey struct {
	v6         bool
	guest, dst tcpip.Address
	ident      uint16
}

// pingFlow is one host ICMP socket carrying a guest's probe series.
type pingFlow struct {
	f      *PingForwarder
	key    pingFlowKey
	fd     int
	mu     sync.Mutex
	closed bool
	probes map[uint16]*pingProbe // by echo sequence
	idle   time.Time             // when the flow became probe-less
}

// pingProbe is one guest echo request in flight on the host network.
type pingProbe struct {
	v6         bool
	guest, dst tcpip.Address // guest source / pinged destination
	ident, seq uint16
	ipHdr      []byte // guest's original IP header, embedded in ICMP errors
	icmpMsg    []byte // guest's original ICMP message (echo header + payload)
	ttl        uint8  // TTL for the host socket (already router-decremented)
	expires    time.Time
}

// icmpError describes an ICMP error towards the guest in terms of both IP
// versions; sendError picks the right pair for the probe.
type icmpError struct {
	type4 header.ICMPv4Type
	code4 header.ICMPv4Code
	type6 header.ICMPv6Type
	code6 header.ICMPv6Code
	mtu   uint32 // for ICMPv6 packet-too-big
}

var errTimeExceeded = icmpError{
	type4: header.ICMPv4TimeExceeded, code4: header.ICMPv4TTLExceeded,
	type6: header.ICMPv6TimeExceeded, code6: header.ICMPv6HopLimitExceeded,
}

var errAdminProhibited = icmpError{
	type4: header.ICMPv4DstUnreachable, code4: header.ICMPv4NetProhibited,
	type6: header.ICMPv6DstUnreachable, code6: header.ICMPv6Prohibited,
}

// HandlePacket relays a guest's ICMP echo request towards the real network.
// It is called for ICMP packets to non-gateway addresses and always returns
// true: the packet is forwarded or dropped, never left to netstack. pkt is
// only valid during the call, so everything a probe needs is copied out.
func (f *PingForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	th := pkt.TransportHeader().Slice()
	probe := pingProbe{guest: id.RemoteAddress, dst: id.LocalAddress}

	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		if len(th) < header.ICMPv4MinimumSize {
			return true
		}
		h := header.ICMPv4(th)
		if h.Type() != header.ICMPv4Echo || h.Code() != 0 {
			return true
		}
		probe.ident, probe.seq = h.Ident(), h.Sequence()
		probe.ttl = header.IPv4(pkt.NetworkHeader().Slice()).TTL()
	case header.IPv6ProtocolNumber:
		probe.v6 = true
		if len(th) < header.ICMPv6EchoMinimumSize {
			return true
		}
		h := header.ICMPv6(th)
		if h.Type() != header.ICMPv6EchoRequest || h.Code() != 0 {
			return true
		}
		probe.ident, probe.seq = h.Ident(), h.Sequence()
		probe.ttl = header.IPv6(pkt.NetworkHeader().Slice()).HopLimit()
	default:
		return true
	}

	if FirewallRoutingBlock(f.state, &net.UDPAddr{IP: net.IP(probe.dst.AsSlice())}) {
		return true
	}

	probe.ipHdr = append([]byte(nil), pkt.NetworkHeader().Slice()...)
	probe.icmpMsg = append(append([]byte(nil), th...), pkt.Data().AsRange().ToSlice()...)

	if probe.ttl <= 1 {
		// The gateway is the guest's first router: expire the packet here,
		// like a real router would. This is traceroute's first hop.
		go f.sendError(&probe, f.gwAddr(probe.v6), errTimeExceeded)
		return true
	}
	probe.ttl-- // we just routed it
	probe.expires = time.Now().Add(pingTimeout)

	go f.forward(&probe)
	return true
}

func (f *PingForwarder) gwAddr(v6 bool) tcpip.Address {
	if v6 {
		return f.gw6
	}
	return f.gw4
}

// Close tears down every flow socket; in-flight probes are dropped.
func (f *PingForwarder) Close() {
	f.mu.Lock()
	f.closed = true
	flows := make([]*pingFlow, 0, len(f.flows))
	for _, fl := range f.flows {
		flows = append(flows, fl)
	}
	f.flows = make(map[pingFlowKey]*pingFlow)
	f.mu.Unlock()
	for _, fl := range flows {
		fl.mu.Lock()
		if !fl.closed {
			fl.closed = true
			unix.Close(fl.fd)
		}
		fl.mu.Unlock()
	}
}

// forward sends one probe through its flow socket, creating the flow on
// first use.
func (f *PingForwarder) forward(p *pingProbe) {
	key := pingFlowKey{v6: p.v6, guest: p.guest, dst: p.dst, ident: p.ident}
	// A flow may close out from under us (idle reaper); retry once.
	for attempt := 0; attempt < 2; attempt++ {
		fl, err := f.getFlow(key, p)
		if fl == nil || err != nil {
			return
		}
		if fl.send(p) {
			return
		}
	}
}

func (f *PingForwarder) getFlow(key pingFlowKey, p *pingProbe) (*pingFlow, error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, nil
	}
	if fl, ok := f.flows[key]; ok {
		f.mu.Unlock()
		return fl, nil
	}
	if len(f.flows) >= pingMaxFlows {
		f.mu.Unlock()
		return nil, nil
	}
	fd, err := f.openSocket(p)
	if err != nil {
		f.mu.Unlock()
		var errno syscall.Errno
		switch {
		case errors.As(err, &errno) && f.isUnreach(errno):
			f.localError(p, errno)
		case errors.As(err, &errno) && (errno == unix.EACCES || errno == unix.EPERM):
			// Ping sockets are gated by the net.ipv4.ping_group_range
			// sysctl. Tell the guest this is policy, not a network failure.
			f.warnOnce.Do(func() {
				fmt.Fprintf(os.Stderr, "[!] ping: %s (is net.ipv4.ping_group_range set?)\n", err)
			})
			f.sendError(p, f.gwAddr(p.v6), errAdminProhibited)
		default:
			f.warnOnce.Do(func() {
				fmt.Fprintf(os.Stderr, "[!] ping: %s\n", err)
			})
		}
		return nil, err
	}
	fl := &pingFlow{
		f: f, key: key, fd: fd,
		probes: make(map[uint16]*pingProbe),
		idle:   time.Now(),
	}
	f.flows[key] = fl
	f.mu.Unlock()
	go fl.run()
	return fl, nil
}

// send transmits one probe with its own TTL. Returns false when the flow
// already closed (the caller re-resolves the flow).
func (fl *pingFlow) send(p *pingProbe) bool {
	fl.mu.Lock()
	if fl.closed {
		fl.mu.Unlock()
		return false
	}
	if len(fl.probes) >= pingMaxProbesPerFlow {
		fl.mu.Unlock()
		return true // drop, but don't recreate the flow
	}
	// The TTL is a socket option, applied at sendmsg time: set + write
	// under the flow lock so concurrent probes can't mix TTLs.
	var err error
	if !p.v6 {
		err = unix.SetsockoptInt(fl.fd, unix.IPPROTO_IP, unix.IP_TTL, int(p.ttl))
	} else {
		err = unix.SetsockoptInt(fl.fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, int(p.ttl))
	}
	if err == nil {
		_, err = unix.Write(fl.fd, p.icmpMsg)
	}
	if err != nil {
		fl.mu.Unlock()
		if errno, ok := err.(syscall.Errno); ok && fl.f.isUnreach(errno) {
			fl.f.localError(p, errno)
		}
		return true
	}
	fl.probes[p.seq] = p
	fl.mu.Unlock()
	return true
}

// run is the flow's reader loop: replies, the error queue, probe expiry
// and the idle reaper.
func (fl *pingFlow) run() {
	for {
		pfd := []unix.PollFd{{Fd: int32(fl.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, 1000)
		if err != nil && err != unix.EINTR {
			fl.close()
			return
		}
		if n > 0 {
			if pfd[0].Revents&unix.POLLERR != 0 {
				fl.handleErrQueue()
			}
			if pfd[0].Revents&unix.POLLIN != 0 {
				fl.handleReply()
			}
			if pfd[0].Revents&(unix.POLLHUP|unix.POLLNVAL) != 0 {
				fl.close()
				return
			}
		}
		if fl.reap() {
			return
		}
	}
}

// reap drops expired probes and closes the flow once it has been idle
// long enough. Returns true when the flow was closed.
func (fl *pingFlow) reap() bool {
	now := time.Now()
	fl.f.mu.Lock()
	fl.mu.Lock()
	for seq, p := range fl.probes {
		if now.After(p.expires) {
			delete(fl.probes, seq)
		}
	}
	if len(fl.probes) > 0 {
		fl.idle = now
	}
	done := fl.closed || now.Sub(fl.idle) > pingFlowIdle
	if done && !fl.closed {
		fl.closed = true
		delete(fl.f.flows, fl.key)
		unix.Close(fl.fd)
	}
	fl.mu.Unlock()
	fl.f.mu.Unlock()
	return done
}

func (fl *pingFlow) close() {
	fl.f.mu.Lock()
	fl.mu.Lock()
	if !fl.closed {
		fl.closed = true
		delete(fl.f.flows, fl.key)
		unix.Close(fl.fd)
	}
	fl.mu.Unlock()
	fl.f.mu.Unlock()
}

// take claims the outstanding probe for an echo sequence number, if any.
func (fl *pingFlow) take(seq uint16) *pingProbe {
	fl.mu.Lock()
	p := fl.probes[seq]
	if p != nil {
		delete(fl.probes, seq)
	}
	fl.mu.Unlock()
	return p
}

func (f *PingForwarder) isUnreach(errno syscall.Errno) bool {
	return errno == unix.ENETUNREACH || errno == unix.EHOSTUNREACH
}

// openSocket opens an unprivileged ICMP socket connected to the probe's
// destination, with error queueing enabled. The TTL is set per send.
func (f *PingForwarder) openSocket(p *pingProbe) (int, error) {
	domain, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if p.v6 {
		domain, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return -1, fmt.Errorf("socket(SOCK_DGRAM, ICMP): %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()

	if !p.v6 {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
			return -1, err
		}
		unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
		if src := f.state.srcIPs.srcIPv4; src != nil {
			var sa unix.SockaddrInet4
			copy(sa.Addr[:], src.To4())
			if err := unix.Bind(fd, &sa); err != nil {
				return -1, err
			}
		}
		var sa unix.SockaddrInet4
		copy(sa.Addr[:], p.dst.AsSlice())
		if err := unix.Connect(fd, &sa); err != nil {
			return -1, err
		}
	} else {
		if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1); err != nil {
			return -1, err
		}
		unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
		if src := f.state.srcIPs.srcIPv6; src != nil {
			var sa unix.SockaddrInet6
			copy(sa.Addr[:], src.To16())
			if err := unix.Bind(fd, &sa); err != nil {
				return -1, err
			}
		}
		var sa unix.SockaddrInet6
		copy(sa.Addr[:], p.dst.AsSlice())
		if err := unix.Connect(fd, &sa); err != nil {
			return -1, err
		}
	}
	ok = true
	return fd, nil
}

// handleReply reads an echo reply off the host socket and relays it to the
// guest whose probe matches its sequence number.
func (fl *pingFlow) handleReply() {
	buf := make([]byte, 65536)
	oob := make([]byte, 256)
	n, oobn, _, _, err := unix.Recvmsg(fl.fd, buf, oob, unix.MSG_DONTWAIT)
	if err != nil || n < header.ICMPv4MinimumSize {
		return
	}
	msg := buf[:n]

	var seq uint16
	if !fl.key.v6 {
		h := header.ICMPv4(msg)
		if h.Type() != header.ICMPv4EchoReply {
			return
		}
		seq = h.Sequence()
	} else {
		h := header.ICMPv6(msg)
		if h.Type() != header.ICMPv6EchoReply {
			return
		}
		seq = h.Sequence()
	}
	p := fl.take(seq)
	if p == nil {
		return
	}

	// Relay the reply's hop count if the kernel tells us, so the guest's
	// ping reports a meaningful ttl.
	hops := uint8(64)
	if cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
		for _, c := range cmsgs {
			v4ttl := !p.v6 && c.Header.Level == unix.IPPROTO_IP && c.Header.Type == unix.IP_TTL
			v6hops := p.v6 && c.Header.Level == unix.IPPROTO_IPV6 && c.Header.Type == unix.IPV6_HOPLIMIT
			if (v4ttl || v6hops) && len(c.Data) >= 4 {
				hops = uint8(binary.NativeEndian.Uint32(c.Data))
			}
		}
	}

	fl.f.injectEchoReply(p, msg[header.ICMPv4MinimumSize:], hops)
}

// handleErrQueue drains one message from the socket error queue and, when it
// carries a relayable ICMP error, forwards it to the guest. The error queue
// returns the original outgoing message, whose echo sequence number tells us
// which probe it answers.
func (fl *pingFlow) handleErrQueue() {
	buf := make([]byte, 2048)
	oob := make([]byte, 1024)
	n, oobn, _, _, err := unix.Recvmsg(fl.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return
	}
	p := fl.takeErrProbe(buf[:n])
	if p == nil {
		return
	}
	cmsgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return
	}
	f := fl.f
	for _, c := range cmsgs {
		v4err := c.Header.Level == unix.IPPROTO_IP && c.Header.Type == unix.IP_RECVERR
		v6err := c.Header.Level == unix.IPPROTO_IPV6 && c.Header.Type == unix.IPV6_RECVERR
		const sizeofSockExtendedErr = int(unsafe.Sizeof(unix.SockExtendedErr{}))
		if !v4err && !v6err || len(c.Data) < sizeofSockExtendedErr {
			continue
		}
		ee := (*unix.SockExtendedErr)(unsafe.Pointer(&c.Data[0]))
		src, srcOk := eeOffender(c.Data[sizeofSockExtendedErr:])
		if !srcOk {
			src = p.dst
		}

		switch ee.Origin {
		case unix.SO_EE_ORIGIN_ICMP:
			switch ee.Type {
			case uint8(header.ICMPv4TimeExceeded):
				f.sendError(p, src, errTimeExceeded)
			case uint8(header.ICMPv4DstUnreachable):
				f.sendError(p, src, icmpError{
					type4: header.ICMPv4DstUnreachable,
					code4: header.ICMPv4Code(ee.Code),
				})
			default:
				continue
			}
			return
		case unix.SO_EE_ORIGIN_ICMP6:
			switch header.ICMPv6Type(ee.Type) {
			case header.ICMPv6TimeExceeded:
				f.sendError(p, src, errTimeExceeded)
			case header.ICMPv6DstUnreachable:
				f.sendError(p, src, icmpError{
					type6: header.ICMPv6DstUnreachable,
					code6: header.ICMPv6Code(ee.Code),
				})
			case header.ICMPv6PacketTooBig:
				f.sendError(p, src, icmpError{
					type6: header.ICMPv6PacketTooBig,
					mtu:   ee.Info,
				})
			default:
				continue
			}
			return
		case unix.SO_EE_ORIGIN_LOCAL, unix.SO_EE_ORIGIN_NONE:
			f.localError(p, syscall.Errno(ee.Errno))
			return
		}
	}
}

// takeErrProbe matches an error-queue message back to its probe: the
// payload is the original echo message, so its sequence number (bytes 6-7
// of the ICMP header) identifies the probe. Falls back to a sole
// outstanding probe when the payload is too short to parse.
func (fl *pingFlow) takeErrProbe(orig []byte) *pingProbe {
	if seq, ok := parseEchoSeq(orig); ok {
		return fl.take(seq)
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if len(fl.probes) != 1 {
		return nil
	}
	for seq, p := range fl.probes {
		delete(fl.probes, seq)
		return p
	}
	return nil
}

// parseEchoSeq extracts the sequence number from an ICMP echo message
// (the v4 and v6 echo layouts agree: ident at bytes 4-5, sequence 6-7).
func parseEchoSeq(msg []byte) (uint16, bool) {
	if len(msg) < header.ICMPv4MinimumSize {
		return 0, false
	}
	return binary.BigEndian.Uint16(msg[6:8]), true
}

// eeOffender extracts the source of an ICMP error from the sockaddr that
// follows sock_extended_err (SO_EE_OFFENDER).
func eeOffender(data []byte) (tcpip.Address, bool) {
	if len(data) < unix.SizeofSockaddrInet4 {
		return tcpip.Address{}, false
	}
	switch binary.NativeEndian.Uint16(data) {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&data[0]))
		return tcpip.AddrFrom4(sa.Addr), true
	case unix.AF_INET6:
		if len(data) < unix.SizeofSockaddrInet6 {
			return tcpip.Address{}, false
		}
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&data[0]))
		return tcpip.AddrFrom16(sa.Addr), true
	}
	return tcpip.Address{}, false
}

// localError translates a host-local sendmsg/connect error (typically "no
// route to host") into a destination-unreachable from the gateway.
func (f *PingForwarder) localError(p *pingProbe, errno syscall.Errno) {
	e := icmpError{
		type4: header.ICMPv4DstUnreachable, code4: header.ICMPv4NetUnreachable,
		type6: header.ICMPv6DstUnreachable, code6: header.ICMPv6NetworkUnreachable,
	}
	if errno == unix.EHOSTUNREACH {
		e.code4 = header.ICMPv4HostUnreachable
	}
	f.sendError(p, f.gwAddr(p.v6), e)
}

// newGuestPacket makes a packet buffer with an 8-byte ICMP transport header
// pushed, routed from src to the probe's guest.
func (f *PingForwarder) newGuestPacket(p *pingProbe, src tcpip.Address, payload []byte) (*stack.Route, *stack.PacketBuffer, []byte) {
	netProto := header.IPv4ProtocolNumber
	if p.v6 {
		netProto = header.IPv6ProtocolNumber
	}
	r, err := f.s.FindRoute(f.nic, src, p.guest, netProto, false)
	if err != nil {
		return nil, nil, nil
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv4MinimumSize + int(r.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(payload),
	})
	hdr := pkt.TransportHeader().Push(header.ICMPv4MinimumSize)
	clear(hdr)
	if p.v6 {
		pkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	} else {
		pkt.TransportProtocolNumber = header.ICMPv4ProtocolNumber
	}
	return r, pkt, hdr
}

// injectEchoReply synthesizes an echo reply from the pinged host to the
// guest, with the guest's original ident restored.
func (f *PingForwarder) injectEchoReply(p *pingProbe, payload []byte, hops uint8) {
	r, pkt, hdr := f.newGuestPacket(p, p.dst, payload)
	if r == nil {
		return
	}
	defer r.Release()
	defer pkt.DecRef()

	if !p.v6 {
		h := header.ICMPv4(hdr)
		h.SetType(header.ICMPv4EchoReply)
		h.SetIdent(p.ident)
		h.SetSequence(p.seq)
		h.SetChecksum(^checksum.Checksum(h, checksum.Checksum(payload, 0)))
		r.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: hops}, pkt)
	} else {
		h := header.ICMPv6(hdr)
		h.SetType(header.ICMPv6EchoReply)
		h.SetIdent(p.ident)
		h.SetSequence(p.seq)
		h.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: h, Src: p.dst, Dst: p.guest,
			PayloadCsum: checksum.Checksum(payload, 0), PayloadLen: len(payload),
		}))
		r.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: hops}, pkt)
	}
}

// sendError synthesizes an ICMP error from src to the guest, embedding the
// guest's original IP header and ICMP message like a real router would.
func (f *PingForwarder) sendError(p *pingProbe, src tcpip.Address, e icmpError) {
	embedded := append(append([]byte(nil), p.ipHdr...), p.icmpMsg...)
	// RFC 1812 (v4): keep the error datagram within 576 bytes. RFC 4443
	// (v6): within the minimum MTU of 1280.
	max := 576 - header.IPv4MinimumSize - header.ICMPv4MinimumSize
	if p.v6 {
		max = header.IPv6MinimumMTU - header.IPv6MinimumSize - header.ICMPv6MinimumSize
	}
	if len(embedded) > max {
		embedded = embedded[:max]
	}

	r, pkt, hdr := f.newGuestPacket(p, src, embedded)
	if r == nil {
		return
	}
	defer r.Release()
	defer pkt.DecRef()

	if !p.v6 {
		h := header.ICMPv4(hdr)
		h.SetType(e.type4)
		h.SetCode(e.code4)
		h.SetChecksum(^checksum.Checksum(h, checksum.Checksum(embedded, 0)))
		r.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv4ProtocolNumber, TTL: 64}, pkt)
	} else {
		h := header.ICMPv6(hdr)
		h.SetType(e.type6)
		h.SetCode(e.code6)
		if e.type6 == header.ICMPv6PacketTooBig {
			h.SetTypeSpecific(e.mtu)
		}
		h.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header: h, Src: src, Dst: p.guest,
			PayloadCsum: checksum.Checksum(embedded, 0), PayloadLen: len(embedded),
		}))
		r.WritePacket(stack.NetworkHeaderParams{Protocol: header.ICMPv6ProtocolNumber, TTL: 64}, pkt)
	}
}
