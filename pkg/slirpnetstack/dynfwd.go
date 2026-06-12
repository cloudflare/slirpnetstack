package slirpnetstack

import (
	"fmt"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func SetLogConnections(v bool) {
	logConnections = v
}

// GatewayStateOpts configures a gateway State for library callers that
// wire up the stack themselves (as opposed to the CLI's Main function).
type GatewayStateOpts struct {
	NatRange4             string
	NatRange6             string
	EnableHostRouting     bool
	EnableInternetRouting bool
	AllowRange            IPPortRangeSlice
	DenyRange             IPPortRangeSlice
	SourceIPv4            net.IP
	SourceIPv6            net.IP
}

var (
	sharedLocalRoutes     LocalRoutes
	sharedLocalRoutesOnce sync.Once
)

// NewGatewayState builds a State equivalent to what Main() assembles from
// flags, but suitable for library use: the host routing table poller is
// shared across calls, and the static remote-forward maps are left nil
// (use DynFwdTable instead).
func NewGatewayState(o GatewayStateOpts) *State {
	sharedLocalRoutesOnce.Do(func() {
		sharedLocalRoutes.Start(30 * time.Second)
	})

	state := &State{}
	state.localRoutes = &sharedLocalRoutes
	state.enableHostRouting = o.EnableHostRouting
	state.enableInternetRouting = o.EnableInternetRouting
	state.allowRange = o.AllowRange
	state.denyRange = o.DenyRange
	state.srcIPs.srcIPv4 = o.SourceIPv4
	state.srcIPs.srcIPv6 = o.SourceIPv6

	state.StaticRoutingDeny = append(state.StaticRoutingDeny,
		MustParseCIDR("0.0.0.0/8"),
		MustParseCIDR("127.0.0.0/8"),
		MustParseCIDR("255.255.255.255/32"),
		MustParseCIDR("::/128"),
		MustParseCIDR("::1/128"),
		MustParseCIDR("::/96"),
		MustParseCIDR("::ffff:0:0:0/96"),
		MustParseCIDR("64:ff9b::/96"),
	)
	if o.NatRange4 != "" {
		state.StaticRoutingDeny = append(state.StaticRoutingDeny, MustParseCIDR(o.NatRange4))
	}
	if o.NatRange6 != "" {
		state.StaticRoutingDeny = append(state.StaticRoutingDeny, MustParseCIDR(o.NatRange6))
	}
	return state
}

// DynFwdTable holds remote-forward rules safe for concurrent add/remove,
// replacing the static maps in State for library callers that need runtime
// rule changes (e.g. a REST API).
type DynFwdTable struct {
	mu  sync.RWMutex
	tcp map[string]*FwdAddr
	udp map[string]*FwdAddr
}

func NewDynFwdTable() *DynFwdTable {
	return &DynFwdTable{
		tcp: make(map[string]*FwdAddr),
		udp: make(map[string]*FwdAddr),
	}
}

func (t *DynFwdTable) byNetwork(network string) (map[string]*FwdAddr, error) {
	switch network {
	case "tcp":
		return t.tcp, nil
	case "udp":
		return t.udp, nil
	}
	return nil, fmt.Errorf("unknown network type %q", network)
}

func (t *DynFwdTable) Add(f *FwdAddr) (string, error) {
	bindAddr, err := f.BindAddr()
	if err != nil {
		return "", err
	}
	key := bindAddr.String()

	t.mu.Lock()
	defer t.mu.Unlock()
	m, err := t.byNetwork(f.network)
	if err != nil {
		return "", err
	}
	if _, busy := m[key]; busy {
		return "", fmt.Errorf("forward %s://%s already exists", f.network, key)
	}
	m[key] = f
	return key, nil
}

func (t *DynFwdTable) Remove(network, key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, err := t.byNetwork(network)
	if err != nil {
		return false
	}
	if _, ok := m[key]; !ok {
		return false
	}
	delete(m, key)
	return true
}

func (t *DynFwdTable) Lookup(network, key string) *FwdAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m, err := t.byNetwork(network)
	if err != nil {
		return nil
	}
	return m[key]
}

func (t *DynFwdTable) List() map[string]map[string]*FwdAddr {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := map[string]map[string]*FwdAddr{"tcp": {}, "udp": {}}
	for k, v := range t.tcp {
		out["tcp"][k] = v
	}
	for k, v := range t.udp {
		out["udp"][k] = v
	}
	return out
}

// DynUdpRoutingHandler is like UdpRoutingHandler but looks up remote-forward
// rules from a DynFwdTable instead of the static State maps. An optional
// DNSProxy serves the gateway's own :53; explicit forward rules take
// precedence.
func DynUdpRoutingHandler(s *stack.Stack, state *State, t *DynFwdTable, dns *DNSProxy) func(*udp.ForwarderRequest) bool {
	return func(r *udp.ForwarderRequest) bool {
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", err)
			return true
		}

		id := r.ID()
		loc := &net.UDPAddr{
			IP:   NetParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf := t.Lookup("udp", loc.String())
		if rf == nil && dns != nil && dns.Matches(loc.IP, loc.Port) {
			go dns.ServeUDP(gonet.NewUDPConn(&wq, ep))
			return true
		}
		if rf == nil {
			if block := FirewallRoutingBlock(state, loc); block {
				ep.Close()
				return true
			}
		}

		xconn := gonet.NewUDPConn(&wq, ep)
		conn := &KaUDPConn{Conn: xconn}

		if rf != nil && rf.kaEnable && rf.kaInterval == 0 {
			conn.closeOnWrite = true
		}

		go func() {
			if rf != nil {
				RemoteForward(conn, &state.srcIPs, rf)
			} else {
				RoutingForward(conn, &state.srcIPs, loc)
			}
		}()
		return true
	}
}

// DynTcpRoutingHandler is like TcpRoutingHandler but looks up remote-forward
// rules from a DynFwdTable instead of the static State maps. An optional
// DNSProxy serves the gateway's own :53; explicit forward rules take
// precedence.
func DynTcpRoutingHandler(state *State, t *DynFwdTable, dns *DNSProxy) func(*tcp.ForwarderRequest) {
	return func(r *tcp.ForwarderRequest) {
		id := r.ID()
		loc := &net.TCPAddr{
			IP:   NetParseIP(id.LocalAddress.String()),
			Port: int(id.LocalPort),
		}

		rf := t.Lookup("tcp", loc.String())
		serveDNS := rf == nil && dns != nil && dns.Matches(loc.IP, loc.Port)
		if rf == nil && !serveDNS {
			if block := FirewallRoutingBlock(state, loc); block {
				r.Complete(true)
				return
			}
		}

		var wq waiter.Queue
		ep, errx := r.CreateEndpoint(&wq)
		if errx != nil {
			fmt.Printf("r.CreateEndpoint() = %v\n", errx)
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetDelayOption(true)

		xconn := gonet.NewTCPConn(&wq, ep)
		conn := &GonetTCPConn{xconn, ep}

		if serveDNS {
			go dns.ServeTCP(conn)
			return
		}

		go func() {
			if rf != nil {
				RemoteForward(conn, &state.srcIPs, rf)
			} else {
				RoutingForward(conn, &state.srcIPs, loc)
			}
		}()
	}
}

// NewFwdAddr builds a forward rule programmatically (as opposed to flag
// parsing). network is "tcp" or "udp".
func NewFwdAddr(network, bindHost, bindPort, hostHost, hostPort string) (*FwdAddr, error) {
	switch network {
	case "tcp", "udp":
	default:
		return nil, fmt.Errorf("unknown network type %q", network)
	}
	bind, err := ParseDefAddress(bindHost, bindPort)
	if err != nil {
		return nil, fmt.Errorf("bad bind address: %w", err)
	}
	host, err := ParseDefAddress(hostHost, hostPort)
	if err != nil {
		return nil, fmt.Errorf("bad host address: %w", err)
	}
	return &FwdAddr{network: network, bind: *bind, host: *host}, nil
}

func (f *FwdAddr) Network() string  { return f.network }
func (f *FwdAddr) BindString() string { return f.bind.String() }
func (f *FwdAddr) HostString() string { return f.host.String() }

func DynLocalForwardTCP(state *State, s *stack.Stack, rf *FwdAddr) (Listener, error) {
	return LocalForwardTCP(state, s, *rf, nil)
}

func DynLocalForwardUDP(state *State, s *stack.Stack, rf *FwdAddr) (Listener, error) {
	return LocalForwardUDP(state, s, *rf, nil)
}
