package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/opencontainers/runc/libcontainer/system"
	"golang.org/x/sys/unix"

	"github.com/godbus/dbus/v5"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	fd             int
	netNsPath      string
	ifName         string
	mtu            uint
	remoteFwd      FwdAddrSlice
	localFwd       FwdAddrSlice
	logConnections bool
	quiet          bool
	metricAddr     AddrFlags
	gomaxprocs     int
	pcapPath       string
	exitWithParent bool
	dbusAddress    string
)

func init() {
	flag.IntVar(&fd, "fd", -1, "Unix datagram socket file descriptor")
	flag.StringVar(&netNsPath, "netns", "", "path to network namespace")
	flag.StringVar(&ifName, "interface", "tun0", "interface name within netns")
	flag.UintVar(&mtu, "mtu", 0, "MTU (default: 1500 for -fd, auto for -netns)")
	flag.Var(&remoteFwd, "R", "Connections to remote side forwarded local")
	flag.Var(&localFwd, "L", "Connections to local side forwarded remote")
	flag.BoolVar(&quiet, "quiet", false, "Print less stuff on screen")
	flag.Var(&metricAddr, "m", "Metrics addr")
	flag.IntVar(&gomaxprocs, "maxprocs", 0, "set GOMAXPROCS variable to limit cpu")
	flag.StringVar(&pcapPath, "pcap", "", "path to PCAP file")
	flag.BoolVar(&exitWithParent, "exit-with-parent", false, "Exit with parent process")
	flag.StringVar(&dbusAddress, "dbus-address", "", "DBus bus to connect to")
}

func main() {
	status := Main()
	os.Exit(status)
}

type State struct {
	stack        *stack.Stack
	RoutingDeny  []*net.IPNet
	RoutingAllow []*net.IPNet

	remoteUdpFwd map[string]*FwdAddr
	remoteTcpFwd map[string]*FwdAddr

	dbus   *dbus.Conn
	quitCh chan bool
}

func Main() int {
	var (
		state   State
		linkEP  stack.LinkEndpoint
		tapMode bool             = true
		mac     net.HardwareAddr = MustParseMAC("70:71:aa:4b:29:aa")
		metrics *Metrics
		err     error
	)

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGINT)
	signal.Notify(sigCh, syscall.SIGTERM)

	// flag.Parse might be called from tests first. To avoid
	// duplicated items in list, ensure parsing is done only once.
	if flag.Parsed() == false {
		flag.Parse()
	}

	if exitWithParent {
		system.ParentDeathSignal(unix.SIGTERM).Set()
	}

	if gomaxprocs > 0 {
		runtime.GOMAXPROCS(gomaxprocs)
	}

	logConnections = !quiet

	localFwd.SetDefaultAddrs(
		netParseIP("127.0.0.1"),
		netParseIP("10.0.2.100"))
	remoteFwd.SetDefaultAddrs(
		netParseIP("10.0.2.2"),
		netParseIP("127.0.0.1"))

	state.quitCh = make(chan bool)
	state.remoteUdpFwd = make(map[string]*FwdAddr)
	state.remoteTcpFwd = make(map[string]*FwdAddr)
	// For the list of reserved IP's see
	// https://idea.popcount.org/2019-12-06-addressing/ The idea
	// here is to forbid outbound connections to obviously wrong
	// or meaningless IP's.
	state.RoutingDeny = append(state.RoutingDeny,
		MustParseCIDR("0.0.0.0/8"),
		MustParseCIDR("10.0.2.0/24"),
		MustParseCIDR("127.0.0.0/8"),
		MustParseCIDR("255.255.255.255/32"),
		MustParseCIDR("::/128"),
		MustParseCIDR("::1/128"),
		MustParseCIDR("::/96"),
		MustParseCIDR("::ffff:0:0:0/96"),
		MustParseCIDR("64:ff9b::/96"),
	)

	state.RoutingAllow = append(state.RoutingAllow,
		MustParseCIDR("0.0.0.0/0"),
		MustParseCIDR("::/0"),
	)

	log.SetLevel(log.Warning)
	rand.Seed(time.Now().UnixNano())

	if metricAddr.Addr != nil && metricAddr.Network() != "" {
		metrics, err = StartMetrics(metricAddr.Addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to start metrics: %s\n", err)
			return -2
		}
	}

	if fd == -1 {
		fd, tapMode, mtu, err = GetTunTap(netNsPath, ifName)
		if err != nil {
			panic(fmt.Sprintf("Failed to open TUN/TAP: %s", err))
		}
	} else {
		if netNsPath != "" {
			panic("Please specify either -fd or -netns")
		}
		if mtu == 0 {
			mtu = 1500
		}
	}

	// With high mtu, low packet loss and low latency over tuntap,
	// the specific value isn't that important. The only important
	// bit is that it should be at least a couple times MSS.
	bufSize := 4 * 1024 * 1024

	s := NewStack(bufSize, bufSize)
	state.stack = s

	if linkEP, err = createLinkEP(s, fd, tapMode, mac, uint32(mtu)); err != nil {
		panic(fmt.Sprintf("Failed to create linkEP: %s", err))
	}

	if pcapPath != "" {
		pcapFile, err := os.OpenFile(pcapPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(fmt.Sprintf("Failed to open PCAP file: %s", err))
		}
		if linkEP, err = sniffer.NewWithFile(linkEP, pcapFile, uint32(mtu)); err != nil {
			panic(fmt.Sprintf("Failed to sniff linkEP: %s", err))
		}
		defer pcapFile.Close()
	}

	if err = createNIC(s, 1, linkEP); err != nil {
		panic(fmt.Sprintf("Failed to createNIC: %s", err))

	}

	StackRoutingSetup(s, 1, "10.0.2.2/24")
	StackPrimeArp(s, 1, netParseIP("10.0.2.100"))

	StackRoutingSetup(s, 1, "2001:2::2/32")

	if err = setupDBus(&state, dbusAddress); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to setup DBus: %s\n", err)
		return 1
	}

	for _, lf := range localFwd {
		var srv Listener
		switch lf.network {
		case "tcp":
			srv, err = LocalForwardTCP(&state, s, &lf)
		case "udp":
			srv, err = LocalForwardUDP(&state, s, &lf)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to listen on %s://%s:%d: %s\n",
				lf.network, lf.bind.Addr, lf.bind.Port, err)
		} else {
			ppPrefix := ""
			if lf.proxyProtocol {
				ppPrefix = "PP "
			}
			laddr := srv.Addr()
			fmt.Printf("[+] local-fwd Local %slisten %s://%s\n",
				ppPrefix,
				laddr.Network(),
				laddr.String())
		}
	}

	for i, rf := range remoteFwd {
		fmt.Printf("[+] Accepting on remote side %s://%s:%d\n",
			rf.network, rf.bind.Addr.String(), rf.bind.Port)
		switch rf.network {
		case "tcp":
			state.remoteTcpFwd[rf.BindAddr().String()] = &remoteFwd[i]
		case "udp":
			state.remoteUdpFwd[rf.BindAddr().String()] = &remoteFwd[i]
		}
	}

	tcpHandler := TcpRoutingHandler(&state)
	// Set sliding window auto-tuned value. Allow 10 concurrent
	// new connection attempts.
	fwdTcp := tcp.NewForwarder(s, 0, 10, tcpHandler)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwdTcp.HandlePacket)

	udpHandler := UdpRoutingHandler(s, &state)
	fwdUdp := udp.NewForwarder(s, udpHandler)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwdUdp.HandlePacket)

	// [****] Finally, the mighty event loop, waiting on signals
	pid := syscall.Getpid()
	fmt.Fprintf(os.Stderr, "[+] #%d Started\n", pid)
	syscall.Kill(syscall.Getppid(), syscall.SIGWINCH)

	for {
		select {
		case <-state.quitCh:
			goto stop
		case sig := <-sigCh:
			signal.Reset(sig)
			goto stop
		}
	}
stop:
	fmt.Fprintf(os.Stderr, "[-] Closing\n")
	// TODO: define semantics of graceful close on signal
	//s.Wait()
	if metrics != nil {
		metrics.Close()
	}
	return 0
}
