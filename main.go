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

	"github.com/cloudflare/slirpnetstack/ext"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	cmdVersion            bool
	fd                    int
	netNsPath             string
	ifName                string
	mtu                   uint
	remoteFwd             FwdAddrSlice
	localFwd              FwdAddrSlice
	logConnections        bool
	quiet                 bool
	metricAddr            AddrFlags
	gomaxprocs            int
	pcapPath              string
	exitWithParent        bool
	enableHostRouting     bool
	enableInternetRouting bool
	sourceIPv4            IPFlag
	sourceIPv6            IPFlag
	allowRange            IPPortRangeSlice
	denyRange             IPPortRangeSlice
	dnsTTL                time.Duration
)

func initFlagSet(flag *flag.FlagSet) {
	flag.BoolVar(&cmdVersion, "version", false, "Print slirpnetstack version and exit")
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
	flag.BoolVar(&enableHostRouting, "enable-host", false, "Allow guest to connecting to IP's that are in the host main and local routing tables")
	flag.BoolVar(&enableInternetRouting, "enable-routing", false, "Allow guest connecting to non-local IP's that are likley to be routed to the internet")
	flag.Var(&sourceIPv4, "source-ipv4", "When connecting, use the selected Source IP for ipv4")
	flag.Var(&sourceIPv6, "source-ipv6", "When connecting, use the selected Source IP for ipv6")
	flag.Var(&allowRange, "allow", "When routing, allow specified IP prefix and port range")
	flag.Var(&denyRange, "deny", "When routing, deny specified IP prefix and port range")
	flag.DurationVar(&dnsTTL, "dns-ttl", time.Duration(5*time.Second), "For how long to cache DNS in case of dns labels passed to forward target.")
}

func main() {
	status := Main(os.Args[0], os.Args[1:])
	os.Exit(status)
}

type SrcIPs struct {
	srcIPv4 net.IP
	srcIPv6 net.IP
}

type State struct {
	StaticRoutingDeny []*net.IPNet

	remoteUdpFwd map[string]*FwdAddr
	remoteTcpFwd map[string]*FwdAddr

	// disable host routes
	localRoutes           *LocalRoutes
	enableHostRouting     bool
	enableInternetRouting bool
	allowRange            IPPortRangeSlice
	denyRange             IPPortRangeSlice

	srcIPs SrcIPs
}

func Main(programName string, args []string) int {
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

	for i := uint64(1024 * 1024); i > 0; i /= 2 {
		rLimit := syscall.Rlimit{Max: i, Cur: i}
		err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		if err == nil {
			break
		}
	}

	// Welcome to the golang flag parsing mess! We need to set our
	// own flagset and not use the defaults because of how we
	// handle the test coverage. You see, when running in coverage
	// mode, golang cover test execs "flag.Parse()" by
	// itself. This means we could do second flag.Parse here,
	// leading to doubly-parsing of flags. On top of that imagine
	// an error - our custom structures that have .Set and .String
	// methods will be called by flag.Parse called from test main,
	// and on error Exit(2) which will _not_ be counted against
	// code coverage, because it exis before code coverage machine
	// even starts. The point is - we need to custom parse flags
	// ourselves and we need to make sure that we don't use the
	// global flag.Parse machinery when running from coverage
	// tests.
	{
		flagSet := flag.NewFlagSet(programName, flag.ContinueOnError)
		initFlagSet(flagSet)
		err := flagSet.Parse(args)
		if err != nil {
			return 2
		}
	}

	if cmdVersion {
		fmt.Printf("slirpnetstack version %s\n", ext.Version)
		fmt.Printf("build time %s\n", ext.BuildTime)
		return 0
	}

	if gomaxprocs > 0 {
		runtime.GOMAXPROCS(gomaxprocs)
	}

	state.localRoutes = &LocalRoutes{}
	state.localRoutes.Start(30 * time.Second)

	state.enableHostRouting = enableHostRouting
	state.enableInternetRouting = enableInternetRouting
	state.srcIPs.srcIPv4 = sourceIPv4.ip
	state.srcIPs.srcIPv6 = sourceIPv6.ip
	state.allowRange = allowRange
	state.denyRange = denyRange

	logConnections = !quiet

	localFwd.SetDefaultAddrs(
		netParseIP("127.0.0.1"),
		netParseIP("::1"),
		netParseIP("10.0.2.100"),
		netParseIP("fd00::100"))
	remoteFwd.SetDefaultAddrs(
		netParseIP("10.0.2.2"),
		netParseIP("fd00::2"),
		netParseIP("127.0.0.1"),
		netParseIP("::1"))

	state.remoteUdpFwd = make(map[string]*FwdAddr)
	state.remoteTcpFwd = make(map[string]*FwdAddr)
	// For the list of reserved IP's see
	// https://idea.popcount.org/2019-12-06-addressing/ The idea
	// here is to forbid outbound connections to obviously wrong
	// or meaningless IP's.
	state.StaticRoutingDeny = append(state.StaticRoutingDeny,
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
			fmt.Fprintf(os.Stderr, "Failed to open TUN/TAP: %s\n", err)
			return -3
		}
	} else {
		if netNsPath != "" {
			fmt.Fprintf(os.Stderr, "Please specify either -fd or -netns\n")
			return -4
		}
		if mtu == 0 {
			mtu = 1500
		}
	}

	// This must be done after all the namespace dance, otherwise
	// it doesn't work. I think it has to do with lack of
	// PR_SET_PDEATHSIG inheritance on fork(), or maybe it is
	// cleared on namespace join? Dunno. Remember SIGTERM is
	// supposed to be gracefully handled.
	if exitWithParent {
		system.ParentDeathSignal(unix.SIGTERM).Set()
	}

	// With high mtu, low packet loss and low latency over tuntap,
	// the specific value isn't that important. The only important
	// bit is that it should be at least a couple times MSS.
	bufSize := 4 * 1024 * 1024

	s := NewStack(bufSize, bufSize)

	tcpHandler := TcpRoutingHandler(&state)
	// Set sliding window auto-tuned value. Allow 10 concurrent
	// new connection attempts.
	fwdTcp := tcp.NewForwarder(s, 0, 10, tcpHandler)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwdTcp.HandlePacket)

	udpHandler := UdpRoutingHandler(s, &state)
	fwdUdp := udp.NewForwarder(s, udpHandler)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, fwdUdp.HandlePacket)

	doneChannel := make(chan bool)

	for _, lf := range localFwd {
		var srv Listener
		switch lf.network {
		case "tcp":
			srv, err = LocalForwardTCP(&state, s, lf, doneChannel)
		case "udp":
			srv, err = LocalForwardUDP(&state, s, lf, doneChannel)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to listen on %s://%s: %s\n",
				lf.network, lf.bind.String(), err)
			return -9
		} else {
			ppPrefix := ""
			if lf.proxyProtocol {
				ppPrefix = "PP "
			}
			laddr := srv.Addr()

			if !quiet {
				fmt.Printf("[+] local-fwd Local %slisten %s://%s\n",
					ppPrefix,
					laddr.Network(),
					laddr.String())
			}
		}
	}

	for i, rf := range remoteFwd {
		bindAddr, err := rf.BindAddr()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to resolve bind address. %v\n", err)
			return -10
		}
		if !quiet {
			fmt.Printf("[+] Accepting on remote side %s://%s\n",
				rf.network, rf.bind.String())
		}
		switch rf.network {
		case "tcp":
			state.remoteTcpFwd[bindAddr.String()] = &remoteFwd[i]
		case "udp":
			state.remoteUdpFwd[bindAddr.String()] = &remoteFwd[i]
		}
	}

	if linkEP, err = createLinkEP(s, fd, tapMode, mac, uint32(mtu)); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to create linkEP: %s\n", err)
		return -5
	}

	if pcapPath != "" {
		pcapFile, err := os.OpenFile(pcapPath, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to open PCAP file: %s\n", err)
			return -6
		}
		if linkEP, err = sniffer.NewWithWriter(linkEP, pcapFile, uint32(mtu)); err != nil {
			fmt.Fprintf(os.Stderr, "[!]Failed to sniff linkEP: %s\n", err)
			return -7
		}
		defer pcapFile.Close()
	}

	if err = createNIC(s, 1, linkEP); err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to createNIC: %s\n", err)
		return -8

	}

	StackRoutingSetup(s, 1, "10.0.2.2/24")
	StackPrimeArp(s, 1, netParseIP("10.0.2.100"))

	StackRoutingSetup(s, 1, "fd00::2/64")

	// [****] Finally, the mighty event loop, waiting on signals
	pid := syscall.Getpid()
	fmt.Fprintf(os.Stderr, "[+] #%d Slirpnetstack started\n", pid)
	syscall.Kill(syscall.Getppid(), syscall.SIGWINCH)

	for {
		select {
		case sig := <-sigCh:
			signal.Reset(sig)
			fmt.Fprintf(os.Stderr, "[-] #%d Slirpnetstack closing\n", pid)
			goto stop
		}
	}
stop:
	// TODO: define semantics of graceful close on signal
	//s.Wait()
	if metrics != nil {
		metrics.Close()
	}
	if state.localRoutes != nil {
		state.localRoutes.Stop()
	}
	return 0
}
