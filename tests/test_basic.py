from . import base
from . import utils
import os
import socket
import struct
import unittest
import urllib.request


class BasicTest(base.TestCase):
    def test_help(self):
        ''' Basic test if -h prints stuff looking like help screen. '''
        p = self.prun("-h", netns=False)
        o = p.stdout_line()
        self.assertFalse(o)
        e = p.stderr_line()
        self.assertIn("Usage of ", e)

    def test_basic_ping(self):
        ''' Due to how netstack is configured, we will answer to ping against
        any IP. Let's test it!.
        '''
        p = self.prun()
        self.assertStartSync(p)
        with self.guest_netns():
            r = os.system("ping -q 10.0.2.11 -c 1 -n > /dev/null")
            self.assertEqual(r, 0)
            r = os.system("ping -q 1.1.1.1 -c 1 -n > /dev/null")
            self.assertEqual(r, 0)

    def test_pcap(self):
        ''' Check -pcap capture '''
        pcap = self.get_tmp_filename("test.pcap")
        p = self.prun("-pcap %s" % pcap)
        self.assertStartSync(p)
        with self.guest_netns():
            r = os.system("ping -q 1.1.1.1 -c 1 -n > /dev/null")
            self.assertEqual(r, 0)
        caught_sizes = set()
        with open(pcap, 'rb') as f:
            data = f.read(24)
            header = struct.unpack(">LHHLLLL", data)
            self.assertEqual(header[0], 0xa1b2c3d4)
            data = f.read(16)
            (seconds, useconds, captured_length, packet_length) = struct.unpack(">LLLL", data)
            # we generally expect icmp echo request at 28 bytes, but
            # sometimes see some other packet at 76 bytes (arp?)
            caught_sizes.add( captured_length )
        self.assertIn(28, caught_sizes)

    def test_fd(self):
        ''' Check inherinting tuntap fd with -fd option '''
        sp = socket.socketpair(type=socket.SOCK_DGRAM)
        os.set_inheritable(sp[0].fileno(), True)
        p = self.prun("-fd %d" % sp[0].fileno(), close_fds=False, netns=False)
        self.assertStartSync(p, fd=True)
        # 10.0.2.15->10.0.2.2 ICMP Echo (ping) request
        ping = bytes.fromhex('''
        52 55 0a 00 02 02 70 71 aa 4b 29 aa 08 00 45 00
        00 54 00 00 40 00 40 01 22 99 0a 00 02 0f 0a 00
        02 02 08 00 4f 4d 73 1e 00 01 8e 3a 3b 5e 00 00
        00 00 a7 27 06 00 00 00 00 00 10 11 12 13 14 15
        16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
        26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
        36 37'''.replace('\n','').replace(' ', ''))
        sp[1].sendall(ping)
        while True:
            pong = sp[1].recv(1024)
            if pong[14+9] == 1 and pong[14+20] == 0: #ICMP and echo reply
                break
        sp[0].close()
        sp[1].close()

    def test_basic_connection(self):
        ''' Test connection reset on netstack IP. Netstack is not supposed to
        forward nor route this. '''
        p = self.prun()
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpRefusedError(port=80, ip='10.0.2.2')

    def test_local_fwd_error_tcp(self):
        ''' Test bind errors on local TCP forwarding.'''
        port = base.find_free_port()
        p = self.prun("-L %s -L %s" % (port, port))
        self.assertIn("[.] Join", p.stderr_line())
        self.assertIn("[.] Opening tun", p.stderr_line())
        xport = self.assertListenLine(p, "local-fwd Local listen tcp://127.0.0.1")
        self.assertEqual(port, xport)
        # [!] Failed to listen on tcp://127.0.0.1:45295
        self.assertIn("Failed to listen on tcp://127.0.0.1", p.stderr_line())

    def test_local_fwd_error_udp(self):
        ''' Test bind errors on local UDP forwarding.'''
        port = base.find_free_port()
        p = self.prun("-L udp://%s -L udp://%s" % (port, port))
        self.assertIn("[.] Join", p.stderr_line())
        self.assertIn("[.] Opening tun", p.stderr_line())
        xport = self.assertListenLine(p, "local-fwd Local listen udp://127.0.0.1")
        self.assertEqual(port, xport)
        # [!] Failed to listen on udp://127.0.0.1:45295
        self.assertIn("Failed to listen on udp://127.0.0.1", p.stderr_line())
        p.close()
        self.assertEqual(p.rc, 255, "exit code should be 255")

    def test_basic_ping6(self):
        '''Due to how netstack is configured, we will answer to ping against
        any IP. Let's test it!.'''
        p = self.prun()
        self.assertStartSync(p)
        with self.guest_netns():
            # ping local address. sanity. This is kinda tricky. First,
            # tuntap must be enabled (ie: someone must pick up the
            # fd). Then the ip needs to have 'nodad' toggle, to
            # prevent it from stalling on duplicate address detection.
            r = os.system("ping6 -q 2001:2::2 -c 1 -n > /dev/null")
            self.assertEqual(r, 0)
            r = os.system("ping6 -q 2001:2::100 -c 1 -n > /dev/null")
            self.assertEqual(r, 0)
            # 1.1.1.1 resolver. Doesn't matter - will be terminated by netstack
            r = os.system("ping6 -q 2606:4700:4700::1111 -c 1 -n > /dev/null")
            self.assertEqual(r, 0)

    def test_metric(self):
        ''' Test if metrics server run. '''
        p = self.prun("-m tcp://127.0.0.1:0")
        e = p.stderr_line()
        self.assertIn("Running metrics ", e)
        metrics_port = int(e.rsplit(':')[-1].rstrip())
        f = urllib.request.urlopen('http://127.0.0.1:%d/debug/pprof' % (metrics_port,))
        self.assertIn(b"Types of profiles available:", f.read(300))


class RoutingTest(base.TestCase):
    @base.isolateHostNetwork()
    def test_tcp_routing(self):
        ''' Test tcp routing. Establish connection from guest onto an IP
        assigned to local-scoped IP on host. '''
        echo_port = self.start_tcp_echo()
        p = self.prun("")
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(ip="192.168.1.100", port=echo_port)
            self.assertIn("Routing conn new", p.stdout_line())
            # TODO: l=[EOF]/0 r=EOF/0 or  l=EOF/0 r=[EOF]/0 ?
            self.assertIn("Routing conn done: l=", p.stdout_line())
            self.assertTcpEcho(ip="192.168.1.100", port=echo_port)

    @base.isolateHostNetwork()
    def test_tcp_routing_v6(self):
        ''' Test tcp routing. Establish connection from guest onto an IP
        assigned to local-scoped IP on host. '''
        echo_port = self.start_tcp_echo()
        p = self.prun("")
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(ip="3ffe::100", port=echo_port)
            self.assertIn("Routing conn new", p.stdout_line())
            # TODO: l=[EOF]/0 r=EOF/0 or  l=EOF/0 r=[EOF]/0 ?
            self.assertIn("Routing conn done: l=", p.stdout_line())
            self.assertTcpEcho(ip="3ffe::100", port=echo_port)

    @base.isolateHostNetwork()
    def test_tcp_routing_multi(self):
        ''' Test tcp routing. Can we establish like 200 connnections? '''
        echo_port = self.start_tcp_echo()
        p = self.prun("")
        self.assertStartSync(p)
        c = 0
        with self.guest_netns():
            for i in range(200):
                self.assertTcpEcho(ip="192.168.1.100", port=echo_port)
            for i in range(400):
                l = p.stdout_line()
                if "Routing conn new" in l:
                    c += 1
                elif "Routing conn done" in l:
                    c -= 1
        self.assertEqual(c, 0)

    @base.isolateHostNetwork()
    def test_udp_routing(self):
        ''' Test udp routing. Send packet from guest onto an IP assigned
        to local-scoped IP on host. '''
        echo_port = self.start_udp_echo()
        self.assertUdpEcho(port=echo_port, ip="192.168.1.100")

        p = self.prun("")
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertUdpEcho(port=echo_port, ip="192.168.1.100")
            self.assertIn("Routing conn new", p.stdout_line())
            # Can't test conn done message.
            self.assertUdpEcho(port=echo_port, ip="192.168.1.100")

    @base.isolateHostNetwork()
    def test_udp_routing_merge(self):
        '''Test udp routing. There is a bug where two packets get merged into
        one if rapidly sent. This is breaking DNS. '''
        echo_port = self.start_udp_echo()
        self.assertUdpEcho(port=echo_port, ip="192.168.1.100")

        p = self.prun("")
        self.assertStartSync(p)
        with self.guest_netns():
            s = utils.connect(port=echo_port, ip="192.168.1.100", udp=True)
            s.sendall(b"ala")
            # We need to do a sync here due to UDP race condition
            self.assertIn("Routing conn new", p.stdout_line())
            s.sendall(b"ma")
            s.sendall(b"kota")
            self.assertEqual(b"ala", s.recv(1024))
            self.assertEqual(b"ma", s.recv(1024))
            self.assertEqual(b"kota", s.recv(1024))
            s.close()


class GenericForwardingTest(base.TestCase):
    def test_fwd_parsing_one(self):
        '''Test basic forwarding parsing, just port'''
        echo_port = 1234
        p = self.prun("-R %s" % echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "Accepting on remote side tcp://10.0.2.2")
        self.assertEqual(port, echo_port)

    def test_fwd_parsing_two(self):
        '''Test basic forwarding parsing, port and host'''
        echo_port = 1235
        p = self.prun("-R 1.2.3.4:%s" % echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "Accepting on remote side tcp://1.2.3.4")
        self.assertEqual(port, echo_port)

    def test_loc_parsing_one(self):
        '''Test basic forwarding parsing, just port'''
        echo_port = 1236
        p = self.prun("-L %s" % echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen tcp://127.0.0.1")
        self.assertEqual(port, echo_port)

    def test_fwd_parsing_two(self):
        '''Test basic forwarding parsing, port and host'''
        echo_port = 1237
        p = self.prun("-L 127.1.2.3:%s" % echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen tcp://127.1.2.3")
        self.assertEqual(port, echo_port)

    def test_local_fwd_resolve_host(self):
        ''' Test if you can local forward to dns label.'''
        g_echo_port = self.start_tcp_echo(guest=True)
        p = self.prun("-L localhost:0:10.0.2.100:%s" % (g_echo_port))
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertTcpEcho(ip="127.0.0.1", port=port)
        self.assertTcpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())


class RemoteForwardingTest(base.TestCase):
    def test_tcp_remote_fwd(self):
        ''' Test tcp remote forwarding - bind to remote port on guest and
        forward it to host. '''
        echo_port = self.start_tcp_echo()
        p = self.prun("-R 80:127.0.0.1:%s" % echo_port)
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(ip='10.0.2.2', port=80)
            self.assertTcpEcho(ip='10.0.2.2', port=80)

    def test_tcp_remote_fwd_2(self):
        '''Test tcp remote forwarding - bind to remote port on
        arbitrary guest IP and forward it to host.
        '''
        echo_port = self.start_tcp_echo()
        p = self.prun("-R 192.0.2.5:80:127.0.0.1:%s" % echo_port)

        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(ip='192.0.2.5', port=80)
            self.assertTcpEcho(ip='192.0.2.5', port=80)

    def test_udp_remote_fwd(self):
        ''' Test udp remote forwarding - bind to remote port on guest and
        forward it to host. '''
        echo_port = self.start_udp_echo()
        p = self.prun("-R udp://80:127.0.0.1:%s" % echo_port)
        self.assertStartSync(p)

        self.assertUdpEcho(ip='127.0.0.1', port=echo_port)
        with self.guest_netns():
            self.assertUdpEcho(ip='10.0.2.2', port=80)
            self.assertUdpEcho(ip='10.0.2.2', port=80)

    def test_udp_remote_fwd_2(self):
        '''Test udp remote forwarding - bind to remote port on arbitrary
        guest IP and forward it to host.'''
        echo_port = self.start_udp_echo()
        p = self.prun("-R udp://192.0.2.5:80:127.0.0.1:%s" % echo_port)
        self.assertStartSync(p)

        self.assertUdpEcho(ip='127.0.0.1', port=echo_port)
        with self.guest_netns():
            self.assertUdpEcho(ip='192.0.2.5', port=80)
            self.assertUdpEcho(ip='192.0.2.5', port=80)

    def test_udp_remote_fwd_merge(self):
        '''Test if udp message boundry is preserved. '''
        echo_port = self.start_udp_echo()
        p = self.prun("-R udp://192.0.2.5:80:127.0.0.1:%s" % echo_port)
        self.assertStartSync(p)

        self.assertUdpEcho(ip='127.0.0.1', port=echo_port)
        with self.guest_netns():
            s = utils.connect(ip='192.0.2.5', port=80, udp=True)
            s.sendall(b"ala")
            s.sendall(b"ma")
            s.sendall(b"kota")
            self.assertEqual(b"ala", s.recv(1024))
            self.assertEqual(b"ma", s.recv(1024))
            self.assertEqual(b"kota", s.recv(1024))
            s.close()


class LocalForwardingTest(base.TestCase):
    def test_tcp_local_fwd(self):
        ''' Test basic local forwarding - bind to local port on host and
        forward it to the guest. '''
        g_echo_port = self.start_tcp_echo(guest=True)
        p = self.prun("-L 0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertTcpEcho(ip="127.0.0.1", port=port)
        self.assertTcpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    @base.isolateHostNetwork()
    def test_tcp_local_fwd_2(self):
        '''Test tcp local forwarding - bind to local port on host and forward
        it to the guest. Establish connection from a routable IP - it
        should be preserved into the guest.'''
        g_echo_port, read_log = self.start_tcp_echo(guest=True, log=True)
        p = self.prun("-L 0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
            self.assertIn("127.0.0.1", read_log())
        self.assertTcpEcho(ip="127.0.0.1", port=port, src="192.168.1.100")
        self.assertTcpEcho(ip="127.0.0.1", port=port, src="192.168.1.100")
        self.assertIn("192.168.1.100", read_log())
        self.assertIn("192.168.1.100", read_log())
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_udp_local_fwd(self):
        ''' Test udp local forwarding - bind to local port on host and forward
        it to the guest. '''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    @base.isolateHostNetwork()
    def test_udp_local_fwd_2(self):
        '''Test udp local forwarding - bind to local port on host and forward
        it to the guest. Establish connection from a routable IP - it
        should be preserved into the guest.'''
        g_echo_port, read_log = self.start_udp_echo(guest=True, log=True)
        p = self.prun("-L udp://0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
            self.assertIn("127.0.0.1", read_log())
        self.assertUdpEcho(ip="127.0.0.1", port=port, src="192.168.1.100")
        self.assertUdpEcho(ip="127.0.0.1", port=port, src="192.168.1.100")
        self.assertIn("192.168.1.100", read_log())
        self.assertIn("192.168.1.100", read_log())
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_udprpc_local_fwd(self):
        '''Test udprcp local forwarding - bind to local port on host and
        forward it to the guest. udprpc is about rapidly closing udp
        rpc flows like DNS or UDP'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udprpc://0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())
        self.assertIn("local-fwd done", p.stdout_line())
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())
        self.assertIn("local-fwd done", p.stdout_line())

    def test_udp_local_fwd_merge(self):
        '''Test if udp message boundry is preserved. '''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        s = utils.connect(port=port, ip="127.0.0.1", udp=True)
        s.sendall(b"ala")
        # We need to do a sync here due to MagicDialUDP race condition
        self.assertIn("local-fwd conn", p.stdout_line())
        self.assertEqual(b"ala", s.recv(1024))
        s.sendall(b"ma")
        s.sendall(b"kota")
        self.assertEqual(b"ma", s.recv(1024))
        self.assertEqual(b"kota", s.recv(1024))
        s.close()


class LocalForwardingPPTest(base.TestCase):
    def test_tcp_pp_local_fwd(self):
        '''  Test inbound TCP proxy-protocol '''
        g_echo_port, read_log = self.start_tcp_echo(guest=True, log=True)
        p = self.prun("-L tcppp://0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local PP listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
            self.assertIn("127.0.0.1", read_log())

        s = utils.connect(port=port, ip="127.0.0.1")
        s.sendall(b"PROXY TCP4 1.2.3.4 4.3.2.1 1 2\r\n")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        s.sendall(b"alamakota")
        self.assertEqual(b"alamakota", s.recv(1024))
        s.close()
        self.assertIn("1.2.3.4", read_log())
        self.assertIn("local-fwd PP done", p.stdout_line())

        s = utils.connect(port=port, ip="127.0.0.1")
        s.sendall(b"PROXY TCP4 4.4.4.4 4.3.2.1 1 2\r\nalama")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        s.sendall(b"kota")
        self.assertIn("4.4.4.4", read_log())
        b = b""
        while len(b) < 8:
            b += s.recv(1024)
        self.assertEqual(b"alamakota", b)
        s.close()

    def test_tcp_pp_local_fwd_noport(self):
        '''Test inbound TCP proxy-protocol, while specifying zero port on the
        guest side'''
        g_echo_port, read_log = self.start_tcp_echo(guest=True, log=True)
        p = self.prun("-L tcppp://0:10.0.2.100:0" )
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local PP listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
            self.assertIn("127.0.0.1", read_log())

        s = utils.connect(port=port, ip="127.0.0.1")
        s.sendall(b"PROXY TCP4 1.2.3.4 4.3.2.1 1 %d\r\n" % (g_echo_port,))
        self.assertIn("local-fwd PP conn", p.stdout_line())
        s.sendall(b"alamakota")
        self.assertEqual(b"alamakota", s.recv(1024))
        s.close()
        self.assertIn("1.2.3.4", read_log())
        self.assertIn("local-fwd PP done", p.stdout_line())

    def test_udp_spp_local_fwd(self):
        '''Test inbound UDP SPP. Read more in https://developers.cloudflare.com/spectrum/getting-started/proxy-protocol/#enabling-simple-proxy-protocol-for-udp'''
        g_echo_port, read_log = self.start_udp_echo(guest=True, log=True)
        p = self.prun("-L udpspp://0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local PP listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
            self.assertIn("127.0.0.1", read_log())

        s = utils.connect(port=port, ip="127.0.0.1", udp=True)
        sppheader = struct.pack("!HIIIIIIIIHH", 0x56ec,
                              0,0,0xffff,0x01020304,
                              0,0,0xffff,0x04030201,
                              1,2)
        s.sendall(sppheader + b"alamakota")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        self.assertEqual(b"alamakota", s.recv(1024)[38:])
        adr = read_log()
        self.assertIn("1.2.3.4", adr)

        s.sendall(b'\x00'*38 + b"alamakota2")
        self.assertEqual(b"alamakota2", s.recv(1024)[38:])
        self.assertEqual(adr, read_log())
        s.close()

        s = utils.connect(port=port, ip="127.0.0.1", udp=True)
        sppheader = struct.pack("!HIIIIIIIIHH", 0x56ec,
                              0,0,0xffff,0x04040404,
                              0,0,0xffff,0x04030201,
                              1,2)
        s.sendall(sppheader + b"kotamaala")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        self.assertEqual(b"kotamaala", s.recv(1024)[38:])
        s.close()
        self.assertIn("4.4.4.4", read_log())

    def test_tcp_pp_local_fwd_v6(self):
        '''  Test inbound TCP v6 proxy-protocol '''
        g_echo_port, read_log = self.start_tcp_echo(guest=True, log=True)
        p = self.prun("-L tcppp://[::1]:0:[2001:2::100]:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local PP listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="::1", port=g_echo_port)
            self.assertIn("::1", read_log())

        s = utils.connect(port=port, ip="::1")
        s.sendall(b"PROXY TCP4 abcd::1 dcba::1 1 2\r\n")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        s.sendall(b"alamakota")
        self.assertEqual(b"alamakota", s.recv(1024))
        s.close()
        self.assertIn("abcd::1", read_log())
        self.assertIn("local-fwd PP done", p.stdout_line())


class RoutingTestSecurity(base.TestCase):
    @base.isolateHostNetwork()
    def test_disabe_host_networks(self):
        ''' Test tcp routing security, specifically --disable-host-networks option. '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--disable-host-networks")
        self.assertStartSync(p)
        with self.guest_netns():
            for dst in ("192.168.1.100", "3ffe::100"):
                with self.assertRaises(socket.timeout):
                    utils.connect(port=echo_tcp_port, ip=dst, timeout=0.3)
                s = utils.connect(port=echo_udp_port, ip=dst, udp=True)
                s.sendall(b"ala")
                s.close()

        # Connections from host, to have something in logs. The
        # connection attempts above should not trigger any logs.
        self.assertTcpEcho(ip="127.0.0.1", src='127.1.2.3', port=echo_tcp_port)
        self.assertIn("127.1.2.3", tcp_log())

        self.assertUdpEcho(ip="127.0.0.1", src='127.1.2.4', port=echo_udp_port)
        self.assertIn("127.1.2.4", udp_log())

    @base.isolateHostNetwork()
    def test_disabe_routing(self):
        ''' Test tcp routing security, specifically --disable-routing
        option. This test is the same as test above. '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--disable-routing")
        self.assertStartSync(p)
        with self.guest_netns():
            for dst in ("192.168.1.100", "3ffe::100"):
                with self.assertRaises(socket.timeout):
                    utils.connect(port=echo_tcp_port, ip=dst, timeout=0.3)
                s = utils.connect(port=echo_udp_port, ip=dst, udp=True)
                s.sendall(b"ala")
                s.close()

        # Connections from host, to have something in logs. The
        # connection attempts above should not trigger any logs.
        self.assertTcpEcho(ip="127.0.0.1", src='127.1.2.3', port=echo_tcp_port)
        self.assertIn("127.1.2.3", tcp_log())

        self.assertUdpEcho(ip="127.0.0.1", src='127.1.2.4', port=echo_udp_port)
        self.assertIn("127.1.2.4", udp_log())

    @base.isolateHostNetwork()
    def test_source_ipv4(self):
        ''' Test --source-ipv4 option'''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--source-ipv4=127.4.3.2")
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(ip="192.168.1.100", port=echo_tcp_port)
            self.assertIn("Routing conn new", p.stdout_line())
            self.assertIn("Routing conn done: l=", p.stdout_line())
            self.assertIn("127.4.3.2", tcp_log())

            self.assertUdpEcho(ip="192.168.1.100", port=echo_udp_port)
            self.assertIn("Routing conn new", p.stdout_line())
            self.assertIn("127.4.3.2", udp_log())

    @base.isolateHostNetwork()
    def test_source_ipv6(self):
        ''' Test --source-ipv6 option'''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--source-ipv6=::1")
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(ip="3ffe::100", port=echo_tcp_port)
            self.assertIn("Routing conn new", p.stdout_line())
            self.assertIn("Routing conn done: l=", p.stdout_line())
            self.assertIn("::1", tcp_log())

            try:
                self.assertUdpEcho(ip="3ffe::100", port=echo_udp_port)
            except:
                pass
            self.assertIn("Routing conn new", p.stdout_line())
            self.assertIn("::1", udp_log())
