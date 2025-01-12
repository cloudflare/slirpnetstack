from . import base
from . import utils
import os
import shutil
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

    def test_version(self):
        ''' Basic test if -version prints version. '''
        p = self.prun("-version", netns=False)
        o = p.stdout_line()
        self.assertIn("slirpnetstack version ", o)
        self.assertNotIn("DEV", o)
        o = p.stdout_line()
        self.assertIn("build time ", o)
        self.assertIn("UTC", o)
        self.assertNotIn("unknown", o)

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
            endianness = "<" if struct.unpack("<L", data[0:4])[0] == 0xa1b2c3d4 else ">"
            header = struct.unpack("%sLHHLLLL" % endianness, data)

            self.assertEqual(header[0], 0xa1b2c3d4)
            data = f.read(16)
            (seconds, useconds, captured_length, packet_length) = struct.unpack("%sLLLL" % endianness, data)
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
        # arp Who has 10.0.2.10? Tell 10.0.2.100
        ping = bytes.fromhex('''
        ff ff ff ff ff ff 70 71 aa 4b 29 aa 08 06 00 01
        08 00 06 04 00 01 70 71 aa 4b 29 aa 0a 00 02 64
        00 00 00 00 00 00 0a 00 02 0a'''.replace('\n','').replace(' ', ''))
        sp[1].sendall(ping)
        while True:
            pong = sp[1].recv(1024)
            if pong[14:16] == b'\x00\x01': # Arp
                if pong[20:22] == b'\x00\x02': # Arp reply
                    if pong[28:32] == b'\x0a\x00\x02\x0a': # 10.0.2.10 is on
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
        self.assertEqual(p.rc, 247, "exit code should be 247")

    def test_basic_ping6(self):
        '''Due to how netstack is configured, we will answer to ping against
        any IP. Let's test it!.'''
        p = self.prun()
        self.assertStartSync(p)
        with self.guest_netns():
            # ping6 may not be present on some systems.
            ping_cmd = shutil.which("ping6")
            if ping_cmd is None:
                ping_cmd = "ping"
            # ping local address. sanity. This is kinda tricky. First,
            # tuntap must be enabled (ie: someone must pick up the
            # fd). Then the ip needs to have 'nodad' toggle, to
            # prevent it from stalling on duplicate address detection.
            r = os.system("%s -q 2001:2::2 -c 1 -n > /dev/null" % ping_cmd)
            self.assertEqual(r, 0)
            r = os.system("%s -q 2001:2::100 -c 1 -n > /dev/null" % ping_cmd)
            self.assertEqual(r, 0)
            # 1.1.1.1 resolver. Doesn't matter - will be terminated by netstack
            r = os.system("%s -q 2606:4700:4700::1111 -c 1 -n > /dev/null" % ping_cmd)
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
        p = self.prun("-enable-host")
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
        p = self.prun("-enable-host")
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
        p = self.prun("-enable-host")
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

        p = self.prun("-enable-host")
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

        p = self.prun("-enable-host")
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

    @base.isolateHostNetwork()
    def test_udp_large_packet(self):
        '''Test UDP packet larger than 1500 bytes'''
        echo_port = self.start_udp_echo()
        self.assertUdpEcho(port=echo_port, ip="192.168.1.100")

        p = self.prun("-enable-host")
        self.assertStartSync(p)
        with self.guest_netns():
            s = utils.connect(port=echo_port, ip="192.168.1.100", udp=True)
            s.send(b"a"*16385)
            s.sendall(b"a"*(65535-28))
            lengths = [16385, 65507]
            while len(lengths) > 0:
                data = s.recv(64*1024)
                lengths.remove(len(data))
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
        p = self.prun("-enable-host -R 1.2.3.4:%s" % echo_port)
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

    def test_loc_parsing_two(self):
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


class DefaultIPSelectionTests(base.TestCase):
    def test_local_empty(self):
        '''Test a local forward rule with no IPs given'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://127.0.0.1")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_remote_empty(self):
        '''Test a remote forward rule with no IPs given'''
        g_echo_port = self.start_udp_echo()
        p = self.prun("-R udp://:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "Accepting on remote side udp://10.0.2.2")

        with self.guest_netns():
            self.assertUdpEcho(ip="10.0.2.2", port=port)
        self.assertRegex(p.stdout_line(), "127.0.0.1:\\d+-127.0.0.1:%s remote-fwd conn new" % g_echo_port)

    def test_local_implicit_host_v4(self):
        '''Test a local forward rule with an implicit IPv4 host'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://:0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://127.0.0.1")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_local_implicit_forward_v4(self):
        '''Test a local forward rule with an implicit IPv4 denstination'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://127.0.0.1:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://127.0.0.1")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_local_implicit_host_v6(self):
        '''Test a local forward rule with an implicit IPv6 host'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://:0:[fd00::100]:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://[::1]")

        with self.guest_netns():
            self.assertUdpEcho(ip="::1", port=g_echo_port)
        self.assertUdpEcho(ip="::1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_local_implicit_forward_v6(self):
        '''Test a local forward rule with an implicit IPv6 denstination'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://[::1]:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://[::1]")

        with self.guest_netns():
            self.assertUdpEcho(ip="::1", port=g_echo_port)
        self.assertUdpEcho(ip="::1", port=port)
        self.assertIn("local-fwd conn", p.stdout_line())

    def test_remote_implicit_forward_v6(self):
        '''Test a remote forward rule with an implicit IPv6 destination'''
        g_echo_port = self.start_udp_echo()
        p = self.prun("-R udp://[fd00::2]:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "Accepting on remote side udp://fd00::2")

        with self.guest_netns():
            self.assertUdpEcho(ip="fd00::2", port=port)
        self.assertRegex(p.stdout_line(), "\\[::1\\]:\\d+-\\[::1\\]:%s remote-fwd conn new" % g_echo_port)

    def test_local_any_v4(self):
        '''Test a local forward rule with the 0.0.0.0 addr'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://0.0.0.0:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://[::]")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertRegex(p.stdout_line(), "10.0.2.2:\\d+-10.0.2.100:%s local-fwd conn" % g_echo_port)

    def test_local_any_v6(self):
        '''Test a local forward rule with the :: addr'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://[::]:::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://[::]")

        with self.guest_netns():
            self.assertUdpEcho(ip="::1", port=g_echo_port)
        self.assertUdpEcho(ip="::1", port=port)
        self.assertRegex(p.stdout_line(), "\\[fd00::2\\]:\\d+-\\[fd00::100\\]:%s local-fwd conn" % g_echo_port)

    def test_localhost_v4(self):
        '''Test a local forward rule with the localhost label'''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://localhost:0::%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen udp://127.0.0.1")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertRegex(p.stdout_line(), "10.0.2.2:\\d+-10.0.2.100:%s local-fwd conn" % g_echo_port)


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

    @base.isolateHostNetwork()
    def test_tcp_local_fwd_v6tov4(self):
        ''' Test local forwarding - bind to local IPv6 port on host and
        forward it to the guest via IPv4. '''
        g_echo_port = self.start_tcp_echo(guest=True)
        p = self.prun("-L tcp://[::]:0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="::1", port=g_echo_port)
        # ::1 is on the StaticRoutingDeny list, meaning it will not be spoofed
        self.assertTcpEcho(ip="::1", port=port)
        self.assertRegex(p.stdout_line(), "10.0.2.2:\\d+-10.0.2.100:%s local-fwd conn" % g_echo_port)
        self.assertIn("local-fwd done", p.stdout_line())
        self.assertTcpEcho(ip="3ffe::100", port=port)
        self.assertRegex(p.stdout_line(), "10.0.2.2:\\d+-10.0.2.100:%s local-fwd conn" % g_echo_port)

    @base.isolateHostNetwork()
    def test_tcp_local_fwd_v4tov6(self):
        ''' Test basic local forwarding - bind to local IPv4 port on host and
        forward it to the guest via IPv6. '''
        g_echo_port = self.start_tcp_echo(guest=True)
        p = self.prun("-L tcp://0.0.0.0:0:[fd00::100]:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
        # 127.0.0.1 is on the StaticRoutingDeny list, meaning it will not be spoofed
        self.assertTcpEcho(ip="127.0.0.1", port=port)
        self.assertRegex(p.stdout_line(), "\\[fd00::2\\]:\\d+-\\[fd00::100\\]:%s local-fwd conn" % g_echo_port)
        self.assertIn("local-fwd done", p.stdout_line())
        self.assertTcpEcho(ip="192.168.1.100", port=port)
        self.assertRegex(p.stdout_line(), "\\[fd00::2\\]:\\d+-\\[fd00::100\\]:%s local-fwd conn" % g_echo_port)

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

    @base.isolateHostNetwork()
    def test_udp_local_fwd_v6tov4(self):
        ''' Test local forwarding - bind to local IPv6 port on host and
        forward it to the guest via IPv4. '''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://[::]:0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="::1", port=g_echo_port)
        # ::1 is on the StaticRoutingDeny list, meaning it will not be spoofed
        self.assertUdpEcho(ip="::1", port=port)
        self.assertRegex(p.stdout_line(), "10.0.2.2:\\d+-10.0.2.100:%s local-fwd conn" % g_echo_port)
        self.assertUdpEcho(ip="3ffe::100", port=port)
        self.assertRegex(p.stdout_line(), "10.0.2.2:\\d+-10.0.2.100:%s local-fwd conn" % g_echo_port)

    @base.isolateHostNetwork()
    def test_udp_local_fwd_v4tov6(self):
        ''' Test basic local forwarding - bind to local IPv4 port on host and
        forward it to the guest via IPv6. '''
        g_echo_port = self.start_udp_echo(guest=True)
        p = self.prun("-L udp://0.0.0.0:0:[fd00::100]:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local listen")

        with self.guest_netns():
            self.assertUdpEcho(ip="127.0.0.1", port=g_echo_port)
        # 127.0.0.1 is on the StaticRoutingDeny list, meaning it will not be spoofed
        self.assertUdpEcho(ip="127.0.0.1", port=port)
        self.assertRegex(p.stdout_line(), "\\[fd00::2\\]:\\d+-\\[fd00::100\\]:%s local-fwd conn" % g_echo_port)
        self.assertUdpEcho(ip="192.168.1.100", port=port)
        self.assertRegex(p.stdout_line(), "\\[fd00::2\\]:\\d+-\\[fd00::100\\]:%s local-fwd conn" % g_echo_port)

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
        s.sendall(sppheader + b"alamakota" + b'x' * 65000)
        self.assertIn("local-fwd PP conn", p.stdout_line())
        data = s.recv(64*1024)
        self.assertEqual(b"alamakota", data[38:38+9])
        self.assertEqual(65000+38+9, len(data))
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
        p = self.prun("-L tcppp://[::1]:0:[fd00::100]:%s" % g_echo_port)
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

    def test_tcp_pp_local_fwd_v6tov4(self):
        '''  Test inbound TCP v6 proxy-protocol to v4 destination '''
        g_echo_port, read_log = self.start_tcp_echo(guest=True, log=True)
        p = self.prun("-L tcppp://[::]:0:10.0.2.100:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local PP listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="127.0.0.1", port=g_echo_port)
            self.assertIn("127.0.0.1", read_log())

        s = utils.connect(port=port, ip="::1")
        s.sendall(b"PROXY TCP4 abcd::1 dcba::1 1 2\r\n")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        s.sendall(b"alamakota")
        self.assertEqual(b"alamakota", s.recv(1024))
        s.close()
        # The source IPv6 address can't be spoofed to the IPv4 destination
        self.assertIn("10.0.2.2", read_log())
        self.assertIn("local-fwd PP done", p.stdout_line())

    def test_tcp_pp_local_fwd_v4tov6(self):
        '''  Test inbound TCP v4 proxy-protocol to v6 destination '''
        g_echo_port, read_log = self.start_tcp_echo(guest=True, log=True)
        p = self.prun("-L tcppp://0.0.0.0:0:[fd00::100]:%s" % g_echo_port)
        self.assertStartSync(p)
        port = self.assertListenLine(p, "local-fwd Local PP listen")

        with self.guest_netns():
            self.assertTcpEcho(ip="::1", port=g_echo_port)
            self.assertIn("::1", read_log())

        s = utils.connect(port=port, ip="127.0.0.1")
        s.sendall(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n")
        self.assertIn("local-fwd PP conn", p.stdout_line())
        s.sendall(b"alamakota")
        self.assertEqual(b"alamakota", s.recv(1024))
        s.close()
        # The source IPv6 address can't be spoofed to the IPv4 destination
        self.assertIn("[fd00::2]", read_log())
        self.assertIn("local-fwd PP done", p.stdout_line())


class RoutingTestSecurity(base.TestCase):
    @base.isolateHostNetwork()
    def test_disable_host_networks(self):
        ''' Test tcp routing security, specifically --disable-host-networks option. '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("")
        self.assertStartSync(p)
        with self.guest_netns():
            for dst in ("192.168.1.100", "3ffe::100"):
                self.assertTcpRefusedError(port=echo_tcp_port, ip=dst)
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
        '''Test tcp routing security, specifically by default routing should
        be disabled.  This test is the same as test above.'''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("")
        self.assertStartSync(p)
        with self.guest_netns():
            for dst in ("192.168.1.100", "3ffe::100"):
                self.assertTcpRefusedError(port=echo_tcp_port, ip=dst)
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
        p = self.prun("--enable-host --source-ipv4=127.4.3.2")
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
        p = self.prun("-enable-host -source-ipv6=::1")
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

    @base.isolateHostNetwork()
    def test_allow_range_all_ports(self):
        ''' Test --allow and --deny with disabled routing - all ports'''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--allow=tcp://192.168.1.100,udp://192.168.1.100,tcp://[3ffe::100],udp://[3ffe::100] --deny=tcp://192.168.1.100,tcp://[3ffe::100]")
        self.assertStartSync(p)
        with self.guest_netns():
            for dst in ("192.168.1.100", "3ffe::100"):
                self.assertTcpRefusedError(port=echo_tcp_port, ip=dst)
                s = utils.connect(port=echo_udp_port, ip=dst, udp=True)
                s.sendall(b"ala")
                s.close()
                self.assertIn(dst, udp_log())

        # Connections from host, to have something in logs. The
        # connection attempts above should not trigger any logs.
        self.assertTcpEcho(ip="127.0.0.1", src='127.1.2.3', port=echo_tcp_port)
        self.assertIn("127.1.2.3", tcp_log())

    @base.isolateHostNetwork()
    def test_deny_range_some_ports(self):
        ''' Test --allow and --deny with --disable-routing - some ports '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--enable-host --allow=udp://192.168.1.100:100-200 --allow=tcp://192.168.1.100:100-200 --deny=tcp://192.168.1.100:%d,tcp://[3ffe::100]:%d-%d" % (
            echo_tcp_port, echo_tcp_port, echo_tcp_port))
        self.assertStartSync(p)
        with self.guest_netns():
            for dst in ("192.168.1.100", "3ffe::100"):
                self.assertTcpRefusedError(port=echo_tcp_port, ip=dst)
                s = utils.connect(port=echo_udp_port, ip=dst, udp=True)
                s.sendall(b"ala")
                s.close()
                self.assertIn(dst, udp_log())

        # Connections from host, to have something in logs. The
        # connection attempts above should not trigger any logs.
        self.assertTcpEcho(ip="127.0.0.1", src='127.1.2.3', port=echo_tcp_port)
        self.assertIn("127.1.2.3", tcp_log())

    @base.isolateHostNetwork()
    def test_allow_cover_cases(self):
        ''' Test --allow parsing corner cases '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        p = self.prun("--allow=192.168.1.100:%d" % (echo_tcp_port,))
        self.assertStartSync(p)
        with self.guest_netns():
            self.assertTcpEcho(port=echo_tcp_port, ip="192.168.1.100")
        self.assertIn("192.168.1.100", tcp_log())
        p.close()

        # Make it not a valid DNS label, to allow dns to fail
        # quick. Otherwise the thing will stall for > 20s on DNS
        # resolution. Remember we don't have access to host resolver
        # from the isolateHostNetwork test.
        p = self.prun("--allow=notahostó")
        e = p.stderr_line()
        self.assertIn('invalid value "notahostó" for flag -allow: lookup notahostó', e)
        p.close()

        p = self.prun("--allow=localhost:a")
        o = p.stdout_line()
        self.assertFalse(o)
        e = p.stderr_line()
        self.assertIn('invalid value "localhost:a" for flag -allow: strconv.ParseUint: parsing "a": invalid syntax', e)
        p.close()

        p = self.prun("--allow=localhost:0-b")
        o = p.stdout_line()
        self.assertFalse(o)
        e = p.stderr_line()
        self.assertIn('invalid value "localhost:0-b" for flag -allow: strconv.ParseUint: parsing "b": invalid syntax', e)
        p.close()

        p = self.prun("--allow=localhost:2-1")
        o = p.stdout_line()
        self.assertFalse(o)
        e = p.stderr_line()
        self.assertIn('invalid value "localhost:2-1" for flag -allow: min port must be smaller equal than max', e)
        p.close()

    @base.isolateHostNetwork()
    def test_remote_srv(self):
        ''' Test -R=tcp://:2222:tcp.echo.server@srv-8600:0 syntax '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        dns_port, dns = self.start_dns("tcp.echo.server.=localhost:%d" % echo_tcp_port,
                                  "udp.echo.server.=localhost:%d" % echo_udp_port)
        p = self.prun("-dns-ttl=0 -R=tcp://:2222:tcp.echo.server@srv-%d:0 -R=udp://:2222:udp.echo.server@srv-%d:0" % (dns_port, dns_port))

        self.assertStartSync(p)
        self.assertIn("Accepting", p.stdout_line())
        self.assertIn("Accepting", p.stdout_line())

        with self.guest_netns():
            self.assertTcpEcho(port=2222, ip="10.0.2.2")
            self.assertIn("%s" % echo_tcp_port, p.stdout_line())
            self.assertIn("%s" % echo_tcp_port, p.stdout_line())
            self.assertUdpEcho(port=2222, ip="10.0.2.2")
            self.assertIn("%s" % echo_udp_port, p.stdout_line())

            dns.close()
            s = utils.connect(port=2222, ip="10.0.2.2")
            s.close()
            self.assertIn("dns lookup error", p.stdout_line())
            s = utils.connect(port=2222, ip="10.0.2.2", udp=True)
            s.sendall(b"ala")
            s.close()
            self.assertIn("dns lookup error" , p.stdout_line())

        self.assertIn("127.0.0.1", tcp_log())
        self.assertTcpEcho(ip="127.0.0.1", src='127.1.2.4', port=echo_tcp_port)
        self.assertIn("127.1.2.4", tcp_log())

        self.assertIn("127.0.0.1", udp_log())
        self.assertUdpEcho(ip="127.0.0.1", src='127.1.2.4', port=echo_udp_port)
        self.assertIn("127.1.2.4", udp_log())

    @base.isolateHostNetwork()
    def test_remote_srv_withut_dns(self):
        '''Test -R=tcp://:2222:tcp.echo.server@srv-8600:0 syntax but when dns
        server is down. Most importantly - starting the app with dns dwown. '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)

        dns_port = 1
        p = self.prun("-dns-ttl=0 -R=tcp://:2222:tcp.echo.server@srv-%d:0 -R=udp://:2222:udp.echo.server@srv-%d:0" % (dns_port, dns_port))

        self.assertStartSync(p)
        self.assertIn("Accepting", p.stdout_line())
        self.assertIn("Accepting", p.stdout_line())

        with self.guest_netns():
            s = utils.connect(port=2222, ip="10.0.2.2", timeout=0.3)
            s.close()
            self.assertIn("10.0.2.2:2222/tcp.echo.server@srv-1-failed remote-fwd dns lookup error", p.stdout_line())
            s = utils.connect(port=2222, ip="10.0.2.2", udp=True)
            s.sendall(b"ala")
            s.close()
            self.assertIn("10.0.2.2:2222/udp.echo.server@srv-1-failed remote-fwd dns lookup error" , p.stdout_line())

        p.close()

        # but when local binding, this hard fails
        p = self.prun("-dns-ttl=0 -R=tcp://tcp.echo.server@srv-%d:0::2222" % (dns_port, ))
        self.assertIn("Joininig", p.stderr_line())
        self.assertIn("Opening tun ", p.stderr_line())
        self.assertIn('[!] Failed to resolve bind address. dns lookup error of tcp addr: failed to lookup SRV "tcp.echo.server"', p.stderr_line())

        p.close()
        self.assertEqual(p.rc, 246, "exit code should be 246")

    @base.isolateHostNetwork()
    def test_remote_srv_ipv6(self):
        ''' Test -R=tcp://:2222:[tcp.echo.server@srv-[::1]:8600]:0 syntax '''
        echo_tcp_port, tcp_log = self.start_tcp_echo(log=True)
        echo_udp_port, udp_log = self.start_udp_echo(log=True)
        dns_port, dns = self.start_dns("--addr=[::1]",
                                  "tcp.echo.server.=localhost:%d" % echo_tcp_port,
                                  "udp.echo.server.=localhost:%d" % echo_udp_port)
        p = self.prun("-dns-ttl=0 -R=tcp://:2222:[tcp.echo.server@srv-[::1]:%d]:0 -R=udp://:2222:[udp.echo.server@srv-[::1]:%d]:0" % (dns_port, dns_port))

        self.assertStartSync(p)
        self.assertIn("Accepting", p.stdout_line())
        self.assertIn("Accepting", p.stdout_line())

        with self.guest_netns():
            self.assertTcpEcho(port=2222, ip="10.0.2.2")
            self.assertIn("%s" % echo_tcp_port, p.stdout_line())
            self.assertIn("%s" % echo_tcp_port, p.stdout_line())
            self.assertUdpEcho(port=2222, ip="10.0.2.2")
            self.assertIn("%s" % echo_udp_port, p.stdout_line())

            dns.close()
            s = utils.connect(port=2222, ip="10.0.2.2")
            s.close()
            self.assertIn("dns lookup error", p.stdout_line())
            s = utils.connect(port=2222, ip="10.0.2.2", udp=True)
            s.sendall(b"ala")
            s.close()
            self.assertIn("dns lookup error" , p.stdout_line())

        self.assertIn("127.0.0.1", tcp_log())
        self.assertTcpEcho(ip="127.0.0.1", src='127.1.2.4', port=echo_tcp_port)
        self.assertIn("127.1.2.4", tcp_log())

        self.assertIn("127.0.0.1", udp_log())
        self.assertUdpEcho(ip="127.0.0.1", src='127.1.2.4', port=echo_udp_port)
        self.assertIn("127.1.2.4", udp_log())
