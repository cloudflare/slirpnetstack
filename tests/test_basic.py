from . import base
from . import utils
import os
import unittest


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
        # TODO: we need to do a sync here due to MagicDialUDP race condition
        self.assertIn("local-fwd conn", p.stdout_line())
        self.assertEqual(b"ala", s.recv(1024))
        s.sendall(b"ma")
        s.sendall(b"kota")
        self.assertEqual(b"ma", s.recv(1024))
        self.assertEqual(b"kota", s.recv(1024))
        s.close()
