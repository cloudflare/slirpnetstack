from . import utils
import ctypes
import errno
import functools
import io
import os
import random
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

LIBC = ctypes.CDLL("libc.so.6")
SLIRPNETSTACKBIN = os.environ.get('SLIRPNETSTACKBIN')
DEBUG = bool(os.environ.get('DEBUG'))
CLONE_NEWNET = 0x40000000
ORIGINAL_NET_NS = open("/proc/self/ns/net", 'rb')
MOCKUDPECHO  = os.environ.get('MOCKUDPECHO', './bin/mockudpecho')
MOCKTCPECHO  = os.environ.get('MOCKTCPECHO', './bin/mocktcpecho')
MOCKDNS      = os.environ.get('MOCKDNS', './bin/mockdns')
IP_FREEBIND = 15

execno = 0
def run(argv1=[], close_fds=True):
    global execno
    execno += 1
    argv0 = shlex.split(SLIRPNETSTACKBIN % {"nr": execno})

    if isinstance(argv1, str):
        argv1 = shlex.split(argv1)

    a = argv0 + argv1

    return Process(a, close_fds=close_fds)


class Process(object):
    def __init__(self, argv, close_fds=True):
        last_cmd = utils.encode_shell(argv)
        if DEBUG:
            print("[r] Running: %s" % (last_cmd,))

        self.p = subprocess.Popen(argv,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  close_fds=close_fds)
        self.rc = None

    def stdout_line(self):
        while True:
            o = self.p.stdout.readline().decode()
            if o == 'PASS\n' or o.startswith("coverage: "):
                continue
            return o

    def stdout_log(self):
        l = self.stdout_line()
        return json.loads(l)

    def stderr_line(self):
        while True:
            e = self.p.stderr.readline().decode()
            if not e:
                continue
            if e.startswith('[o]'):
                print(e)
                continue
            if e.startswith('panic'):
                while e:
                    print(e.rstrip())
                    e = self.p.stderr.readline().decode()
                e = 'PANIC'
            return e

    def close(self, kill=True):
        '''Returns process return code.'''
        if self.p:
            if kill:
                # Ensure the process registers two signals by sending a combo of
                # SIGINT and SIGTERM. Sending the same signal two times is racy
                # because the process can't reliably detect how many times the
                # signal was sent.
                self.p.send_signal(signal.SIGINT)
                self.p.send_signal(signal.SIGTERM)
            self.rc = self.p.wait()
            self.p.stderr.close()
            self.p.stdout.close()

        self.p = None
        return self.rc

    def graceful_stop(self, wait=True):
        self.p.send_signal(signal.SIGINT)
        if wait:
            self.p.wait()

class TestCase(unittest.TestCase):
    cleanups = None

    def prun(self, argv1=[], close_fds=True, netns=True):
        global execno
        execno += 1
        argv0 = shlex.split(SLIRPNETSTACKBIN % {"nr": execno})

        if isinstance(argv1, str):
            argv1 = shlex.split(argv1)

        if netns:
            argv1 = argv1 + ["-netns=%s" % self.net_ns_path()]
        if '.cover' in SLIRPNETSTACKBIN:
            argv1 = ['--args=%s' % i for i in argv1]
        p = Process(argv0 + argv1, close_fds=close_fds)
        self._add_teardown(p)
        return p

    def get_tmp_filename(self, name):
        return os.path.join(self._tmpdir.name, name)

    def _add_teardown(self, item):
        if not self.cleanups:
            self.cleanups = []
        self.cleanups.append(item)

    def setUp(self):
        prev_net_fd = open("/proc/self/ns/net", 'rb')
        r = LIBC.unshare(CLONE_NEWNET)
        if r != 0:
            print('[!] Are you running within "unshare -Ur" ? Need unshare() syscall.')
            sys.exit(-1)
        self.guest_net_fd = open("/proc/self/ns/net", 'rb')
        self._add_teardown(self.guest_net_fd)

        # mode tap, means ethernet headers
        os.system("ip link set lo up;"
                  "ip tuntap add mode tap name tun0;"
                  "ip link set tun0 mtu 65521;"
                  "ip link set tun0 up;"
                  "ip addr add 10.0.2.100/24 dev tun0;"
                  "ip addr add fd00::100/64 dev tun0 nodad;"
                  "ip route add 0.0.0.0/0 via 10.0.2.2 dev tun0;"
                  "ip route add ::/0 via fd00::2 dev tun0;")
        w = subprocess.Popen(["/bin/sleep", "1073741824"])
        self.guest_ns_pid = w.pid
        self._add_teardown(w)
        LIBC.setns(prev_net_fd.fileno(), CLONE_NEWNET)
        prev_net_fd.close()
        self._tmpdir = tempfile.TemporaryDirectory()
        self._add_teardown(self._tmpdir)

    def tearDown(self):
        while self.cleanups:
            item = self.cleanups.pop()
            if isinstance(item, subprocess.Popen):
                item.send_signal(signal.SIGINT)
                item.wait()
            elif isinstance(item, Process):
                item.close()
                if getattr(item, 'stdout', None):
                    item.stdout.close()
                if getattr(item, 'stderr', None):
                    item.stderr.close()
            elif isinstance(item, io.BufferedReader):
                item.close()
            elif isinstance(item, tempfile.TemporaryDirectory):
                item.cleanup()
            else:
                print("[!] Unknown cleanup type")
                print(type(item))

    def net_ns_path(self):
        return "/proc/%s/ns/net" % self.guest_ns_pid

    def guest_netns(self):
        xself = self
        class controlled_execution:
            def __enter__(self):
                self.prev_net_fd = open("/proc/self/ns/net", 'rb')
                LIBC.setns(xself.guest_net_fd.fileno(), CLONE_NEWNET)
            def __exit__(self, type, value, traceback):
                LIBC.setns(self.prev_net_fd.fileno(), CLONE_NEWNET)
                self.prev_net_fd.close()
        return controlled_execution()

    def start_udp_echo(self, **kwargs):
        kwargs['tcp'] = False
        return self.start_echo(**kwargs)

    def start_tcp_echo(self, **kwargs):
        kwargs['tcp'] = True
        return self.start_echo(**kwargs)

    def start_echo(self, guest=False, log=False, tcp=True):
        if tcp:
            cmd = [MOCKTCPECHO]
        else:
            cmd = [MOCKUDPECHO]
        if log:
            cmd += ["-log"]
        if guest == False:
            p = Process(cmd)
        else:
            with self.guest_netns():
                p = Process(cmd)
        echo_port = int(p.stdout_line())
        self._add_teardown(p)
        if log:
            return echo_port, p.stdout_line
        else:
            return echo_port

    def start_dns(self, *kv):
        cmd = [MOCKDNS, *kv]
        p = Process(cmd)
        dns_port = int(p.stdout_line())
        self._add_teardown(p)
        return dns_port, p

    def assertUdpEcho(self, *args, **kwargs):
        kwargs['udp'] = True
        s = utils.connect(*args, **kwargs)
        payload = b'ala%f\n' % random.random()
        s.sendall(payload)
        self.assertEqual(payload, s.recv(1024))
        s.close()

    def assertTcpEcho(self, *args, **kwargs):
        s = utils.connect(*args, **kwargs)
        payload = b'bob%f\n' % random.random()
        s.sendall(payload)
        self.assertEqual(payload, s.recv(1024))
        s.close()

    def assertTcpRefusedError(self, ip="127.0.0.1", port=0):
        with self.assertRaises(socket.error) as e:
            s = utils.connect(ip, port, cleanup=self)
            s.recv(1024)
        self.assertEqual(e.exception.errno, errno.ECONNREFUSED)

    def assertStartSync(self, p, fd=False):
        if not fd:
            self.assertIn("[.] Join", p.stderr_line())
            self.assertIn("[.] Opening tun", p.stderr_line())
        self.assertIn("Slirpnetstack started", p.stderr_line())

    def assertListenLine(self, p, in_pattern):
        line = p.stdout_line().strip()
        self.assertIn(in_pattern, line)
        return int(line.split(":")[-1])

    def _allow_ping_sockets(self):
        # slirpnetstack relays guest echo requests out via SOCK_DGRAM ICMP
        # sockets, which the kernel only allows for groups within
        # ping_group_range (this gates ICMPv6 too). The isolated host netns
        # starts with the kernel default "1 0" (off); inside "unshare -Ur"
        # only gid 0 is mapped, so allow just it. Written in the host netns,
        # where slirpnetstack opens those sockets.
        with open("/proc/sys/net/ipv4/ping_group_range", "w") as f:
            f.write("0 0")

    def _netns_holder(self):
        '''Spawn a process that owns a fresh, otherwise-empty network
        namespace and then sleeps. Its only job is to keep that netns alive
        and reachable as /proc/<pid>/ns/net, so we can move veth ends into it
        (ip link set ... netns <pid>) and configure it (nsenter -t <pid> -n).
        Reuses the harness' Popen teardown: killing the sleeper drops the
        netns and its interfaces. Needs CAP_SYS_ADMIN, which we have as the
        mapped-root user under "unshare -Ur".'''
        h = subprocess.Popen(["unshare", "--net", "/bin/sleep", "1073741824"])
        nspath = "/proc/%d/ns/net" % h.pid
        for _ in range(400):
            if os.path.exists(nspath):
                break
            time.sleep(0.005)
        else:
            self.fail("netns holder did not come up")
        self._add_teardown(h)
        return h.pid

    def setup_wan(self, lan_mtu=1500, wan_mtu=1492):
        '''Build a small routed "external network" off the current (host)
        netns, so guest traffic relayed out by slirpnetstack crosses a real
        router and an MTU step-down:

            host --veth wan(mtu)-- router --veth lan(mtu)-- server

        The guest LAN (tun0) is lowered to lan_mtu so the guest<->slirp side
        negotiates a realistic MSS; the WAN links use wan_mtu. Returns a Wan
        with the server/router addresses and a run_server() helper. Must be
        called from the host netns (after isolateHostNetwork()), before prun(),
        so slirpnetstack's initial local-route scan sees the server subnet.'''
        with self.guest_netns():
            self.assertEqual(0, os.system("ip link set tun0 mtu %d" % lan_mtu))

        rtr = self._netns_holder()
        srv = self._netns_holder()

        def sh(cmd):
            self.assertEqual(0, os.system(cmd), "failed: %s" % cmd)

        def rsh(pid, cmd):
            sh("nsenter -t %d -n %s" % (pid, cmd))

        # host <-> router
        sh("ip link add wan0 type veth peer name wan1")
        sh("ip link set wan1 netns %d" % rtr)
        sh("ip addr add 198.51.100.1/30 dev wan0")
        sh("ip addr add 2001:db8:1::1/64 dev wan0 nodad")
        sh("ip link set wan0 mtu %d up" % wan_mtu)
        rsh(rtr, "ip addr add 198.51.100.2/30 dev wan1")
        rsh(rtr, "ip addr add 2001:db8:1::2/64 dev wan1 nodad")
        rsh(rtr, "ip link set wan1 mtu %d up" % wan_mtu)
        rsh(rtr, "ip link set lo up")

        # router <-> server
        sh("ip link add lan0 type veth peer name lan1")
        sh("ip link set lan0 netns %d" % rtr)
        sh("ip link set lan1 netns %d" % srv)
        rsh(rtr, "ip addr add 203.0.113.1/30 dev lan0")
        rsh(rtr, "ip addr add 2001:db8:2::1/64 dev lan0 nodad")
        rsh(rtr, "ip link set lan0 mtu %d up" % wan_mtu)
        rsh(srv, "ip addr add 203.0.113.2/30 dev lan1")
        rsh(srv, "ip addr add 2001:db8:2::2/64 dev lan1 nodad")
        rsh(srv, "ip link set lan1 mtu %d up" % wan_mtu)
        rsh(srv, "ip link set lo up")

        # router forwards; host reaches the server subnet via the router; the
        # server's default route points back at it.
        rsh(rtr, "sysctl -wq net.ipv4.ip_forward=1")
        rsh(rtr, "sysctl -wq net.ipv6.conf.all.forwarding=1")
        sh("ip route add 203.0.113.0/30 via 198.51.100.2 dev wan0")
        sh("ip -6 route add 2001:db8:2::/64 via 2001:db8:1::2 dev wan0")
        rsh(srv, "ip route add default via 203.0.113.1 dev lan1")
        rsh(srv, "ip -6 route add default via 2001:db8:2::1 dev lan1")

        # Warm up ARP/NDP end-to-end along the path slirpnetstack relays over
        # (host -> router -> server and back). Otherwise the first packet of a
        # test pays neighbor-resolution latency; cold IPv6 ND stacking across
        # two segments measures ~2s, enough to lose a single probe under a
        # short client timeout. Retry so the cache warms progressively; this
        # also sanity-checks the topology is actually wired up.
        self._warm_neighbors(Wan.server_v4)
        self._warm_neighbors(Wan.server_v6)
        return Wan(self, srv, rtr)

    def _warm_neighbors(self, ip):
        flag = "-6" if ":" in ip else ""
        cmd = "ping %s -c1 -W2 -n %s >/dev/null 2>&1" % (flag, ip)
        for _ in range(8):
            if os.system(cmd) == 0:
                return
        self.fail("host cannot reach external server %s" % ip)


class Wan(object):
    '''Handle to the external network built by TestCase.setup_wan().'''
    server_v4 = "203.0.113.2"
    server_v6 = "2001:db8:2::2"
    router_v4 = "198.51.100.2"
    router_v6 = "2001:db8:1::2"
    gateway_v4 = "10.0.2.2"
    gateway_v6 = "fd00::2"

    def __init__(self, tc, srv_pid, rtr_pid):
        self.tc = tc
        self.srv_pid = srv_pid
        self.rtr_pid = rtr_pid

    def run_server(self, argv):
        '''Run a server process inside the server netns (host filesystem),
        registered for teardown. Returns the Process.'''
        p = Process(["nsenter", "-t", str(self.srv_pid), "-n"] + argv)
        self.tc._add_teardown(p)
        return p

    def serve_file(self, directory, addr, port):
        '''Start a stdlib HTTP server in the server netns serving directory,
        and wait until it accepts connections (probed from the host netns).'''
        p = self.run_server(["python3", "-m", "http.server", str(port),
                             "--bind", addr, "--directory", directory])
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        for _ in range(400):
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(0.2)
            try:
                s.connect((addr, port))
                s.close()
                return p
            except socket.error:
                s.close()
                time.sleep(0.01)
        self.tc.fail("file server did not come up on %s:%d" % (addr, port))


def isolateHostNetwork():
    def decorate(fn):
        fn_name = fn.__name__
        @functools.wraps(fn)
        def maybe(*args, **kw):
            prev_net_fd = open("/proc/self/ns/net", 'rb')
            r = LIBC.unshare(CLONE_NEWNET)
            if r != 0:
                print('[!] Are you running within "unshare -Ur" ? Need unshare() syscall.')
                sys.exit(-1)
            # mode tun, since we don't actually plan on anyone reading the other side.
            os.system("ip link set lo up;"
                  "ip tuntap add mode tun name eth0;"
                  "ip link set eth0 mtu 65521;"
                  "ip link set eth0 up;"
                  "ip addr add 192.168.1.100/24 dev eth0;"
                  "ip addr add 3ffe::100/16 dev eth0 nodad;"
                  "ip route add 0.0.0.0/0 via 192.168.1.1 dev eth0;"
                  "ip route add ::/0 via 3ffe::1 dev eth0;")
            ret = fn(*args, **kw)
            LIBC.setns(prev_net_fd.fileno(), CLONE_NEWNET)
            prev_net_fd.close()
            return ret
        return maybe
    return decorate

def find_free_port(ip='127.0.0.1', udp=False):
    if udp == False:
        p = socket.SOCK_STREAM
    else:
        p = socket.SOCK_DGRAM

    if ':' not in ip:
        s = socket.socket(socket.AF_INET, p)
    else:
        s = socket.socket(socket.AF_INET6, p)

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, 1)
    s.bind((ip, 0))

    _, port = s.getsockname()
    s.close()
    return port
