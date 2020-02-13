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
import tempfile
import unittest

from scapy.all import StreamSocket, sndrcv, Ether, conf, Route, ARP

LIBC = ctypes.CDLL("libc.so.6")
SLIRPNETSTACKBIN = os.environ.get('SLIRPNETSTACKBIN')
DEBUG = bool(os.environ.get('DEBUG'))
CLONE_NEWNET = 0x40000000
ORIGINAL_NET_NS = open("/proc/self/ns/net", 'rb')
MOCKHTTPSERVER  = os.environ.get('MOCKHTTPSERVER', './tests/mockhttpserver/mockhttpserver')
MOCKUDPECHO  = os.environ.get('MOCKUDPECHO', './bin/mockudpecho')
MOCKTCPECHO  = os.environ.get('MOCKTCPECHO', './bin/mocktcpecho')
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

        a = argv0 + argv1
        if netns:
            a = a + ["-netns", self.net_ns_path()]
        p = Process(a, close_fds=close_fds)
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
                  "ip addr add 2001:2::100/32 dev tun0 nodad;"
                  "ip route add 0.0.0.0/0 via 10.0.2.2 dev tun0;"
                  "ip route add ::/0 via 2001:2::2 dev tun0;")
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

    def assertTcpTimeout(self, ip, port):
        with self.assertRaises(socket.timeout) as e:
            s = utils.connect(ip, port, cleanup=self)
            s.recv(1024)

    def assertStartSync(self, p, fd=False):
        if not fd:
            self.assertIn("[.] Join", p.stderr_line())
            self.assertIn("[.] Opening tun", p.stderr_line())
        self.assertIn("Started", p.stderr_line())

    def assertListenLine(self, p, in_pattern):
        line = p.stdout_line().strip()
        self.assertIn(in_pattern, line)
        return int(line.split(":")[-1])


def withFd():
    def decorate(fn):
        fn_name = fn.__name__
        @functools.wraps(fn)
        def maybe(*args, **kw):
            sp = socket.socketpair(type=socket.SOCK_DGRAM)
            os.set_inheritable(sp[0].fileno(), True)
            self = args[0]
            p = self.prun("-fd %d" % sp[0].fileno(), close_fds=False, netns=False)
            self.assertStartSync(p, fd=True)
            kw['fd'] = sp[1]
            ret = fn(*args, **kw)
            sp[0].close()
            sp[1].close()
            return ret
        return maybe
    return decorate


class testScapySocket(object):
    def __init__(self, fd):
        ss = StreamSocket(fd)
        ss.basecls = Ether
        self.ss = ss
        conf.route = Route() # reinitializes the route based on the NS
        # send a gratious ARP to tell our MAC/IP
        arp = ARP()
        self.e = Ether(src=arp.hwsrc, dst='70:71:aa:4b:29:aa')
        self.send(arp)

    def send(self, x):
        self.ss.send(self.e / x)

    def recv(self, x):
        # this is not symmetrical with send, which appends Ether
        # header, but ss.basecls will strip it of: not sure if that's
        # the best way of doing things in fact, but that seem to work..
        return self.ss.recv(x)

    def fileno(self):
        return self.ss.fileno()

    def sr1(self, x, checkIPaddr=True, *args, **kwargs):
        conf.checkIPaddr = checkIPaddr
        ans, _ = sndrcv(self.ss, self.e / x, *args, **kwargs)
        return ans[0][1]

    def sr(self, x, checkIPaddr=True, *args, **kwargs):
        conf.checkIPaddr = checkIPaddr
        return sndrcv(self.ss, self.e / x, *args, **kwargs)


def withScapy():
    def decorate(fn):
        fn_name = fn.__name__
        @functools.wraps(fn)
        def maybe(*args, **kw):
            sp = socket.socketpair(type=socket.SOCK_DGRAM)
            os.set_inheritable(sp[0].fileno(), True)
            self = args[0]
            arg = kw.pop('parg', '')
            p = self.prun(arg + " -fd %d" % sp[0].fileno(), close_fds=False, netns=False)
            self.assertStartSync(p, fd=True)
            kw['s'] = testScapySocket(sp[1])
            ret = fn(*args, **kw)
            sp[0].close()
            sp[1].close()
            return ret
        return maybe
    return decorate


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
