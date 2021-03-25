[![Build Status](https://travis-ci.org/majek/slirpnetstack.svg?branch=master)](https://travis-ci.org/majek/slirpnetstack) [![Coverage Status](https://coveralls.io/repos/github/majek/slirpnetstack/badge.svg?branch=master)](https://coveralls.io/github/majek/slirpnetstack?branch=master)

slirpnetstack
=============

User-mode networking for unprivileged network namespaces.


First take a look at slirp4netns project:

 - https://github.com/rootless-containers/slirp4netns


The general idea of this code is to:

 - Acquire a handle to a network namespace used by someone else, like
   a container.
 - Open a tun/tap device living there.
 - Receive/send L3 packets from/to that namespace processes.

The magic happens with these L3 packets - slirpnetstack uses a
user-space (unprivileged) network stack. It is able to terminate
network connections and translate them into syscalls.

Therefore, a received SYN from guest network namespace becomes
connect() in the host kernel namespace. L3 UDP packet becomes
sendto(), and so on.

slirpnetstack can do three things:

 - It can "route" connections exiting guest namespace, to internet
   provided by host namespace. This is useful to give internet access
   to guest. Classical SLIRP use case.

 - It can "local forward" connections. It will bind to host ip/port,
   and open a new connection directing it to guest. This is useful to
   expose services living inside guest to outside world.

 - It can "remote forward" connections. It will bind to guest ip/port,
   and open new host connection for each new one in guest. This is
   useful to expose host services to guest.

Why not libslirp?
----------------

Libslirp is a good and mature piece of software, used by many. Sadly,
it suffers occasional security problems:

 - https://github.com/rootless-containers/slirp4netns/security/advisories

Furthermore it is based on ancient networking stack, so adding modern
features like IPv6 or window scaling is difficult. There has been many
user-space networking stacks created recently, but neither seem to be
fitting the slirp use case.

Non-features of slirpnetstack
-----------------------------

Broken things:

 - ping - icmp echo request - are terminated locally.
 - udp requires connection tracking, therefore is hard to do in
   general. Timeouts are arbitrary.
 - gvisor/netstack has some implementation issues, so of course this
   project inhertits them.

Networking topology
-------------------

Slirpnetstack assumes that the namespace will have the following IP's:

  - `10.0.2.100/24` for IPv4
  - `[fd00::100]/64` for IPv6

And that the guest will use the following IP's as default routes:

  - `10.0.2.2` for IPv4
  - `[fd00::2]` for IPv6

In other words, Slirpnetstack listens on these IP's and will handle
traffic routed to it.


Usage with custom network namespace
-----------------------------------

Before you start, you need a guest network namespace handle. This is
usually a /proc/<pid>/ns/net path. You can create such a namespace
with this command - notice, it doesn't require root:

    marek@:~$ unshare -Urn
    root@:~#

This will give you full permissions to do stuff inside a net
namespace. Now you must configure it:

```
ip link set lo up
ip tuntap add mode tap name tun0
ip link set tun0 mtu 65521
ip link set tun0 up
ip addr add 10.0.2.100/24 dev tun0
ip addr add fd00::100/64 dev tun0
ip route add 0.0.0.0/0 via 10.0.2.2 dev tun0
ip route add ::/0 via fd00::2 dev tun0
```

Finally, you need a pid of the process having this namespace. Easiest
is to type "echo $$", like:

    root@:~# echo $$
    31530

Alternatively you can use "lsns" from host:

    marek@:~$ lsns -t net | grep -- -bash
    4026533150 net 2 31530 marek -bash

Now you can run slirpnetstack:

    sudo ./bin/slirpnetstack -interface tun0 -netns /proc/31530/ns/net


Usage with gvisor
-----------------

Perhaps a more powerful way is to see slirpnetstack in action with
gvisor. To avoid docker magic we can use OCI gvisor interface. See the
script:

   - https://github.com/cloudflare/slirpnetstack/blob/master/test-gvisor.sh

Once you run it, you will see:

```
marek@$ sudo bash test-gvisor.sh
[*] Starting gvisor
To enter the container run:
    runsc --net-raw exec --console-socket /tmp/pty.sock hello bash
[*] Running slirpnetstack
[.] Joininig netns /proc/8519/ns/net
[.] Opening tun interface tun0
[.] Restoring root netns
[+] #8578 Started
```

From now on you should have internet connectivity in the isolated
gvisor container, supplied by slirpnetstack.


Routing security
----------------

By default the guest is totally locked. No traffic from the guest can
exit to the host unless allowed explicitly with local forwarding rules
or --allow statements.

There are two options --deny --allow that can override the more
generic firewall settings for specific IP prefixes and port
ranges. For example, to allow some connectivity:

 --allow=udp://192.168.1.0/24:53-53

This would allow connectivity to any IP in the given 192.168.1.0/24 network
prefix and in the port range of 53-53 ports (one port in this case)
over protocol UDP. `--deny` takes precedence over `--allow`.

There are three toggles:

--enable-routing allows routing to non-local IP's. Connectivity to the
peers outside the host machine will work, but IP ranges that are on
the host or attached to any of it's network interfaces will be
blocked. This is to avoid connections to 192.168.0.0/24 style ranges
if they are in use on the host.

--enable-host allows routing to host-bound IP ranges like the
192.168.0.0/24 shown above. The code scrapes the local interfaces and
builds the list every 30 seconds. This option is considered insecure
and will allow guest to connect to resources on host.

Even in such case, for sanity we block traffic to the following IP
prefixes:

 - 0.0.0.0/8
 - 10.0.2.0/24
 - 127.0.0.0/8
 - 255.255.255.255/32
 - ::/128
 - ::1/128
 - ::/96
 - ::ffff:0:0:0/96
 - 64:ff9b::/96


Development
-----------

You can run tests with:

    make tests

Or tests with code coverage

    make cover

You can get HTML report with

    make cover HTML=1

Finally, to run standalone test:

    SLIRPNETSTACKBIN=./bin/slirpnetstack \
        unshare -Ur \
        python3 -m unittest tests.test_basic.RoutingTestSecurity.test_remote_srv


Updating netstack/gvisor
------------------------

To update netstack dependency try running:

    make update-gomod

This sometimes works, but when it fails it's messy. In such case,
clone `gvisor` repo, check out `origin/go` branch to get the
golang-consumable code and point to it by adding this line to
`go.mod`. This is useful in bisecting netstack issues:

    replace gvisor.dev/gvisor => ../../src/gvisor
