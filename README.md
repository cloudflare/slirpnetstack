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

Therefore, received SYN from guest network namespace becomes connect()
in the host kernel namespace. L3 UDP packet becomes sendto(), and so
on.

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


Usage
-----

Before you start, you need a guest network namespace handle. This is
usually a /proc/<pid>/ns/net path. You can create such a namespace
with this command - notice, it doesn't require root:

    $ unshare -Urn

This will give you full permissions to do stuff inside a net
namespace. Now you must configure it:

```
ip link set lo up
ip tuntap add mode tap name tun0
ip link set tun0 mtu 65521
ip link set tun0 up
ip addr add 10.0.2.100/24 dev tun0
ip addr add 2001:2::100/32 dev tun0
ip route add 0.0.0.0/0 via 10.0.2.2 dev tun0
ip route add ::/0 via 2001:2::2 dev tun0
```

Finally, you need a pid of the process having this namespace. Easiest
is to type "echo $$", like:

    root@:~# echo $$
    31530

Alternatively you can use "lsns" from host:

    marek@:~$ sudo lsns -t net --raw|grep -- -bash
    4026533150 net 2 31530 marek -bash

Now you can run slirpnetstack:

    sudo ./bin/slirpnetstack -interface tun0 -netns /proc/31530/ns/net


