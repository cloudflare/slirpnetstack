#!/bin/bash

RUNSC="XXX/runsc"
GVFLAGS="--net-raw"
SLIRPNETSTACK="./bin/slirpnetstack"

if [ ! -f config.json ]; then
    ${RUNSC} spec
    EXTRA_CAPS='"CAP_SETGID", "CAP_SETUID", "CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_RAW"'
    sed -i "s#\(\"CAP_NET_BIND_SERVICE\"\)#\1, ${EXTRA_CAPS}#" config.json
    sed -i 's#readonly": true#readonly": false#' config.json
    sed -i 's#\("TERM=xterm"\)#\1,\n"DEBIAN_FRONTEND=noninteractive"#' config.json
fi

if [ ! -d rootfs ]; then
    mkdir rootfs
    docker export $(docker create ubuntu:bionic) | tar -xf - -C rootfs
    echo "nameserver 1.1.1.1" > rootfs/etc/resolv.conf
fi

${RUNSC} kill hello || true
${RUNSC} delete hello || true

ulimit -n 1048576
${RUNSC} ${GVFLAGS} create hello

NSPID=`${RUNSC} state hello | jq .pid`
nsenter -n -t ${NSPID} bash -c " \
	ip link set lo up; \
	ip tuntap add mode tap name tun0; \
	ip link set tun0 mtu 65521; \
	ip link set tun0 up; \
	ip addr add 10.0.2.100/24 dev tun0; \
	ip route add 0.0.0.0/0 via 10.0.2.2 dev tun0;"

# IPv6 support
if [ ]; then
    nsenter -n -t ${NSPID} bash -c " \
            ip addr add 2001:2::100/32 dev tun0; \
            ip route add ::/0 via 2001:2::2 dev tun0;"
fi

echo "[*] Starting gvisor"
${RUNSC} ${GVFLAGS} start hello

echo "To enter the container run:"
echo "    ${RUNSC} ${GVFLAGS} exec --console-socket /tmp/pty.sock hello bash"

echo "[*] Running slirpnetstack"
${SLIRPNETSTACK} -interface tun0 -netns /proc/${NSPID}/ns/net
