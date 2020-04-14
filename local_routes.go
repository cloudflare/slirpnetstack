package main

import (
	"github.com/vishvananda/netlink"
	"gopkg.in/netaddr.v1"
	"net"
	"sync"
	"time"
)

type LocalRoutes struct {
	sync.RWMutex
	ipset  *netaddr.IPSet
	ticker *time.Ticker
	done   chan bool
}

func (lr *LocalRoutes) Contains(ip net.IP) bool {
	lr.RLock()
	r := lr.ipset.Contains(ip)
	lr.RUnlock()
	return r
}

func (lr *LocalRoutes) Start(interval time.Duration) {
	lr.Lock()
	lr.ticker = time.NewTicker(interval)
	lr.done = make(chan bool)
	lr.ipset = FetchLocalRoutes()
	lr.Unlock()
	go func() {
		for {
			lr.Lock()
			lr.ipset = FetchLocalRoutes()
			lr.Unlock()
			select {
			case <-lr.done:
				return
			case <-lr.ticker.C:
			}
		}
	}()
}

func (lr *LocalRoutes) Stop() {
	lr.Lock()
	close(lr.done)
	lr.Unlock()
}

// Regularly load "local" and "main" routing tables, for both IPv4 and
// IPv6. The idea is to refuse connections to IP ranges that might be
// local.
func FetchLocalRoutes() *netaddr.IPSet {
	ipset := netaddr.IPSet{}

	// "local" routing table
	fltr := netlink.Route{Table: 255}
	routes, _ := netlink.RouteListFiltered(0, &fltr, netlink.RT_FILTER_TABLE)
	for _, r := range routes {
		if r.Dst != nil {
			ipset.InsertNet(r.Dst)
		}
	}

	// "main" routing table
	fltr = netlink.Route{Table: 254}
	routes, _ = netlink.RouteListFiltered(0, &fltr, netlink.RT_FILTER_TABLE)
	for _, r := range routes {
		if r.Dst != nil {
			ipset.InsertNet(r.Dst)
		}
	}

	return &ipset
}
