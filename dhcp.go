package main

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/sirupsen/logrus"

	"github.com/coredhcp/coredhcp"
	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/logger"

	"github.com/coredhcp/coredhcp/plugins"
	"github.com/coredhcp/coredhcp/plugins/dns"
	"github.com/coredhcp/coredhcp/plugins/nbp"
	rangepl "github.com/coredhcp/coredhcp/plugins/range"
	"github.com/coredhcp/coredhcp/plugins/router"
	"github.com/coredhcp/coredhcp/plugins/serverid"
)

var desiredPlugins = []*plugins.Plugin{
	&dns.Plugin,
	&rangepl.Plugin,
	&router.Plugin,
	&serverid.Plugin,
	&nbp.Plugin,
}

func setupDHCP(s *stack.Stack, state *State) error {
	log := logger.GetLogger("plugins")
	log.Logger.SetLevel(logrus.WarnLevel)
	for _, plugin := range desiredPlugins {
		if e := plugins.RegisterPlugin(plugin); e != nil {
			return e
		}
	}

	conf := config.New()
	plugins := make([]*config.PluginConfig, 0)
	plugins = append(plugins,
		&config.PluginConfig{
			Name: "range",
			Args: []string{"/dev/null",
				state.DHCPStart.String(), state.DHCPEnd.String(),
				"24h"},
		},
		&config.PluginConfig{
			Name: "router",
			Args: []string{state.Host.String()},
		},
		&config.PluginConfig{
			Name: "dns",
			Args: state.DHCPDns.servers,
		},
		&config.PluginConfig{
			Name: "server_id",
			Args: []string{state.Host.String()},
		})
	if state.DHCPNbp != "" {
		plugins = append(plugins,
			&config.PluginConfig{
				Name: "nbp",
				Args: []string{state.DHCPNbp},
			},
		)
	}
	conf.Server4 = &config.ServerConfig{
		Plugins: plugins,
	}

	server := coredhcp.NewServer(conf)
	if _, _, e := server.LoadPlugins(server.Config); e != nil {
		return e
	}

	// no IP, this will catch broadcasted packets
	addr := tcpip.FullAddress{1, "", dhcpv4.ServerPort}
	if conn, e := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber); e != nil {
		return e
	} else if server4, e := server4.NewServer("", nil, server.MainHandler4, server4.WithConn(conn)); e != nil {
		return e
	} else {
		server.Server4 = server4
	}
	go server.Server4.Serve()

	return nil
}
