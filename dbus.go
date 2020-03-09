package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func getInfo(tcpep tcpip.Endpoint) *stack.TransportEndpointInfo {
	switch t := tcpep.Info().(type) {
	case *stack.TransportEndpointInfo:
		return t
	case *tcp.EndpointInfo:
		return &t.TransportEndpointInfo
	default:
		fmt.Fprintf(os.Stderr, "unexpected type %T\n", t)
		return nil
	}

}

func (s *State) GetInfo() (string, *dbus.Error) {
	var b strings.Builder

	fmt.Fprintf(&b, "Protocol[State]      Source Address  Port   Dest. Address  Port\n")
	teps := s.stack.RegisteredEndpoints()
	for _, tep := range teps {
		ep := tep.(tcpip.Endpoint)
		tepi := getInfo(ep)
		if tepi == nil {
			continue
		}

		transName := "unknown"
		state := ""
		switch tepi.TransProto {
		case header.UDPProtocolNumber:
			transName = "UDP"
			state = udp.EndpointState(ep.State()).String()
		case header.TCPProtocolNumber:
			transName = "TCP"
			state = tcp.EndpointState(ep.State()).String()
		}

		protocolState := transName + "[" + state + "]"
		fmt.Fprintf(&b, "%-19v %15v %5v %15v %5v\n",
			protocolState,
			tepi.ID.RemoteAddress, tepi.ID.RemotePort,
			tepi.ID.LocalAddress, tepi.ID.LocalPort)
	}
	return b.String(), nil
}

type forwardEntry struct {
	Network  string
	Addr     string
	Port     uint16
	HostAddr string
	HostPort uint16
}

func (s *State) RemoveRemoteForward(addr string) *dbus.Error {
	var fwa FwdAddr

	if err := fwa.Set(addr); err != nil {
		return dbus.MakeFailedError(err)
	}

	fwa.SetDefaultAddr(netParseIP("10.0.2.2"), netParseIP("127.0.0.1"))

	if err := s.removeRemoteFwd(&fwa); err != nil {
		return dbus.MakeFailedError(err)
	}

	return nil
}

func (s *State) AddRemoteForward(addr string) *dbus.Error {
	var fwa FwdAddr

	if err := fwa.Set(addr); err != nil {
		return dbus.MakeFailedError(err)
	}

	fwa.SetDefaultAddr(netParseIP("10.0.2.2"), netParseIP("127.0.0.1"))

	err := s.addRemoteFwd(&fwa)
	if err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func (s *State) RemoveLocalForward(addr string) *dbus.Error {
	var fwa FwdAddr

	if err := fwa.Set(addr); err != nil {
		return dbus.MakeFailedError(err)
	}

	fwa.SetDefaultAddr(netParseIP("127.0.0.1"), netParseIP("10.0.2.100"))

	if err := s.removeLocalFwd(&fwa); err != nil {
		return dbus.MakeFailedError(err)
	}

	return nil
}

func (s *State) AddLocalForward(addr string) *dbus.Error {
	var fwa FwdAddr

	if err := fwa.Set(addr); err != nil {
		return dbus.MakeFailedError(err)
	}

	fwa.SetDefaultAddr(netParseIP("127.0.0.1"), netParseIP("10.0.2.100"))

	err := s.addLocalFwd(&fwa)
	if err != nil {
		return dbus.MakeFailedError(err)
	}
	return nil
}

func getForwardList(m map[string]*FwdAddr) []forwardEntry {
	e := []forwardEntry{}
	for _, b := range m {
		e = append(e, forwardEntry{
			b.network,
			b.bind.Addr.String(),
			b.bind.Port,
			b.host.Addr.String(),
			b.host.Port,
		})
	}
	return e
}

func (s *State) ListRemoteForward() ([]forwardEntry, *dbus.Error) {
	e := getForwardList(s.remoteTcpFwd)
	e = append(e, getForwardList(s.remoteUdpFwd)...)
	return e, nil
}

func (s *State) ListLocalForward() ([]forwardEntry, *dbus.Error) {
	e := getForwardList(s.localTcpFwd)
	e = append(e, getForwardList(s.localUdpFwd)...)
	return e, nil
}

func (s *State) Quit() *dbus.Error {
	s.quitCh <- true
	return nil
}

func connect(addr string) (*dbus.Conn, error) {
	conn, err := dbus.Dial(addr)
	if err != nil {
		return nil, err
	}
	if err = conn.Auth(nil); err != nil {
		return nil, err
	}
	if err = conn.Hello(); err != nil {
		return nil, err
	}

	return conn, nil
}

func setupDBus(state *State, addr string) error {
	if addr == "" {
		return nil
	}

	conn, err := connect(addr)
	if err != nil {
		return err
	}

	conn.Export(state, "/org/freedesktop/SlirpHelper1", "org.freedesktop.SlirpHelper1")
	n := &introspect.Node{
		Name: "/org/freedesktop/SlirpHelper1",
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    "org.freedesktop.SlirpHelper1",
				Methods: introspect.Methods(state),
			},
		},
	}
	conn.Export(introspect.NewIntrospectable(n), "/org/freedesktop/SlirpHelper1",
		"org.freedesktop.DBus.Introspectable")

	if reply, err := conn.RequestName(
		fmt.Sprintf("org.freedesktop.Slirp1_%d", os.Getpid()),
		dbus.NameFlagDoNotQueue); err != nil {
		return err
	} else if reply != dbus.RequestNameReplyPrimaryOwner {
		return errors.New("DBus name already taken")
	}

	state.dbus = conn
	return nil
}
