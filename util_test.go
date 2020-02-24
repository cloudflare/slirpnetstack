package main

import (
	"reflect"
	"testing"
)

var dnsReadConfigTests = []struct {
	name string
	want *dnsConfig
}{
	{
		name: "tests/data/resolv.conf",
		want: &dnsConfig{
			servers:    []string{"8.8.8.8", "2001:4860:4860::8888", "fe80::1"},
			unknownOpt: true,
		},
	},
}

func TestDNSReadConfig(t *testing.T) {
	for _, tt := range dnsReadConfigTests {
		conf := dnsReadConfig(tt.name)
		if conf.err != nil {
			t.Fatal(conf.err)
		}
		if !reflect.DeepEqual(conf, tt.want) {
			t.Errorf("%s:\ngot: %+v\nwant: %+v", tt.name, conf, tt.want)
		}
	}
}
