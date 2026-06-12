package slirpnetstack

import (
	"testing"
)

func TestReconcileGateway(t *testing.T) {
	cases := []struct {
		name     string
		natRange string
		gwAddr   string
		wantNat  string
		wantGw   string
		wantErr  bool
	}{
		{
			name:     "ipv4 derive from natRange host",
			natRange: "10.0.2.2/24",
			gwAddr:   "",
			wantNat:  "10.0.2.2/24",
			wantGw:   "10.0.2.2",
		},
		{
			name:     "ipv6 derive from natRange host",
			natRange: "fd00::2/64",
			gwAddr:   "",
			wantNat:  "fd00::2/64",
			wantGw:   "fd00::2",
		},
		{
			name:     "ipv4 gw overrides natRange host, keeps prefix",
			natRange: "10.0.2.7/24",
			gwAddr:   "10.0.2.3",
			wantNat:  "10.0.2.3/24",
			wantGw:   "10.0.2.3",
		},
		{
			name:     "ipv6 gw overrides natRange host, keeps prefix",
			natRange: "fd00::2/64",
			gwAddr:   "fd00::5",
			wantNat:  "fd00::5/64",
			wantGw:   "fd00::5",
		},
		{
			name:     "ipv4 gw outside natRange subnet errors",
			natRange: "10.0.2.2/24",
			gwAddr:   "10.0.3.3",
			wantErr:  true,
		},
		{
			name:     "ipv6 gw outside natRange subnet errors",
			natRange: "fd00::2/64",
			gwAddr:   "fd01::5",
			wantErr:  true,
		},
		{
			name:     "invalid nat range errors",
			natRange: "not-a-cidr",
			gwAddr:   "",
			wantErr:  true,
		},
		{
			name:     "invalid gateway errors",
			natRange: "10.0.2.2/24",
			gwAddr:   "not-an-ip",
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotNat, gotGw, err := reconcileGateway(tc.natRange, tc.gwAddr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nat=%q gw=%q", gotNat, gotGw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if gotNat != tc.wantNat {
				t.Errorf("natRange: expected %q got %q", tc.wantNat, gotNat)
			}
			if gotGw != tc.wantGw {
				t.Errorf("gwAddr: expected %q got %q", tc.wantGw, gotGw)
			}
		})
	}
}
