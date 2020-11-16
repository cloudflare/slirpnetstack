package main

import (
	"testing"
)

func equalSlice(t *testing.T, expected, actual []string) {
	if len(expected) != len(actual) {
		t.Error("mismatching slice lengths")
	}

	for i := range expected {
		if expected[i] != actual[i] {
			t.Errorf("mismatching index %d, expected %s got %s", i, expected[i], actual[i])
		}
	}
}

func TestSplitHost(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		p := SplitHostPort("")
		equalSlice(t, []string{""}, p)
	})

	t.Run("ipv4 addr", func(t *testing.T) {
		p := SplitHostPort(":2222:[tcp.echo.server@srv-127.0.0.1:53]:0")
		equalSlice(t, []string{"", "2222", "tcp.echo.server@srv-127.0.0.1:53", "0"}, p)

		p = SplitHostPort(":2222:[tcp.echo.server@srv-[127.0.0.1]:53]:0")
		equalSlice(t, []string{"", "2222", "tcp.echo.server@srv-[127.0.0.1]:53", "0"}, p)
	})

	t.Run("ipv6 addr", func(t *testing.T) {
		p := SplitHostPort(":2222:[tcp.echo.server@srv-[::1]:53]:0")
		equalSlice(t, []string{"", "2222", "tcp.echo.server@srv-[::1]:53", "0"}, p)
	})
}
