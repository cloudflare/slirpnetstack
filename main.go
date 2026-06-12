package main

import (
	"os"

	"github.com/KusakabeShi/slirpnetstack/pkg/slirpnetstack"
)

func main() {
	status := slirpnetstack.Main(os.Args[0], os.Args[1:])
	os.Exit(status)
}
