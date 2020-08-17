// +build testrunmain

package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

type sliceString []string

func (i *sliceString) String() string {
	return strings.Join(*i, " ")
}
func (i *sliceString) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	mainStatus int
	slirpArgs  sliceString
)

// Inject our option whether go tests like it or not. Muhahaha.
func init() {
	flag.Var(&slirpArgs, "args", "Args to slirpnetstack")
}

func TestRunMain(t *testing.T) {
	mainStatus = Main("slirpnetstack", slirpArgs)
}

func TestMain(m *testing.M) {
	testStatus := m.Run()
	if testStatus != 0 {
		os.Exit(testStatus)
	} else {
		os.Exit(mainStatus)
	}
}
