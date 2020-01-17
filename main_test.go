// +build testrunmain

package main

import (
	"os"
	"testing"
)

var mainStatus int

func TestRunMain(t *testing.T) {
	mainStatus = Main()
}

func TestMain(m *testing.M) {
	testStatus := m.Run()
	if testStatus != 0 {
		os.Exit(testStatus)
	} else {
		os.Exit(mainStatus)
	}
}
