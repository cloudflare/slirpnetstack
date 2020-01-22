package main

import (
	"fmt"
	"runtime"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

func joinNetNS(nsPath string, run func()) error {
	ch := make(chan error, 2)
	go func() {
		runtime.LockOSThread()
		_, err := specutils.ApplyNS(specs.LinuxNamespace{
			Type: specs.NetworkNamespace,
			Path: nsPath,
		})
		if err != nil {
			runtime.UnlockOSThread()
			ch <- fmt.Errorf("joining net namespace %q: %v", nsPath, err)
			return
		}
		run()
		ch <- nil
	}()
	// Here is a big hack. Avoid restoring netns. Allow golang to
	// reap the thread, by not calling runtime.UnlockOSThread().
	// This will avoid any errors from restoreNS().

	err := <-ch
	return err
}
