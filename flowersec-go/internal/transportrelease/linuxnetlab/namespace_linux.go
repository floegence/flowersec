//go:build linux

package linuxnetlab

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func RequireCurrentNamespace(namespace string) error {
	if !identifierPattern.MatchString(namespace) {
		return errors.New("valid network namespace is required")
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("stat current network namespace: %w", err)
	}
	target, err := os.Stat("/var/run/netns/" + namespace)
	if err != nil {
		return fmt.Errorf("stat target network namespace: %w", err)
	}
	if !os.SameFile(current, target) {
		return errors.New("network worker did not start in the requested client namespace")
	}
	return nil
}

// InNamespace runs fn on one locked OS thread in the named network namespace
// and restores the original namespace before the thread returns to the runtime.
func InNamespace(namespace string, fn func() error) (resultErr error) {
	if !identifierPattern.MatchString(namespace) || fn == nil {
		return errors.New("valid network namespace and callback are required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	original, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open current network namespace: %w", err)
	}
	defer unix.Close(original)
	target, err := unix.Open("/var/run/netns/"+namespace, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open target network namespace: %w", err)
	}
	defer unix.Close(target)
	if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter network namespace: %w", err)
	}
	defer func() {
		if err := unix.Setns(original, unix.CLONE_NEWNET); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restore network namespace: %w", err))
		}
	}()
	return fn()
}
