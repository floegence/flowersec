package linuxnetlab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RecoverOwnedStaleResources removes only resources whose names carry the
// calling test's stable owner prefix. Tests call this before creating a run.
func RecoverOwnedStaleResources(ctx context.Context, runner CommandRunner, testID string) error {
	if runner == nil || !identifierTestIDPattern.MatchString(testID) {
		return errors.New("stale-resource recovery input is invalid")
	}
	owner := resourceOwnerPrefix(testID)
	namespaces, err := ownedEntries("/var/run/netns", []string{"fc-" + owner, "fs-" + owner, "fr-" + owner})
	if err != nil {
		return err
	}
	pins, err := ownedEntries(bpfPinRoot, []string{"flowersec-fc-" + owner})
	if err != nil {
		return err
	}
	return recoverOwnedEntries(ctx, runner, testID, namespaces, pins)
}

func recoverOwnedEntries(ctx context.Context, runner CommandRunner, testID string, namespaces, pins []string) error {
	owner := resourceOwnerPrefix(testID)
	var result error
	for _, pin := range pins {
		if !strings.HasPrefix(pin, "flowersec-fc-"+owner) || filepath.Base(pin) != pin {
			return errors.New("stale BPF pin is outside the test ownership prefix")
		}
		result = errors.Join(result, runner.Run(ctx, "rm", "-rf", "--", filepath.Join(bpfPinRoot, pin)))
	}
	for _, namespace := range namespaces {
		owned := false
		for _, prefix := range []string{"fc-" + owner, "fs-" + owner, "fr-" + owner} {
			owned = owned || strings.HasPrefix(namespace, prefix)
		}
		if !owned || filepath.Base(namespace) != namespace {
			return errors.New("stale namespace is outside the test ownership prefix")
		}
		result = errors.Join(result, runner.Run(ctx, "ip", "netns", "del", namespace))
	}
	return result
}

var identifierTestIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9/-]*$`)

func ownedEntries(directory string, prefixes []string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list stale resources in %s: %w", directory, err)
	}
	var result []string
	for _, entry := range entries {
		name := entry.Name()
		for _, prefix := range prefixes {
			if strings.HasPrefix(name, prefix) {
				result = append(result, name)
				break
			}
		}
	}
	return result, nil
}
