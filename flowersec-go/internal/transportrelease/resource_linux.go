//go:build linux

package transportrelease

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func capturePlatformResources() (platformResources, error) {
	statm, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return platformResources{}, fmt.Errorf("read process statm: %w", err)
	}
	fields := strings.Fields(string(statm))
	if len(fields) < 2 {
		return platformResources{}, fmt.Errorf("process statm has %d fields", len(fields))
	}
	residentPages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return platformResources{}, fmt.Errorf("parse resident pages: %w", err)
	}
	openFDs, err := countProcEntries("/proc/self/fd")
	if err != nil {
		return platformResources{}, fmt.Errorf("count process file descriptors: %w", err)
	}
	tasks, err := countProcEntries("/proc/self/task")
	if err != nil {
		return platformResources{}, fmt.Errorf("count process tasks: %w", err)
	}
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return platformResources{}, fmt.Errorf("read process CPU usage: %w", err)
	}
	return platformResources{
		rssBytes:       residentPages * uint64(os.Getpagesize()),
		cpuNanoseconds: timevalNanoseconds(usage.Utime) + timevalNanoseconds(usage.Stime),
		openFDs:        openFDs,
		tasks:          tasks,
	}, nil
}

func countProcEntries(path string) (int, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func timevalNanoseconds(value syscall.Timeval) uint64 {
	return uint64(value.Sec)*1_000_000_000 + uint64(value.Usec)*1_000
}
