//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const collectionCgroupRoot = "/sys/fs/cgroup"

type linuxCollectionLaneSet struct {
	root  string
	lanes []linuxCollectionLane
}

type linuxCollectionLane struct {
	path     string
	workload string
	identity collectionLaneIdentity
}

func openCollectionLaneSet(count int, isolated, caseSuite bool) (_ collectionLaneSet, resultErr error) {
	if !isolated {
		return newLocalCollectionLaneSet(count), nil
	}
	if caseSuite && count != 1 && count != collectionCaseParallelism || !caseSuite && count != 6 {
		return nil, fmt.Errorf("production collection lane count is invalid: count=%d case_suite=%t", count, caseSuite)
	}
	cpusPerLane, memoryMax, pidsMax := collectionLaneCPUs, int64(collectionLaneMemoryMaxBytes), collectionLanePIDsMax
	if caseSuite {
		cpusPerLane, memoryMax, pidsMax = collectionCaseLaneCPUs, collectionCaseMemoryMaxBytes, collectionCasePIDsMax
	}
	controllers, err := os.ReadFile(filepath.Join(collectionCgroupRoot, "cgroup.subtree_control"))
	if err != nil {
		return nil, fmt.Errorf("read delegated cgroup controllers: %w", err)
	}
	delegated := make(map[string]struct{})
	for _, controller := range strings.Fields(string(controllers)) {
		delegated[controller] = struct{}{}
	}
	for _, controller := range []string{"cpuset", "cpu", "memory", "pids"} {
		if _, exists := delegated[controller]; !exists {
			return nil, fmt.Errorf("release wrapper did not delegate cgroup controller %s", controller)
		}
	}
	allowedData, err := os.ReadFile(filepath.Join(collectionCgroupRoot, "cpuset.cpus.effective"))
	if err != nil {
		return nil, fmt.Errorf("read effective release CPU set: %w", err)
	}
	allowed, err := parseCPUSet(strings.TrimSpace(string(allowedData)))
	if err != nil {
		return nil, fmt.Errorf("parse effective release CPU set: %w", err)
	}
	laneCPUs, err := allocateCollectionLaneCPUs(allowed, count, cpusPerLane)
	if err != nil {
		return nil, err
	}
	memoryNodes, err := os.ReadFile(filepath.Join(collectionCgroupRoot, "cpuset.mems.effective"))
	if err != nil || strings.TrimSpace(string(memoryNodes)) == "" {
		return nil, errors.New("release runner has no effective cgroup memory nodes")
	}
	root := filepath.Join(collectionCgroupRoot, fmt.Sprintf("flowersec-transport-%d", os.Getpid()))
	if err := os.Mkdir(root, 0o755); err != nil {
		return nil, fmt.Errorf("create collection cgroup: %w", err)
	}
	set := &linuxCollectionLaneSet{root: root, lanes: make([]linuxCollectionLane, count)}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, set.Close())
		}
	}()
	if err := writeCgroupValue(root, "cpuset.cpus", formatCPUSet(allowed)); err != nil {
		return nil, err
	}
	if err := writeCgroupValue(root, "cpuset.mems", strings.TrimSpace(string(memoryNodes))); err != nil {
		return nil, err
	}
	if err := writeCgroupValue(root, "cgroup.subtree_control", "+cpuset +cpu +memory +pids"); err != nil {
		return nil, err
	}
	for index := range set.lanes {
		path := filepath.Join(root, fmt.Sprintf("lane-%d", index))
		if err := os.Mkdir(path, 0o755); err != nil {
			return nil, err
		}
		cpus := formatCPUSet(laneCPUs[index])
		laneCPUCount := len(laneCPUs[index])
		for name, value := range map[string]string{
			"cpuset.cpus": cpus, "cpuset.mems": strings.TrimSpace(string(memoryNodes)),
			"cpu.max": strconv.Itoa(laneCPUCount*100000) + " 100000", "memory.high": strconv.FormatInt(memoryMax, 10),
			"memory.max": strconv.FormatInt(memoryMax, 10), "memory.swap.max": "0",
			"memory.oom.group": "1", "pids.max": strconv.Itoa(pidsMax),
		} {
			if err := writeCgroupValue(path, name, value); err != nil {
				return nil, fmt.Errorf("configure collection lane %d: %w", index, err)
			}
		}
		if err := writeCgroupValue(path, "cgroup.subtree_control", "+cpuset +cpu +memory +pids"); err != nil {
			return nil, fmt.Errorf("delegate collection lane %d controllers: %w", index, err)
		}
		workload := filepath.Join(path, "workload")
		if err := os.Mkdir(workload, 0o755); err != nil {
			return nil, fmt.Errorf("create collection lane %d workload: %w", index, err)
		}
		set.lanes[index] = linuxCollectionLane{path: path, workload: workload, identity: collectionLaneIdentity{
			Index: index, CPUSet: cpus, MemoryMaxBytes: memoryMax, PIDsMax: pidsMax,
		}}
	}
	return set, nil
}

func (set *linuxCollectionLaneSet) Lane(index int) collectionLaneRuntime { return &set.lanes[index] }

func (set *linuxCollectionLaneSet) Close() error {
	if set == nil || set.root == "" {
		return nil
	}
	var result error
	for index := len(set.lanes) - 1; index >= 0; index-- {
		path := set.lanes[index].path
		if path == "" {
			continue
		}
		populated, populatedErr := collectionCgroupPopulated(path)
		if populatedErr != nil {
			result = errors.Join(result, fmt.Errorf("read collection lane %d population: %w", index, populatedErr))
		}
		if populated {
			result = errors.Join(result, fmt.Errorf("collection lane %d retained processes after runner exit", index))
			_ = writeCgroupValue(path, "cgroup.kill", "1")
		}
		for attempt := 0; attempt < 20; attempt++ {
			if err := removeCollectionCgroupTree(path); err == nil || errors.Is(err, os.ErrNotExist) {
				break
			} else if attempt == 19 {
				result = errors.Join(result, fmt.Errorf("remove collection lane %d cgroup: %w", index, err))
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	if err := os.Remove(set.root); err != nil && !errors.Is(err, os.ErrNotExist) {
		result = errors.Join(result, fmt.Errorf("remove collection cgroup: %w", err))
	}
	set.root = ""
	return result
}

func collectionCgroupPopulated(path string) (bool, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			return fields[1] == "1", nil
		}
	}
	return false, errors.New("cgroup.events has no populated state")
}

func removeCollectionCgroupTree(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if err := removeCollectionCgroupTree(filepath.Join(path, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Remove(path)
}

func (lane *linuxCollectionLane) Identity() collectionLaneIdentity { return lane.identity }

func (lane *linuxCollectionLane) Command(ctx context.Context, executable string, args ...string) *exec.Cmd {
	arguments := []string{"-c", `printf '%s\n' "$$" > "$FLOWERSEC_LANE_CGROUP/workload/cgroup.procs" && exec "$@"`, "flowersec-lane", executable}
	arguments = append(arguments, args...)
	command := exec.CommandContext(ctx, "/bin/sh", arguments...)
	command.Env = append(os.Environ(), "FLOWERSEC_LANE_CGROUP="+lane.path, "GOMAXPROCS="+strconv.Itoa(len(strings.Split(lane.identity.CPUSet, ","))))
	return command
}

func writeCgroupValue(root, name, value string) error {
	if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0o600); err != nil {
		return fmt.Errorf("write cgroup %s: %w", name, err)
	}
	return nil
}
