package performance

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const linuxProcClockTicksPerSecond = 100

var errLinuxProcessTreeSnapshotIncomplete = errors.New("process-tree resource snapshot is incomplete")

type linuxProcessTreeSnapshot struct {
	At                  time.Time `json:"at"`
	RootPID             int       `json:"root_pid"`
	PGID                int       `json:"pgid"`
	RSSBytes            uint64    `json:"rss_bytes"`
	CPUNanoseconds      uint64    `json:"cpu_nanoseconds"`
	OpenFDs             int       `json:"open_fds"`
	Tasks               int       `json:"tasks"`
	ProcessCount        int       `json:"process_count"`
	ZombieProcesses     int       `json:"zombie_processes"`
	CgroupMemoryCurrent uint64    `json:"cgroup_memory_current_bytes,omitempty"`
	CgroupMemoryPeak    uint64    `json:"cgroup_memory_peak_bytes,omitempty"`
	CgroupPIDsCurrent   int       `json:"cgroup_pids_current,omitempty"`
	SampledRSSPeak      uint64    `json:"sampled_rss_peak_bytes,omitempty"`
	AccountingMode      string    `json:"accounting_mode"`
	FallbackReason      string    `json:"fallback_reason,omitempty"`
	SampleIntervalMS    int       `json:"sample_interval_ms,omitempty"`
}

type linuxProcessTreeSampler struct {
	procRoot       string
	rootPID        int
	pgid           int
	rootStartTicks uint64
	pageSize       uint64
	cgroupPath     string
	fallbackReason string

	sampleMu     sync.Mutex
	knownCPU     map[linuxProcessIdentity]uint64
	retiredTicks uint64
	peakRSS      uint64
	cgroupPeak   uint64
	stop         chan struct{}
	done         chan struct{}
}

type linuxProcessIdentity struct {
	pid        int
	startTicks uint64
}

type linuxProcStat struct {
	pid         int
	ppid        int
	pgid        int
	state       byte
	userTicks   uint64
	systemTicks uint64
	startTicks  uint64
}

func newLinuxProcessTreeSampler(pid int, cgroupPath string, fallbackReason ...string) (*linuxProcessTreeSampler, error) {
	if pid <= 0 {
		return nil, errors.New("process-tree sampler requires a positive root PID")
	}
	stat, err := readLinuxProcStat("/proc", pid)
	if err != nil {
		return nil, fmt.Errorf("read process-tree root: %w", err)
	}
	sampler := &linuxProcessTreeSampler{
		procRoot: "/proc", rootPID: pid, pgid: stat.pgid, rootStartTicks: stat.startTicks, pageSize: uint64(os.Getpagesize()),
		cgroupPath: cgroupPath, knownCPU: make(map[linuxProcessIdentity]uint64), stop: make(chan struct{}), done: make(chan struct{}),
	}
	if len(fallbackReason) > 0 {
		sampler.fallbackReason = fallbackReason[0]
	}
	go sampler.runResourceSampler()
	return sampler, nil
}

func (sampler *linuxProcessTreeSampler) Snapshot() (linuxProcessTreeSnapshot, error) {
	return retryLinuxProcessTreeSnapshot(func() (linuxProcessTreeSnapshot, error) {
		sampler.sampleMu.Lock()
		defer sampler.sampleMu.Unlock()
		return sampler.snapshotLocked()
	}, time.Sleep)
}

func retryLinuxProcessTreeSnapshot(
	capture func() (linuxProcessTreeSnapshot, error),
	wait func(time.Duration),
) (linuxProcessTreeSnapshot, error) {
	const attempts = 40
	for attempt := 0; attempt < attempts; attempt++ {
		snapshot, err := capture()
		if !errors.Is(err, errLinuxProcessTreeSnapshotIncomplete) || attempt == attempts-1 {
			return snapshot, err
		}
		wait(25 * time.Millisecond)
	}
	panic("unreachable")
}

func (sampler *linuxProcessTreeSampler) snapshotLocked() (linuxProcessTreeSnapshot, error) {
	if sampler == nil || sampler.rootPID <= 0 || sampler.pgid <= 0 || sampler.rootStartTicks == 0 || sampler.pageSize == 0 {
		return linuxProcessTreeSnapshot{}, errors.New("process-tree sampler is not initialized")
	}
	entries, err := os.ReadDir(sampler.procRoot)
	if err != nil {
		return linuxProcessTreeSnapshot{}, err
	}
	stats := make(map[int]linuxProcStat)
	children := make(map[int][]int)
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		stat, readErr := readLinuxProcStat(sampler.procRoot, pid)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			return linuxProcessTreeSnapshot{}, readErr
		}
		stats[pid] = stat
		children[stat.ppid] = append(children[stat.ppid], pid)
	}
	root, ok := stats[sampler.rootPID]
	if !ok || root.startTicks != sampler.rootStartTicks || root.pgid != sampler.pgid {
		return linuxProcessTreeSnapshot{}, errors.New("process-tree root exited or changed identity")
	}
	var pids []int
	if sampler.cgroupPath != "" {
		pids, err = readLinuxCgroupProcesses(sampler.cgroupPath)
		if err != nil {
			return linuxProcessTreeSnapshot{}, err
		}
		if !slices.Contains(pids, sampler.rootPID) {
			return linuxProcessTreeSnapshot{}, errors.New("process-tree root is outside its private cgroup")
		}
	} else {
		pids = []int{sampler.rootPID}
		seen := map[int]struct{}{sampler.rootPID: {}}
		for index := 0; index < len(pids); index++ {
			for _, child := range children[pids[index]] {
				if _, exists := seen[child]; exists {
					continue
				}
				seen[child] = struct{}{}
				pids = append(pids, child)
			}
		}
	}
	snapshot := linuxProcessTreeSnapshot{At: time.Now().UTC(), RootPID: sampler.rootPID, PGID: sampler.pgid}
	if sampler.cgroupPath == "" {
		snapshot.AccountingMode = "pid_starttime_process_tree_fallback"
		snapshot.FallbackReason = sampler.fallbackReason
		snapshot.SampleIntervalMS = 10
	}
	currentCPU := make(map[linuxProcessIdentity]uint64, len(pids))
	for _, pid := range pids {
		stat, exists := stats[pid]
		if !exists {
			var readErr error
			stat, readErr = readLinuxProcStat(sampler.procRoot, pid)
			if errors.Is(readErr, os.ErrNotExist) && pid != sampler.rootPID {
				continue
			}
			if readErr != nil {
				return linuxProcessTreeSnapshot{}, readErr
			}
		}
		residentPages, readErr := readLinuxResidentPages(sampler.procRoot, pid)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) && pid != sampler.rootPID {
				continue
			}
			return linuxProcessTreeSnapshot{}, readErr
		}
		fds, readErr := countLinuxProcEntries(sampler.procRoot, pid, "fd")
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) && pid != sampler.rootPID {
				continue
			}
			return linuxProcessTreeSnapshot{}, readErr
		}
		tasks, readErr := countLinuxProcEntries(sampler.procRoot, pid, "task")
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) && pid != sampler.rootPID {
				continue
			}
			return linuxProcessTreeSnapshot{}, readErr
		}
		if residentPages > math.MaxUint64/sampler.pageSize || snapshot.RSSBytes > math.MaxUint64-residentPages*sampler.pageSize ||
			stat.userTicks > math.MaxUint64-stat.systemTicks {
			return linuxProcessTreeSnapshot{}, errors.New("process-tree resource counter overflow")
		}
		snapshot.RSSBytes += residentPages * sampler.pageSize
		currentCPU[linuxProcessIdentity{pid: pid, startTicks: stat.startTicks}] = stat.userTicks + stat.systemTicks
		snapshot.OpenFDs += fds
		snapshot.Tasks += tasks
		snapshot.ProcessCount++
		if stat.state == 'Z' {
			snapshot.ZombieProcesses++
		}
	}
	if snapshot.ProcessCount == 0 || snapshot.Tasks < snapshot.ProcessCount || snapshot.OpenFDs < 0 || snapshot.ZombieProcesses != 0 {
		return linuxProcessTreeSnapshot{}, errLinuxProcessTreeSnapshotIncomplete
	}
	if snapshot.RSSBytes > sampler.peakRSS {
		sampler.peakRSS = snapshot.RSSBytes
	}
	snapshot.SampledRSSPeak = sampler.peakRSS
	if sampler.cgroupPath != "" {
		cpu, currentMemory, peakMemory, pidsCurrent, nativePeak, err := readLinuxCgroupResources(sampler.cgroupPath)
		if err != nil {
			return linuxProcessTreeSnapshot{}, err
		}
		if currentMemory > sampler.cgroupPeak {
			sampler.cgroupPeak = currentMemory
		}
		if nativePeak {
			snapshot.AccountingMode = "cgroup_v2"
		} else {
			snapshot.AccountingMode = "cgroup_v2_sampled_peak"
			snapshot.SampleIntervalMS = 10
			peakMemory = sampler.cgroupPeak
		}
		snapshot.CPUNanoseconds = cpu
		snapshot.CgroupMemoryCurrent = currentMemory
		snapshot.CgroupMemoryPeak = peakMemory
		snapshot.CgroupPIDsCurrent = pidsCurrent
		if pidsCurrent < snapshot.ProcessCount {
			return linuxProcessTreeSnapshot{}, errors.New("cgroup task count is smaller than the bound process tree")
		}
		snapshot.Tasks = pidsCurrent
		return snapshot, nil
	}
	for identity, ticks := range sampler.knownCPU {
		if _, exists := currentCPU[identity]; !exists {
			if sampler.retiredTicks > math.MaxUint64-ticks {
				return linuxProcessTreeSnapshot{}, errors.New("retired process CPU counter overflow")
			}
			sampler.retiredTicks += ticks
		}
	}
	sampler.knownCPU = currentCPU
	totalTicks := sampler.retiredTicks
	for _, ticks := range currentCPU {
		if totalTicks > math.MaxUint64-ticks {
			return linuxProcessTreeSnapshot{}, errors.New("process-tree CPU counter overflow")
		}
		totalTicks += ticks
	}
	if totalTicks > math.MaxUint64/uint64(time.Second) {
		return linuxProcessTreeSnapshot{}, errors.New("process-tree CPU nanosecond counter overflow")
	}
	snapshot.CPUNanoseconds = totalTicks * uint64(time.Second) / linuxProcClockTicksPerSecond
	return snapshot, nil
}

func readLinuxCgroupProcesses(directory string) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(directory, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return nil, errors.New("private cgroup has no processes")
	}
	pids := make([]int, 0, len(fields))
	for _, field := range fields {
		pid, parseErr := strconv.Atoi(field)
		if parseErr != nil || pid <= 0 {
			return nil, errors.New("private cgroup has an invalid process member")
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func (sampler *linuxProcessTreeSampler) runResourceSampler() {
	defer close(sampler.done)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sampler.sampleMu.Lock()
			sampler.sampleResourcePeakLocked()
			sampler.sampleMu.Unlock()
		case <-sampler.stop:
			return
		}
	}
}

func (sampler *linuxProcessTreeSampler) sampleResourcePeakLocked() {
	if sampler.cgroupPath == "" {
		_, _ = sampler.snapshotLocked()
		return
	}
	currentMemory, err := readLinuxCgroupUint(sampler.cgroupPath, "memory.current")
	if err == nil && currentMemory > sampler.cgroupPeak {
		sampler.cgroupPeak = currentMemory
	}
}

func (sampler *linuxProcessTreeSampler) Close() error {
	if sampler == nil {
		return nil
	}
	select {
	case <-sampler.stop:
	default:
		close(sampler.stop)
	}
	<-sampler.done
	if sampler.cgroupPath == "" {
		return nil
	}
	return os.Remove(sampler.cgroupPath)
}

func (sampler *linuxProcessTreeSampler) Kill() error {
	if sampler == nil {
		return nil
	}
	if sampler.cgroupPath != "" {
		var result error
		killPath := filepath.Join(sampler.cgroupPath, "cgroup.kill")
		_, statErr := os.Stat(killPath)
		if statErr == nil {
			if err := os.WriteFile(killPath, []byte("1"), 0o600); err != nil {
				result = fmt.Errorf("kill private cgroup: %w", err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			result = fmt.Errorf("inspect private cgroup kill capability: %w", statErr)
		} else {
			if pids, readErr := readLinuxCgroupProcesses(sampler.cgroupPath); readErr != nil {
				result = fmt.Errorf("read private cgroup for kill: %w", readErr)
			} else {
				for _, pid := range pids {
					if signalErr := syscall.Kill(pid, syscall.SIGKILL); signalErr != nil && !errors.Is(signalErr, syscall.ESRCH) {
						result = errors.Join(result, signalErr)
					}
				}
			}
		}
		if sampler.pgid > 0 {
			if err := syscall.Kill(-sampler.pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
				result = errors.Join(result, fmt.Errorf("kill private process group: %w", err))
			}
		}
		return result
	}
	sampler.sampleMu.Lock()
	defer sampler.sampleMu.Unlock()
	entries, err := os.ReadDir(sampler.procRoot)
	if err != nil {
		return err
	}
	children := make(map[int][]int)
	stats := make(map[int]linuxProcStat)
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 || !entry.IsDir() {
			continue
		}
		stat, readErr := readLinuxProcStat(sampler.procRoot, pid)
		if readErr == nil {
			stats[pid] = stat
			children[stat.ppid] = append(children[stat.ppid], pid)
		}
	}
	var pids []int
	if sampler.cgroupPath != "" {
		pids, err = readLinuxCgroupProcesses(sampler.cgroupPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		seen := make(map[int]struct{})
		pids = append(pids, sampler.rootPID)
		seen[sampler.rootPID] = struct{}{}
		for index := 0; index < len(pids); index++ {
			for _, child := range children[pids[index]] {
				if _, exists := seen[child]; exists {
					continue
				}
				seen[child] = struct{}{}
				pids = append(pids, child)
			}
		}
		for pid, stat := range stats {
			if stat.pgid == sampler.pgid {
				if _, exists := seen[pid]; exists {
					continue
				}
				seen[pid] = struct{}{}
				pids = append(pids, pid)
			}
		}
	}
	var result error
	for index := len(pids) - 1; index >= 0; index-- {
		if signalErr := syscall.Kill(pids[index], syscall.SIGKILL); signalErr != nil && !errors.Is(signalErr, syscall.ESRCH) {
			result = errors.Join(result, signalErr)
		}
	}
	return result
}

func readLinuxCgroupResources(directory string) (cpu, memoryCurrent, memoryPeak uint64, pidsCurrent int, nativeMemoryPeak bool, resultErr error) {
	cpuData, err := os.ReadFile(filepath.Join(directory, "cpu.stat"))
	if err != nil {
		return 0, 0, 0, 0, false, err
	}
	var usageMicroseconds uint64
	foundUsage := false
	for _, line := range strings.Split(string(cpuData), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "usage_usec" {
			foundUsage = true
			usageMicroseconds, err = strconv.ParseUint(fields[1], 10, 64)
			break
		}
	}
	if !foundUsage || err != nil || usageMicroseconds > math.MaxUint64/1000 {
		return 0, 0, 0, 0, false, errors.New("cgroup CPU usage is invalid")
	}
	memoryCurrent, err = readLinuxCgroupUint(directory, "memory.current")
	if err != nil {
		return 0, 0, 0, 0, false, err
	}
	memoryPeak, err = readLinuxCgroupUint(directory, "memory.peak")
	if errors.Is(err, os.ErrNotExist) {
		memoryPeak = 0
	} else if err != nil || memoryPeak < memoryCurrent {
		return 0, 0, 0, 0, false, errors.New("cgroup memory counters are invalid")
	} else {
		nativeMemoryPeak = true
	}
	pids, err := readLinuxCgroupUint(directory, "pids.current")
	if err != nil || pids == 0 || pids > math.MaxInt {
		return 0, 0, 0, 0, false, errors.New("cgroup task counter is invalid")
	}
	return usageMicroseconds * 1000, memoryCurrent, memoryPeak, int(pids), nativeMemoryPeak, nil
}

func readLinuxCgroupUint(directory, name string) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

func readLinuxProcStat(procRoot string, pid int) (linuxProcStat, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return linuxProcStat{}, err
	}
	return parseLinuxProcStatRecord(pid, string(data))
}

func parseLinuxProcStatRecord(pid int, record string) (linuxProcStat, error) {
	text := strings.TrimSpace(record)
	closeParen := strings.LastIndexByte(text, ')')
	openParen := strings.IndexByte(text, '(')
	if openParen <= 0 || closeParen <= openParen || closeParen+2 > len(text) {
		return linuxProcStat{}, errors.New("invalid /proc stat record")
	}
	parsedPID, err := strconv.Atoi(strings.TrimSpace(text[:openParen]))
	if err != nil || parsedPID != pid {
		return linuxProcStat{}, errors.New("mismatched /proc stat PID")
	}
	fields := strings.Fields(text[closeParen+2:])
	if len(fields) < 20 {
		return linuxProcStat{}, errors.New("truncated /proc stat record")
	}
	if len(fields[0]) != 1 {
		return linuxProcStat{}, errors.New("invalid /proc process state")
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return linuxProcStat{}, err
	}
	pgid, err := strconv.Atoi(fields[2])
	if err != nil {
		return linuxProcStat{}, err
	}
	userTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return linuxProcStat{}, err
	}
	systemTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return linuxProcStat{}, err
	}
	startTicks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return linuxProcStat{}, errors.New("invalid /proc process start time")
	}
	return linuxProcStat{pid: pid, ppid: ppid, pgid: pgid, state: fields[0][0], userTicks: userTicks, systemTicks: systemTicks, startTicks: startTicks}, nil
}

func readLinuxResidentPages(procRoot string, pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "statm"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, errors.New("truncated /proc statm record")
	}
	return strconv.ParseUint(fields[1], 10, 64)
}

func countLinuxProcEntries(procRoot string, pid int, name string) (int, error) {
	entries, err := os.ReadDir(filepath.Join(procRoot, strconv.Itoa(pid), name))
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}
