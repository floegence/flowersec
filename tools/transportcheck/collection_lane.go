package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

func allocateCollectionLaneCPUs(allowed []int, laneCount, maximumPerLane int) ([][]int, error) {
	if laneCount <= 0 || maximumPerLane <= 0 {
		return nil, errors.New("collection CPU allocation requires positive lane and per-lane limits")
	}
	if len(allowed) < laneCount {
		return nil, fmt.Errorf("release runner requires at least %d delegated CPUs, got %d", laneCount, len(allowed))
	}
	width := min(len(allowed), maximumPerLane)
	result := make([][]int, laneCount)
	for lane := range result {
		start := lane * len(allowed) / laneCount
		for offset := range width {
			result[lane] = append(result[lane], allowed[(start+offset)%len(allowed)])
		}
		sort.Ints(result[lane])
	}
	return result, nil
}

func parseCPUSet(value string) ([]int, error) {
	if value == "" {
		return nil, errors.New("CPU set is empty")
	}
	var result []int
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(item, "-")
		if len(bounds) > 2 {
			return nil, fmt.Errorf("invalid CPU set %q", value)
		}
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 0 {
			return nil, fmt.Errorf("invalid CPU set %q", value)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first {
				return nil, fmt.Errorf("invalid CPU set %q", value)
			}
		}
		for cpu := first; cpu <= last; cpu++ {
			result = append(result, cpu)
		}
	}
	return result, nil
}

func formatCPUSet(cpus []int) string {
	parts := make([]string, len(cpus))
	for index, cpu := range cpus {
		parts[index] = strconv.Itoa(cpu)
	}
	return strings.Join(parts, ",")
}

const (
	collectionLaneCPUs           = 2
	collectionLaneMemoryMaxBytes = 3 * 1024 * 1024 * 1024
	collectionLanePIDsMax        = 4096
	collectionBrowserParallelism = 1
	collectionCaseParallelism    = 3
	collectionCaseLaneCPUs       = 4
	collectionCaseMemoryMaxBytes = 4 * 1024 * 1024 * 1024
	collectionCasePIDsMax        = 8192
)

type collectionLaneIdentity struct {
	Index          int    `json:"index"`
	CPUSet         string `json:"cpuset"`
	MemoryMaxBytes int64  `json:"memory_max_bytes"`
	PIDsMax        int    `json:"pids_max"`
}

type collectionLaneRuntime interface {
	Identity() collectionLaneIdentity
	Command(context.Context, string, ...string) *exec.Cmd
}

type collectionLaneSet interface {
	Lane(int) collectionLaneRuntime
	Close() error
}

type localCollectionLaneSet struct {
	lanes []localCollectionLane
}

type localCollectionLane struct {
	identity collectionLaneIdentity
}

func newLocalCollectionLaneSet(count int) collectionLaneSet {
	set := &localCollectionLaneSet{lanes: make([]localCollectionLane, count)}
	for index := range set.lanes {
		set.lanes[index].identity = collectionLaneIdentity{Index: index, CPUSet: "test-only", MemoryMaxBytes: collectionLaneMemoryMaxBytes, PIDsMax: collectionLanePIDsMax}
	}
	return set
}

func (set *localCollectionLaneSet) Lane(index int) collectionLaneRuntime { return &set.lanes[index] }
func (set *localCollectionLaneSet) Close() error                         { return nil }
func (lane *localCollectionLane) Identity() collectionLaneIdentity       { return lane.identity }
func (lane *localCollectionLane) Command(ctx context.Context, executable string, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, executable, args...)
}

type scheduledCollectionJob struct {
	index    int
	job      collectionJob
	duration int
	browser  bool
}

func requiresProductionLaneIsolation(manifest *PerformanceManifest) bool {
	// Unit fixtures omit the global schedule. A validated production manifest
	// always carries all three bounds, regardless of later watchdog tightening.
	return manifest != nil && manifest.GlobalSetupMinutes > 0 && manifest.GlobalWatchdogMinutes > 0 && manifest.MaximumLaneMinutes > 0
}

type collectionLaneSchedule struct {
	lanes     [][]scheduledCollectionJob
	loads     []int
	caseSuite []scheduledCollectionJob
}

func scheduleCollectionJobs(manifest *PerformanceManifest, jobs []collectionJob) (collectionLaneSchedule, error) {
	if manifest == nil {
		return collectionLaneSchedule{}, errors.New("collection lane schedule requires the frozen performance manifest")
	}
	laneCount := manifest.EligibleLaneCount
	if laneCount <= 0 {
		// Unit fixtures that exercise only process handling predate the frozen
		// schedule. Production manifests are validated before this point.
		laneCount = 1
	}
	durationByCell := make(map[string]int, len(manifest.Cells))
	topologyByCell := make(map[string]string, len(manifest.Cells))
	for _, cell := range manifest.Cells {
		if cell.DurationMinutes <= 0 {
			return collectionLaneSchedule{}, fmt.Errorf("collection cell %s has an invalid duration", cell.ID)
		}
		durationByCell[cell.ID] = cell.DurationMinutes
		topologyByCell[cell.ID] = cell.Topology
	}
	ordered := make([]scheduledCollectionJob, 0, len(jobs))
	for index, job := range jobs {
		duration := 0
		browser := false
		for _, cellID := range job.CellIDs {
			cellDuration, exists := durationByCell[cellID]
			if len(durationByCell) != 0 && !exists {
				return collectionLaneSchedule{}, fmt.Errorf("collection job %s references unknown performance cell %s", job.ID, cellID)
			}
			if cellDuration > duration {
				duration = cellDuration
			}
			topology := topologyByCell[cellID]
			browser = browser || strings.HasPrefix(topology, "browser_") || topology == "adaptive_web"
		}
		if duration == 0 && len(durationByCell) == 0 {
			duration = 1
		}
		scheduled := scheduledCollectionJob{index: index, job: job, duration: duration, browser: browser}
		if duration == 0 {
			if job.CaseOwner == "" && len(durationByCell) != 0 {
				return collectionLaneSchedule{}, fmt.Errorf("collection job %s has neither a performance cell nor a case-suite owner", job.ID)
			}
			continue
		}
		ordered = append(ordered, scheduled)
	}
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].duration != ordered[right].duration {
			return ordered[left].duration > ordered[right].duration
		}
		return ordered[left].job.ID < ordered[right].job.ID
	})
	schedule := collectionLaneSchedule{lanes: make([][]scheduledCollectionJob, laneCount), loads: make([]int, laneCount)}
	for index, job := range jobs {
		if len(job.CellIDs) == 0 && job.CaseOwner != "" {
			schedule.caseSuite = append(schedule.caseSuite, scheduledCollectionJob{index: index, job: job})
		}
	}
	sort.Slice(schedule.caseSuite, func(left, right int) bool { return schedule.caseSuite[left].job.ID < schedule.caseSuite[right].job.ID })
	cellLane := make(map[string]int)
	for _, scheduled := range ordered {
		minimum := 0
		for lane := 1; lane < laneCount; lane++ {
			if schedule.loads[lane] < schedule.loads[minimum] {
				minimum = lane
			}
		}
		// clean-01 base and candidate deliberately exercise the same stable
		// cell/run identity. Keeping them on one lane prevents namespace and
		// pinned-BPF collisions while preserving the preregistered total load.
		if len(scheduled.job.CellIDs) == 1 && scheduled.job.CellIDs[0] == "clean-01" {
			if lane, exists := cellLane["clean-01"]; exists {
				minimum = lane
			} else {
				cellLane["clean-01"] = minimum
			}
		}
		schedule.lanes[minimum] = append(schedule.lanes[minimum], scheduled)
		schedule.loads[minimum] += scheduled.duration
	}
	for lane := range schedule.lanes {
		sort.SliceStable(schedule.lanes[lane], func(left, right int) bool {
			if schedule.lanes[lane][left].browser == schedule.lanes[lane][right].browser {
				return false
			}
			if lane < collectionBrowserParallelism {
				return schedule.lanes[lane][left].browser
			}
			return !schedule.lanes[lane][left].browser
		})
	}
	if manifest.GlobalWatchdogMinutes > 0 && manifest.GlobalSetupMinutes > 0 {
		maximum := 0
		for _, load := range schedule.loads {
			if load > maximum {
				maximum = load
			}
		}
		if maximum+manifest.GlobalSetupMinutes > manifest.GlobalWatchdogMinutes {
			return collectionLaneSchedule{}, fmt.Errorf("executable lane schedule requires %d minutes including setup, exceeding global watchdog %d", maximum+manifest.GlobalSetupMinutes, manifest.GlobalWatchdogMinutes)
		}
	}
	return schedule, nil
}
