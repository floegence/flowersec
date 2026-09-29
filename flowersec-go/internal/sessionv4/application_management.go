package sessionv4

import (
	"context"
	"unsafe"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/cryptov4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
)

// The protected management lane belongs to the unique budget-root executor.
// Channel readers and small-response publication have separate original owners.
type managementLane struct {
	queue   [4]*managementTask
	active  [2]*managementTask
	last    *ManagementChannel
	workers uint32
	started bool
	wake    chan struct{}
	stop    chan struct{}
}

type managementTask struct {
	channel   *ManagementChannel
	job       rpcv4.ManagementJob
	ctx       context.Context
	cancel    context.CancelFunc
	resolver  rpcv4.ExecutionManagementResolver
	done      chan struct{}
	reply     rpcv4.ManagementReply
	err       error
	response  rpcv4.ManagementReply
	published bool
}

func managementLaneCharge(c ApplicationExecutorConfig) (resourcev4.Vector, error) {
	// Both protected workers consume the same root task and work dimensions as
	// the other executor services, even while their lazy startup is deferred.
	charge := resourcev4.Vector{resourcev4.SDKBytes: uint64(unsafe.Sizeof(managementLane{})) + 2*128, resourcev4.Items: 3, resourcev4.Tasks: 2, resourcev4.WorkSlots: 2}
	var err error
	for range 2 {
		charge, err = charge.Add(resourcev4.Vector{resourcev4.SDKBytes: c.RuntimeBytesPerTask})
		if err != nil {
			return resourcev4.Vector{}, err
		}
	}
	return charge, nil
}

func (e *ApplicationExecutor) submitManagement(task *managementTask) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.management == nil {
		return cryptov4.ErrClosed
	}
	if !e.management.started {
		e.management.started = true
		e.management.workers = 2
		for i := range 2 {
			go e.runManagementWorker(i)
		}
	}
	for i, current := range e.management.queue {
		if current == nil {
			e.management.queue[i] = task
			e.wakeManagementLocked()
			return nil
		}
	}
	return cryptov4.ErrCapacity
}

func (e *ApplicationExecutor) wakeManagementLocked() {
	for range 2 {
		select {
		case e.management.wake <- struct{}{}:
		default:
		}
	}
}

func (e *ApplicationExecutor) runManagementWorker(index int) {
	defer func() { e.mu.Lock(); e.management.workers--; e.cleanupLocked(); e.mu.Unlock() }()
	for {
		e.mu.Lock()
		lane := e.management
		if e.closed {
			e.mu.Unlock()
			return
		}
		chosen := -1
		// Alternate ready Sessions before accepting another turn from the last
		// channel. The fixed queue is compacted in original FIFO order.
		for i, task := range lane.queue {
			if task != nil && (chosen < 0 || lane.queue[chosen].channel == lane.last && task.channel != lane.last) {
				chosen = i
			}
		}
		if chosen < 0 {
			e.mu.Unlock()
			select {
			case <-lane.wake:
			case <-lane.stop:
				return
			}
			continue
		}
		task := lane.queue[chosen]
		copy(lane.queue[chosen:], lane.queue[chosen+1:])
		lane.queue[len(lane.queue)-1] = nil
		lane.active[index], lane.last = task, task.channel
		e.mu.Unlock()
		func() {
			defer func() {
				if recover() != nil {
					task.err = ErrEnvironmentTaskExit
				}
				close(task.done)
				task.channel.tasks.Done()
				notifyOpenWait(task.channel.managementWake)
			}()
			task.reply, task.err = task.job.Run(task.ctx, task.resolver)
		}()
		e.mu.Lock()
		lane.active[index] = nil
		e.mu.Unlock()
	}
}

func (e *ApplicationExecutor) closeManagementLocked() {
	if e.management == nil {
		return
	}
	select {
	case <-e.management.stop:
		return
	default:
		close(e.management.stop)
	}
	for i, task := range e.management.queue {
		if task != nil {
			task.err = cryptov4.ErrClosed
			close(task.done)
			task.channel.tasks.Done()
			notifyOpenWait(task.channel.managementWake)
			e.management.queue[i] = nil
		}
	}
}
