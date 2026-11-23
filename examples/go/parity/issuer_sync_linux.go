//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// linux/aio_abi.h: the FSYNC operation covers file metadata as well as data.
const issuerAIOFsync = 2

type issuerRequest struct {
	data     uint64
	key      uint32
	rwFlags  uint32
	opcode   uint16
	priority int16
	fd       uint32
	buffer   uint64
	bytes    uint64
	offset   int64
	reserved uint64
	flags    uint32
	resfd    uint32
}

type issuerCompletion struct {
	data, object    uint64
	result, result2 int64
}

type issuerSlot struct {
	sequence uint64
	expected atomic.Uint64
	done     chan int64
}

type issuerQueue struct {
	context  uintptr
	requests [issuerParallelism]issuerRequest
	slots    [issuerParallelism]issuerSlot
	pin      runtime.Pinner
	free     chan int
	tickets  chan struct{}
	stopped  chan struct{}
	gate     sync.RWMutex
	err      error
}

func newIssuerSync() (publicationSync, func() error, error) {
	queue := &issuerQueue{}
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IO_SETUP, issuerParallelism, uintptr(unsafe.Pointer(&queue.context)), 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return nil, nil, os.NewSyscallError("io_setup", errno)
		}
		break
	}
	queue.pin.Pin(&queue.requests)
	queue.free = make(chan int, issuerParallelism)
	queue.tickets = make(chan struct{}, issuerParallelism)
	queue.stopped = make(chan struct{})
	for index := range queue.slots {
		queue.slots[index].sequence = uint64(index)
		queue.slots[index].done = make(chan int64, 1)
		queue.free <- index
	}
	go queue.collect()
	return queue.sync, queue.close, nil
}

func (queue *issuerQueue) submit(index int, fd uintptr) error {
	queue.gate.RLock()
	defer queue.gate.RUnlock()
	if queue.err != nil {
		return queue.err
	}
	slot := &queue.slots[index]
	slot.sequence += issuerParallelism
	request := &queue.requests[index]
	*request = issuerRequest{data: slot.sequence, opcode: issuerAIOFsync, fd: uint32(fd)}
	slot.expected.Store(slot.sequence)
	for {
		count, _, errno := syscall.Syscall(syscall.SYS_IO_SUBMIT, queue.context, 1, uintptr(unsafe.Pointer(&request)))
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 || count != 1 {
			slot.expected.Store(0)
			if errno != 0 {
				return errno
			}
			return syscall.EIO
		}
		queue.tickets <- struct{}{}
		return nil
	}
}

func (queue *issuerQueue) sync(file *os.File) error {
	index := <-queue.free
	defer func() { queue.free <- index }()
	defer runtime.KeepAlive(file)
	wrap := func(err error) error { return &os.PathError{Op: "sync", Path: file.Name(), Err: err} }
	for {
		if err := queue.submit(index, file.Fd()); err != nil {
			return wrap(err)
		}
		select {
		case <-queue.stopped:
			return wrap(queue.err)
		case result := <-queue.slots[index].done:
			switch {
			case result == 0:
				return nil
			case result == -int64(syscall.EINTR):
				continue
			case result < 0 && result >= -4095:
				return wrap(syscall.Errno(-result))
			default:
				return wrap(syscall.EIO)
			}
		}
	}
}

func (queue *issuerQueue) reap() error {
	var event issuerCompletion
	for {
		count, _, errno := syscall.Syscall6(syscall.SYS_IO_GETEVENTS, queue.context, 1, 1, uintptr(unsafe.Pointer(&event)), 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return os.NewSyscallError("io_getevents", errno)
		}
		if count != 1 {
			return syscall.EIO
		}
		break
	}
	index := event.data % issuerParallelism
	slot := &queue.slots[index]
	if event.data == 0 || event.object != uint64(uintptr(unsafe.Pointer(&queue.requests[index]))) || event.result2 != 0 || !slot.expected.CompareAndSwap(event.data, 0) {
		return errors.New("unexpected issuer fsync completion")
	}
	slot.done <- event.result
	return nil
}

func (queue *issuerQueue) collect() {
	var err error
	for range queue.tickets {
		if err = queue.reap(); err != nil {
			break
		}
	}
	// Exclude submissions and drain the kernel context before waking failed waiters.
	queue.gate.Lock()
	defer queue.gate.Unlock()
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_IO_DESTROY, queue.context, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			err = errors.Join(err, os.NewSyscallError("io_destroy", errno))
		}
		break
	}
	queue.err = err
	queue.pin.Unpin()
	close(queue.stopped)
}

func (queue *issuerQueue) close() error {
	close(queue.tickets)
	<-queue.stopped
	return queue.err
}
