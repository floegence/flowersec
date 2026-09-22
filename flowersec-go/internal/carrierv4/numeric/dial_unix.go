//go:build darwin || linux

package numeric

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const connectPollInterval = 20 * time.Millisecond

func CheckPlatform(address netip.AddrPort) error {
	if !address.IsValid() || address.Port() == 0 {
		return ErrEndpoint
	}
	_, err := numericZone(address.Addr().Zone())
	return err
}

func numericZone(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if len(zone) > 10 {
		return 0, ErrEndpoint
	}
	var id uint64
	for _, digit := range []byte(zone) {
		if digit < '0' || digit > '9' {
			return 0, ErrEndpoint
		}
		id = id*10 + uint64(digit-'0')
		if id > uint64(^uint32(0)) {
			return 0, ErrEndpoint
		}
	}
	if id == 0 {
		return 0, ErrEndpoint
	}
	return uint32(id), nil
}

func connectCheck(ctx context.Context, deadline time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Connect has no goroutine, timer or context observer. The original
// synchronous prepare task owns fd through every Connect/Poll/error path.
// Cancellation is observed before/after each syscall and at most one bounded
// Poll interval later, subject to ordinary host scheduling latency.
func Connect(ctx context.Context, address netip.AddrPort, deadline time.Time) (net.Conn, error) {
	if ctx == nil {
		return nil, ErrEndpoint
	}
	if err := connectCheck(ctx, deadline); err != nil {
		return nil, err
	}
	if err := CheckPlatform(address); err != nil {
		return nil, err
	}
	ip := address.Addr().Unmap()
	family := unix.AF_INET6
	var sockaddr unix.Sockaddr
	if ip.Is4() {
		family = unix.AF_INET
		sockaddr = &unix.SockaddrInet4{Port: int(address.Port()), Addr: ip.As4()}
	} else {
		zone, _ := numericZone(ip.Zone())
		sockaddr = &unix.SockaddrInet6{Port: int(address.Port()), Addr: ip.As16(), ZoneId: zone}
	}
	// Darwin lacks the atomic SOCK_CLOEXEC flag. Use Go's public fork lock
	// across socket creation/CloseOnExec so no child can inherit this handle.
	syscall.ForkLock.RLock()
	fd, err := unix.Socket(family, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}
	if err := connectCheck(ctx, deadline); err != nil {
		return nil, err
	}
	err = unix.Connect(fd, sockaddr)
	if err != nil && !errors.Is(err, unix.EINPROGRESS) && !errors.Is(err, unix.EALREADY) && !errors.Is(err, unix.EINTR) {
		return nil, os.NewSyscallError("connect", err)
	}
	if err != nil {
		poll := [1]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		for {
			if err := connectCheck(ctx, deadline); err != nil {
				return nil, err
			}
			remaining := min(time.Until(deadline), connectPollInterval)
			if remaining <= 0 {
				return nil, context.DeadlineExceeded
			}
			milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
			poll[0].Revents = 0
			_, err := unix.Poll(poll[:], milliseconds)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return nil, os.NewSyscallError("poll", err)
			}
			if err := connectCheck(ctx, deadline); err != nil {
				return nil, err
			}
			if err != nil || poll[0].Revents == 0 {
				continue
			}
			if poll[0].Revents&unix.POLLNVAL != 0 {
				return nil, os.NewSyscallError("poll", unix.EBADF)
			}
			code, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
			if err != nil {
				return nil, os.NewSyscallError("getsockopt", err)
			}
			if code != 0 {
				return nil, os.NewSyscallError("connect", syscall.Errno(code))
			}
			if poll[0].Revents&unix.POLLOUT != 0 {
				break
			}
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP) != 0 {
				return nil, os.NewSyscallError("connect", unix.ECONNRESET)
			}
		}
	}
	if err := connectCheck(ctx, deadline); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "flowersec-numeric-connect")
	if file == nil {
		return nil, os.NewSyscallError("newfile", unix.EBADF)
	}
	fd = -1 // file now owns the original descriptor, including error cleanup.
	conn, err := net.FileConn(file)
	closeErr := file.Close() // Join the original dup source before returning.
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = conn.Close()
		return nil, closeErr
	}
	if err := connectCheck(ctx, deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}
