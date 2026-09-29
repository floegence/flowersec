package native

import (
	"context"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

type hostileFailure []byte

func (hostileFailure) Error() string { panic("error hook") }
func (hostileFailure) Unwrap() error { panic("unwrap hook") }
func (hostileFailure) Is(error) bool { panic("is hook") }

func TestNetworkFailurePreservesLocalCancellationAndHalfClose(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, io.ErrClosedPipe, context.Canceled,
		&net.OpError{Op: "read", Err: net.ErrClosed}, &net.OpError{Op: "write", Err: context.Canceled},
		&net.OpError{Op: "dial", Err: context.DeadlineExceeded}, os.NewSyscallError("connect", syscall.EMFILE),
		&net.OpError{Op: "read", Err: hostileFailure{1}}, &net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.EBADF)},
		os.NewSyscallError("socket", syscall.ENETUNREACH)} {
		if got := NetworkFailure(err); got != err {
			t.Fatalf("nonretryable failure changed: %T", err)
		}
	}
	for _, err := range []error{&net.OpError{Op: "read", Err: syscall.ECONNRESET},
		&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, &net.OpError{Op: "write", Err: os.ErrDeadlineExceeded},
		os.NewSyscallError("connect", syscall.ECONNREFUSED), os.NewSyscallError("connect", syscall.EHOSTUNREACH)} {
		if got := NetworkFailure(err); got != ErrConnectionLost {
			t.Fatalf("connection loss not projected: %T", err)
		}
	}
	if _, ok := NetworkFailure(hostileFailure{1}).(hostileFailure); !ok {
		t.Fatal("arbitrary failure changed")
	}
}
