package tunnelv3

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

type bridgeReadFunc func([]byte) (int, error)

func (f bridgeReadFunc) Read(p []byte) (int, error) { return f(p) }

type bridgeWriteFunc func([]byte) (int, error)

func (f bridgeWriteFunc) Write(p []byte) (int, error) { return f(p) }

func TestBridgeCopyForwardsFinalBytesAndErrors(t *testing.T) {
	want := bytes.Repeat([]byte("bulk-stream-record"), 16384)
	for _, size := range []int{37, 32 << 10} {
		var dst bytes.Buffer
		src := iotest.DataErrReader(bytes.NewReader(want))
		if err := copyStreamBytes(bridgeWriteFunc(dst.Write), src, size); err != nil || !bytes.Equal(want, dst.Bytes()) {
			t.Fatalf("copy size %d: bytes %d, err %v", size, dst.Len(), err)
		}
	}
	failure := errors.New("read failed after data")
	src := bridgeReadFunc(func(p []byte) (int, error) { return copy(p, "last"), failure })
	var dst bytes.Buffer
	if err := copyStreamBytes(bridgeWriteFunc(dst.Write), src, 1024); err != failure || dst.String() != "last" {
		t.Fatalf("final data = %q, err = %v", dst.String(), err)
	}
	if err := copyStreamBytes(bridgeWriteFunc(func(p []byte) (int, error) { return len(p) - 1, nil }), src, 1024); err != io.ErrShortWrite {
		t.Fatalf("short write = %v", err)
	}
}
