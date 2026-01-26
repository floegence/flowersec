package rpc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	"github.com/floegence/flowersec/flowersec-go/rpc"
)

type memRWC struct {
	r *bytes.Reader
}

func (m *memRWC) Read(p []byte) (int, error)  { return m.r.Read(p) }
func (m *memRWC) Write(p []byte) (int, error) { return len(p), nil }
func (m *memRWC) Close() error                { return nil }

func TestRPCServer_SetMaxFrameBytes_ZeroKeepsSizeGuardEnabled(t *testing.T) {
	payloadLen := jsonframe.DefaultMaxJSONFrameBytes + 1
	frame := make([]byte, 4+payloadLen)
	binary.BigEndian.PutUint32(frame[:4], uint32(payloadLen))
	// The payload is never read when the size guard triggers, but we still provide it so
	// the same test helper remains safe if the guard regresses.
	copy(frame[4:], bytes.Repeat([]byte("x"), payloadLen))

	rwc := &memRWC{r: bytes.NewReader(frame)}
	srv := rpc.NewServer(rwc, rpc.NewRouter())
	srv.SetMaxFrameBytes(0) // should reset to default, not disable the guard

	err := srv.Serve(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, jsonframe.ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %T: %v", err, err)
	}
}
