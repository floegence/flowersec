package rpc

import (
	"bytes"
	"errors"
	"testing"

	rpcv1 "github.com/floegence/flowersec/gen/flowersec/rpc/v1"
)

func TestReadStreamHelloRejectsInvalidJSON(t *testing.T) {
	buf := &bytes.Buffer{}
	buf.Write([]byte{0, 0, 0, 5})
	buf.Write([]byte("oops{"))
	if _, err := ReadStreamHello(buf, 1024); !errors.Is(err, ErrBadStreamHello) {
		t.Fatalf("expected bad stream hello, got %v", err)
	}
}

func TestReadStreamHelloValidatesFields(t *testing.T) {
	buf := &bytes.Buffer{}
	if err := WriteJSONFrame(buf, rpcv1.StreamHello{Kind: "", V: 1}); err != nil {
		t.Fatalf("WriteJSONFrame failed: %v", err)
	}
	if _, err := ReadStreamHello(buf, 1024); !errors.Is(err, ErrBadStreamHello) {
		t.Fatalf("expected bad stream hello, got %v", err)
	}

	buf.Reset()
	if err := WriteJSONFrame(buf, rpcv1.StreamHello{Kind: "rpc", V: 0}); err != nil {
		t.Fatalf("WriteJSONFrame failed: %v", err)
	}
	if _, err := ReadStreamHello(buf, 1024); !errors.Is(err, ErrBadStreamHello) {
		t.Fatalf("expected bad stream hello, got %v", err)
	}
}
