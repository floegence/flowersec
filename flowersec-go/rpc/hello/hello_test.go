package hello

import (
	"bytes"
	"testing"

	rpcv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/rpc/v1"
	"github.com/floegence/flowersec/flowersec-go/rpc/frame"
)

func TestReadStreamHelloRejectsBadInputs(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	if err := frame.WriteJSONFrame(buf, rpcv1.StreamHello{Kind: "", V: 1}); err != nil {
		t.Fatalf("WriteJSONFrame failed: %v", err)
	}
	if _, err := ReadStreamHello(buf, 8*1024); err == nil {
		t.Fatal("expected error for empty kind")
	}
	buf.Reset()
	if err := frame.WriteJSONFrame(buf, rpcv1.StreamHello{Kind: "rpc", V: 0}); err != nil {
		t.Fatalf("WriteJSONFrame failed: %v", err)
	}
	if _, err := ReadStreamHello(buf, 8*1024); err == nil {
		t.Fatal("expected error for bad version")
	}
}
