package sessionv4

import (
	"bytes"
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

func TestStreamFlowEncryptedBidirectionalFinish(t *testing.T) {
	client, server := ioEngine(t, protocolv4.ClientToServer), ioEngine(t, protocolv4.ServerToClient)
	var cWire, sWire, cMaintenance, sMaintenance bytes.Buffer
	cWriter, _ := NewRecordWriter(client, 1, &cWire)
	sWriter, _ := NewRecordWriter(server, 1, &sWire)
	cControl, _ := NewRecordWriter(client, 0, &cMaintenance)
	sControl, _ := NewRecordWriter(server, 0, &sMaintenance)
	cSend, _ := testSendFlow(t, cWriter, protocolv4.ClientToServer, 64, TerminalTuple{}, 64, 128)
	sSend, _ := testSendFlow(t, sWriter, protocolv4.ServerToClient, 64, TerminalTuple{}, 64, 128)
	cPool, _ := testReceivePool(t, 64, 64)
	sPool, _ := testReceivePool(t, 64, 64)
	cReceive, _ := NewReceiveFlow(cPool, 1, protocolv4.ServerToClient, 64, TerminalTuple{}, 64)
	sReceive, _ := NewReceiveFlow(sPool, 1, protocolv4.ClientToServer, 64, TerminalTuple{}, 64)
	cStream, err := NewStreamFlow(cSend, cReceive)
	if err != nil {
		t.Fatal(err)
	}
	sStream, err := NewStreamFlow(sSend, sReceive)
	if err != nil {
		t.Fatal(err)
	}
	contextBounds := protocolv4.DecodeContext{Limits: map[string]uint64{"max_data_payload_bytes": 1024}}
	cReader, err := newTestRecordReceiver(t, client, protocolv4.ServerToClient, 4096, 128, contextBounds)
	if err != nil {
		t.Fatal(err)
	}
	sReader, err := newTestRecordReceiver(t, server, protocolv4.ClientToServer, 4096, 128, contextBounds)
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(wire *bytes.Buffer, reader *RecordReceiver, stream *StreamFlow) {
		t.Helper()
		record, err := reader.Read(context.Background(), bytes.NewReader(wire.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		defer record.Release()
		if err = stream.Apply(record); err != nil {
			t.Fatal(err)
		}
		wire.Reset()
	}
	if _, err = cSend.Write(context.Background(), []byte("request"), true); err != nil {
		t.Fatal(err)
	}
	deliver(&cWire, sReader, sStream)
	if _, err = sSend.Write(context.Background(), []byte("response"), true); err != nil {
		t.Fatal(err)
	}
	deliver(&sWire, cReader, cStream)
	var proof [256]byte
	encoded, err := sStream.EncodeDrained(proof[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sControl.Write(context.Background(), protocolv4.FrameStreamAck, encoded); err != nil {
		t.Fatal(err)
	}
	deliver(&sMaintenance, cReader, cStream)
	encoded, err = cStream.EncodeDrained(proof[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cControl.Write(context.Background(), protocolv4.FrameStreamAck, encoded); err != nil {
		t.Fatal(err)
	}
	deliver(&cMaintenance, sReader, sStream)
	for _, stream := range []*StreamFlow{cStream, sStream} {
		result := stream.CloseResult()
		if !result.SendDrained || result.ReadTerminal != protocolv4.V4ReadTerminalOpen || result.CleanupStatus.Status != protocolv4.V4CleanupStatePending {
			t.Fatal("wire proof invented application EOF/cleanup", result)
		}
	}
	var data [64]byte
	if n, terminal, err := sReceive.TryRead(data[:]); n != 7 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(data[:n]) != "request" {
		t.Fatal(n, terminal, err)
	}
	if n, terminal, err := cReceive.TryRead(data[:]); n != 8 || terminal != protocolv4.V4ReadTerminalEof || err != nil || string(data[:n]) != "response" {
		t.Fatal(n, terminal, err)
	}
	if err = cReceive.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err = sReceive.Cleanup(); err != nil {
		t.Fatal(err)
	}
	for _, stream := range []*StreamFlow{cStream, sStream} {
		result := stream.CloseResult()
		if !result.SendDrained || result.ReadTerminal != protocolv4.V4ReadTerminalEof || result.CleanupStatus.Status != protocolv4.V4CleanupStateComplete {
			t.Fatal(result)
		}
	}
	if cPool.Outstanding() != 0 || sPool.Outstanding() != 0 {
		t.Fatal("credit did not return after both actual readers exited")
	}
}
