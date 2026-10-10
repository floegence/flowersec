package cryptov4

import (
	"bytes"
	"errors"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"testing"
)

func TestEnginePrepaidRecordBackingLifecycle(t *testing.T) {
	client, server, _ := enginePair(t, protocolv4.DHProfileX25519)
	for _, e := range []*Engine{client, server} {
		for _, w := range e.free {
			if w.input != nil || w.output != nil {
				t.Fatal("key-only workspace allocated record arrays")
			}
		}
	}
	p, err := client.Seal(protocolv4.FrameStreamData, 1, []byte("prepaid backing"))
	if err != nil {
		t.Fatal(err)
	}
	w := p.workspace
	if len(w.input) != len("prepaid backing") || len(w.output) != len(p.data) {
		t.Fatal("record backing does not match its original invocation bound")
	}
	client.Close()
	if w.input == nil || w.output == nil {
		t.Fatal("Close reclaimed a borrowed record")
	}
	p.Release()
	if w.input != nil || w.output != nil {
		t.Fatal("released closed record retained backing")
	}
	server.Close()
	if !server.cleanupComplete {
		t.Fatal("unused record arrays prevented cleanup")
	}
}

func TestEnginePagedLifetimeRejectsRetiredAndOutOfRangeScopes(t *testing.T) {
	e, _, _ := enginePair(t, protocolv4.DHProfileX25519)
	for role := uint64(0); role < 2; role++ {
		for _, ordinal := range []uint64{32767, 32768, e.ordinal[role] - 1} {
			scope := 2*ordinal + 1 + role
			if err := e.OpenScope(scope); err != nil {
				t.Fatal("legal lifetime ordinal refused", scope, err)
			}
			e.RetireScope(scope)
			if err := e.OpenScope(scope); !errors.Is(err, ErrScope) {
				t.Fatal("retired ordinal reused", scope, err)
			}
		}
		scope := 2*e.ordinal[role] + 1 + role
		if err := e.OpenScope(scope); !errors.Is(err, ErrScope) {
			t.Fatal("maximum lifetime bound enlarged", scope, err)
		}
	}
}

func TestEngineRecordBackingRestoresOriginalMaximumAfterEachRelease(t *testing.T) {
	for _, profile := range []string{protocolv4.DHProfileX25519, protocolv4.DHProfileP256} {
		t.Run(profile, func(t *testing.T) {
			client, server, _ := enginePair(t, profile)
			defer client.Close()
			defer server.Close()
			maximum := int(client.config.MaxFrame) - protocolv4.RecordHeaderSize() - client.profile.TagBytes
			for _, size := range []int{1, maximum, 7} {
				payload := bytes.Repeat([]byte{'a'}, size)
				sent, err := client.Seal(protocolv4.FrameStreamData, 1, payload)
				if err != nil {
					t.Fatal("original legal record refused", size, err)
				}
				sendWork := sent.workspace
				if len(sendWork.input) != size || len(sendWork.output) != len(sent.data) {
					t.Fatal("send arena does not match original record", size)
				}
				received, _, _, err := server.Open(sent.data, func(_ protocolv4.FrameType, _ protocolv4.RecordHeader, plain []byte) error {
					if !bytes.Equal(plain, payload) {
						return ErrAuthentication
					}
					return nil
				})
				if err != nil {
					sent.Release()
					t.Fatal("original record failed authentication", size, err)
				}
				receiveWork := received.workspace
				sendView, receiveView := sent.data, received.data
				if len(receiveWork.input) != len(sent.data) || len(receiveWork.output) != size+server.profile.TagBytes {
					t.Fatal("receive arena does not match original envelope", size)
				}
				sent.Release()
				if !bytes.Equal(received.data, payload) {
					t.Fatal("sender cleanup erased peer's retained packet")
				}
				received.Release()
				if sendWork.input != nil || sendWork.output != nil || receiveWork.input != nil || receiveWork.output != nil || !bytes.Equal(sendView, make([]byte, len(sendView))) || !bytes.Equal(receiveView, make([]byte, len(receiveView))) {
					t.Fatal("packet Release retained backing or original plaintext")
				}
			}
			if packet, err := client.Seal(protocolv4.FrameStreamData, 1, make([]byte, maximum+1)); err == nil {
				packet.Release()
				t.Fatal("original maximum record enlarged")
			}
		})
	}
}
