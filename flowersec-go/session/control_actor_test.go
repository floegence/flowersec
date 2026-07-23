package session

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
	"github.com/floegence/flowersec/flowersec-go/v2/protocolv2"
)

func TestNativeResetDoesNotWaitForBlockedControlWriter(t *testing.T) {
	clientCarrier, serverCarrier := newMemoryCarrierPair(carrier.KindQUIC)
	clientConfig, serverConfig := testEngineConfigs(2)
	client, server := establishWithCarriers(t, clientCarrier, serverCarrier, clientConfig, serverConfig)
	defer client.Close()
	defer server.Close()

	accepted := make(chan IncomingStream, 1)
	acceptErr := make(chan error, 1)
	go acceptOne(server, accepted, acceptErr)
	stream, err := client.OpenStream(context.Background(), "reset-with-stalled-control", Metadata{})
	if err != nil {
		t.Fatal(err)
	}
	peer := awaitIncoming(t, accepted, acceptErr)

	writerBlocked := make(chan struct{})
	releaseWriter := make(chan struct{})
	var once sync.Once
	clientCarrier.setWriteHook(func(payload []byte) {
		if bytes.HasPrefix(payload, []byte("FSR2")) {
			once.Do(func() { close(writerBlocked) })
			<-releaseWriter
		}
	})
	probeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := client.ProbeLiveness(ctx)
		probeDone <- err
	}()
	select {
	case <-writerBlocked:
	case <-time.After(time.Second):
		t.Fatal("control writer did not block")
	}

	resetDone := make(chan error, 1)
	go func() { resetDone <- stream.Reset() }()
	select {
	case err := <-resetDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("native reset waited for the blocked control writer")
	}
	readDone := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := peer.Stream.Read(one[:])
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, carrier.ErrStreamReset) && !errors.Is(err, protocolv2.ErrStreamReset) {
			t.Fatalf("peer reset error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("peer native stream did not observe reset")
	}
	close(releaseWriter)
	if err := <-probeDone; err != nil {
		t.Fatalf("probe after writer release: %v", err)
	}
}

func TestLiveControlActorHasReservedCriticalCapacityAndOrderedPublish(t *testing.T) {
	session := newControlActorUnitSession(t, 1)
	published := false
	if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(1, 6), func() error {
		published = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("control state was not published at commit")
	}
	var update [20]byte
	update[7] = 1
	update[11] = 1
	if err := session.commitControl(protocolv2.InnerSessionKeyUpdate, update[:], nil); err != nil {
		t.Fatal(err)
	}

	session.controlActorMu.Lock()
	if len(session.controlQueue) != 2 {
		session.controlActorMu.Unlock()
		t.Fatalf("control queue length = %d", len(session.controlQueue))
	}
	first, second := session.controlQueue[0], session.controlQueue[1]
	session.controlActorMu.Unlock()
	if first.typ != protocolv2.InnerStreamReset || second.typ != protocolv2.InnerSessionKeyUpdate ||
		first.sequence != 0 || second.sequence != 1 {
		t.Fatalf("control order = (%d,%d) then (%d,%d)", first.typ, first.sequence, second.typ, second.sequence)
	}

	for i := 2; i < 10; i++ { // 2*maxInbound(1)+8 critical records.
		if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(uint64(i*2+1), 6), nil); err != nil {
			t.Fatalf("critical commit %d: %v", i, err)
		}
	}
	if err := session.commitControl(protocolv2.InnerStreamReset, marshalIDReason(21, 6), nil); !errors.Is(err, protocolv2.ErrControlQueueFull) {
		t.Fatalf("critical capacity+1 error = %v", err)
	}
	for i := 0; i < 8; i++ {
		if err := session.commitControl(protocolv2.InnerPing, make([]byte, 8), nil); err != nil {
			t.Fatalf("noncritical commit %d: %v", i, err)
		}
	}
	if err := session.commitControl(protocolv2.InnerPing, make([]byte, 8), nil); !errors.Is(err, protocolv2.ErrControlQueueFull) {
		t.Fatalf("noncritical capacity+1 error = %v", err)
	}
}

func newControlActorUnitSession(t *testing.T, maxInbound uint16) *engineSession {
	t.Helper()
	var sessionPRK [32]byte
	for i := range sessionPRK {
		sessionPRK[i] = byte(i + 1)
	}
	roots, err := protocolv2.DeriveEpochZero(sessionPRK, protocolv2.DirectionClientToServer)
	if err != nil {
		t.Fatal(err)
	}
	session := &engineSession{
		config:    Config{Suite: protocolv2.SuiteChaCha20Poly1305, MaxInboundStreams: maxInbound},
		sendDir:   protocolv2.DirectionClientToServer,
		sendRoots: map[uint32]protocolv2.EpochRoots{0: roots},
	}
	session.initControlActor()
	return session
}
