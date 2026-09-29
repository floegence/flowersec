package sessionv4_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/rpcv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type rpcPoolAccess struct{}

func (rpcPoolAccess) CheckTopUpAccess(tenant string, source [16]byte) error {
	if tenant != "tenant-1" || source != ([16]byte{1}) {
		return errors.New("permission denied")
	}
	return nil
}

type rpcPoolDecoder func(context.Context, uint32, bool, []byte, []byte) (sessionv4.TopUpExchangeResult, error)

func (f rpcPoolDecoder) DecodePoolControlResult(ctx context.Context, method uint32, failure bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
	return f(ctx, method, failure, body, dst)
}

func poolRPCTransport(t *testing.T, h *sessionv4.PoolRPCTestHarness, decode rpcPoolDecoder) *controlv4.PoolRPCTransport {
	t.Helper()
	c := controlv4.PoolRPCConfig{Services: h.Services, TopUpRoute: h.Routes[0], AckRoute: h.Routes[1], Namespace: "pool.control.test", ApplicationErrorCode: 1, LifetimeMS: 500, RuntimeBytes: 65536, Decoder: decode}
	charge, err := controlv4.PoolRPCTransportCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	routeCharge, err := rpcv4.ContractRouteCharge(c.RuntimeBytes)
	if err != nil {
		t.Fatal(err)
	}
	p, err := controlv4.NewPoolRPCTransport(c, h.Reserve(t, charge), h.Reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096}), [2]resourcev4.Reference{h.Reserve(t, routeCharge), h.Reserve(t, routeCharge)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestPoolRPCTransportJoinsCanceledOriginalDecoder(t *testing.T) {
	h := sessionv4.NewPoolRPCTestHarness(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p := poolRPCTransport(t, h, func(_ context.Context, method uint32, failure bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
		if method != controlv4.ControlPoolTopUp || failure {
			return sessionv4.TopUpExchangeResult{}, controlv4.ErrResponse
		}
		close(entered)
		<-release
		return sessionv4.TopUpExchangeResult{ResponseBytes: copy(dst, body)}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dst := make([]byte, 524288)
	returned := make(chan error, 1)
	go func() { _, err := p.TopUp(ctx, []byte("request"), dst); returned <- err }()
	request := h.Respond(t, 1, []byte("original result"), false, returned)
	if request.Kind() != "transient_unary_request" || request.HasExecutionIdentity() || request.Fields().Type != controlv4.ControlPoolTopUp {
		t.Fatal("wrong control call shape")
	}
	select {
	case <-entered:
	case err := <-returned:
		t.Fatal("decoder did not enter", err)
	case <-time.After(time.Second):
		t.Fatal("decoder did not enter")
	}
	cancel()
	p.Close()
	h.Advance(t, true)
	wait, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err := p.WaitCleanup(wait); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late decoder reported cleaned", err)
	}
	select {
	case err := <-returned:
		t.Fatal("transport returned while decoder still owns dst", err)
	default:
	}
	once.Do(func() { close(release) })
	end := time.After(time.Second)
	for {
		h.Advance(t, true)
		select {
		case err := <-returned:
			if !errors.Is(err, context.Canceled) || !bytes.Equal(dst, make([]byte, len(dst))) {
				t.Fatal("canceled output delivered", err)
			}
			if err := p.WaitCleanup(context.Background()); err != nil {
				t.Fatal(err)
			}
			return
		case <-end:
			t.Fatal("original cleanup did not complete")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestPoolRPCTransportWaitsForOriginalPublication(t *testing.T) {
	h := sessionv4.NewPoolRPCTestHarness(t)
	p := poolRPCTransport(t, h, func(_ context.Context, method uint32, failure bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
		if failure {
			return sessionv4.TopUpExchangeResult{}, controlv4.ErrResponse
		}
		return sessionv4.TopUpExchangeResult{ResponseBytes: copy(dst, body)}, nil
	})
	dst := make([]byte, 524288)
	returned := make(chan error, 1)
	go func() { _, err := p.TopUp(context.Background(), []byte("request"), dst); returned <- err }()
	h.Respond(t, 1, []byte("original result"), true, returned)
	for range 20 {
		h.Advance(t, false)
		select {
		case err := <-returned:
			t.Fatal("provider tail released early", err)
		case <-time.After(time.Millisecond):
		}
	}
	end := time.After(time.Second)
	for {
		h.Advance(t, true)
		select {
		case err := <-returned:
			if err != nil || string(dst[:15]) != "original result" {
				t.Fatal("original result lost", err)
			}
			return
		case <-end:
			t.Fatal("provider cleanup did not complete")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestPoolRPCTransportDeliversBoundApplicationErrorReceipt(t *testing.T) {
	h := sessionv4.NewPoolRPCTestHarness(t)
	c := controlv4.PoolResultDecoderConfig{Tenant: "tenant-1", Source: [16]byte{1}, ClientStore: ledgerv4.SQLiteIdentity{Authority: "client-1", StoreID: [32]byte{1}, Generation: 1}, Access: rpcPoolAccess{}, RuntimeBytes: 4096}
	cost, err := controlv4.PoolResultDecoderCharge(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := controlv4.NewPoolResultDecoder(c, h.Reserve(t, cost), h.Reserve(t, resourcev4.Vector{resourcev4.SDKBytes: 4096}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	p := poolRPCTransport(t, h, d.DecodePoolControlResult)
	fence := ledgerv4.TopUpPermanentFenceReceipt{Tenant: c.Tenant, Source: c.Source, Generation: 1}
	var envelope [512]byte
	n, err := controlv4.EncodePoolControlReply(envelope[:], controlv4.ControlPoolAck, controlv4.PoolControlReply{Code: "source_reset_required", Fence: &fence})
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan error, 1)
	var reply sessionv4.TopUpExchangeResult
	go func() { var e error; reply, e = p.Ack(context.Background(), []byte("original ack")); returned <- e }()
	h.Respond(t, 1, envelope[:n], false, returned, 1)
	end := time.After(time.Second)
	for {
		h.Advance(t, true)
		select {
		case err := <-returned:
			defer reply.Release()
			if err != nil || reply.FenceEvidence == nil || reply.Fence != fence || reply.Evidence != nil {
				t.Fatal("application receipt lost", reply, err)
			}
			if err = reply.FenceEvidence.CheckTopUpPermanentFence(c.ClientStore, fence); err != nil {
				t.Fatal(err)
			}
			return
		case <-end:
			t.Fatal("original application-error completion did not return")
		case <-time.After(time.Millisecond):
		}
	}
}
