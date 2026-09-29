package ledgerv4_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/controlv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/ledgerv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

type serviceIssuer func(context.Context, ledgerv4.TopUpServerSnapshot, []byte) (controlv4.PoolIssueResult, error)

func (f serviceIssuer) IssuePoolBatch(c context.Context, s ledgerv4.TopUpServerSnapshot, b []byte) (controlv4.PoolIssueResult, error) {
	return f(c, s, b)
}
func serviceAdapter(t *testing.T, h *ledgerv4.PoolServiceTestHarness, issue serviceIssuer) *controlv4.PoolService {
	t.Helper()
	c := controlv4.PoolServiceConfig{Store: h.Store, Issuer: issue, Tenant: "tenant-1", Source: [16]byte{1}, TopUpContract: [32]byte{1}, AckContract: [32]byte{2}, CallMS: 1000, RuntimeBytes: 4096, ApplicationErrorCode: 1}
	cost, e := controlv4.PoolServiceCharge(c)
	if e != nil {
		t.Fatal(e)
	}
	p, e := controlv4.NewPoolService(c, h.Reserve(cost), h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096}))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := p.WaitCleanup(ctx); e != nil {
			t.Error(e)
		}
	})
	return p
}
func serviceDecoder(t *testing.T, h *ledgerv4.PoolServiceTestHarness) *controlv4.PoolResultDecoder {
	t.Helper()
	c := controlv4.PoolResultDecoderConfig{Tenant: "tenant-1", Source: [16]byte{1}, ClientStore: h.ClientIdentity, Access: h.Access, RuntimeBytes: 4096}
	cost, e := controlv4.PoolResultDecoderCharge(c)
	if e != nil {
		t.Fatal(e)
	}
	d, e := controlv4.NewPoolResultDecoder(c, h.Reserve(cost), h.Reserve(resourcev4.Vector{resourcev4.SDKBytes: 4096}))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		d.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if e := d.WaitCleanup(ctx); e != nil {
			t.Error(e)
		}
	})
	return d
}

func TestPoolServiceCommitReplayAndHistoricalAck(t *testing.T) {
	h := ledgerv4.NewPoolServiceTestHarness(t)
	ctx := context.Background()
	r, wire := h.Request(t, 1)
	h.Begin(t, r)
	original, facts := h.Response(t, r)
	var issues atomic.Int32
	p := serviceAdapter(t, h, func(_ context.Context, s ledgerv4.TopUpServerSnapshot, dst []byte) (controlv4.PoolIssueResult, error) {
		issues.Add(1)
		if s.State != ledgerv4.TopUpServerPending || s.Request != r {
			t.Error("issuer lost original intent")
		}
		return controlv4.PoolIssueResult{ResponseBytes: copy(dst, original)}, nil
	})
	d := serviceDecoder(t, h)
	envelope, dst := make([]byte, 524288), make([]byte, 524288)
	for attempt := 0; attempt < 2; attempt++ {
		n, failure, e := p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, envelope)
		if e != nil || failure {
			t.Fatal(n, failure, e)
		}
		out, e := d.DecodePoolControlResult(ctx, controlv4.ControlPoolTopUp, false, envelope[:n], dst)
		if e != nil || out.Replay != (attempt == 1) || !bytes.Equal(dst[:out.ResponseBytes], original) {
			t.Fatal(out, e)
		}
		out.Release()
	}
	if issues.Load() != 1 {
		t.Fatal("replay reissued material")
	}
	codec, e := protocolv4.NewTopUpCodec()
	if e != nil {
		t.Fatal(e)
	}
	batch, e := codec.ParseResponse(original, r)
	if e != nil {
		t.Fatal(e)
	}
	e = h.Client.Install(ctx, r, batch)
	batch.Release()
	if e != nil {
		t.Fatal(e)
	}
	h.Tick(1200)
	n, failure, e := p.Exchange(ctx, controlv4.ControlPoolAck, h.Access, h.Ack(t, r, facts), envelope)
	if e != nil || failure {
		t.Fatal(n, failure, e)
	}
	ack, e := d.DecodePoolControlResult(ctx, controlv4.ControlPoolAck, false, envelope[:n], nil)
	if e != nil || ack.Code != "" {
		t.Fatal(ack, e)
	}
	if e = h.Client.ConfirmAck(ctx, r, facts); e != nil {
		t.Fatal(e)
	}
	state, e := h.Client.Recover(ctx)
	if e != nil || state.State != ledgerv4.TopUpJournalAcked {
		t.Fatal(state, e)
	}
}

func TestPoolServiceUnknownCommitDoesNotPublishOrReissue(t *testing.T) {
	h := ledgerv4.NewPoolServiceTestHarness(t)
	ctx := context.Background()
	r, wire := h.Request(t, 1)
	original, _ := h.Response(t, r)
	var issues atomic.Int32
	var restore func()
	p := serviceAdapter(t, h, func(_ context.Context, _ ledgerv4.TopUpServerSnapshot, dst []byte) (controlv4.PoolIssueResult, error) {
		issues.Add(1)
		restore = h.LoseCommitConfirmation()
		return controlv4.PoolIssueResult{ResponseBytes: copy(dst, original)}, nil
	})
	envelope := make([]byte, 524288)
	d := serviceDecoder(t, h)
	n, failure, e := p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, envelope)
	if restore != nil {
		restore()
	}
	if e != nil || n == 0 || !failure {
		t.Fatal("uncertain commit returned success", n, failure, e)
	}
	out, e := d.DecodePoolControlResult(ctx, controlv4.ControlPoolTopUp, true, envelope[:n], nil)
	if e != nil || out.Code != protocolv4.V4TopUpErrorCodeSourceStateUnknown || out.Evidence != nil || out.FenceEvidence != nil || out.ResponseBytes != 0 {
		t.Fatal("uncertain commit became terminal", out, e)
	}
	n, failure, e = p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, envelope)
	if e != nil || failure || issues.Load() != 1 {
		t.Fatal("uncertain commit reissued", n, failure, e, issues.Load())
	}
	out, e = d.DecodePoolControlResult(ctx, controlv4.ControlPoolTopUp, false, envelope[:n], make([]byte, 524288))
	if e != nil || !out.Replay {
		t.Fatal(out, e)
	}
}

func TestPoolServiceAuditCapacityPreservesOriginalPendingFacts(t *testing.T) {
	h := ledgerv4.NewPoolServiceAuditTestHarness(t, ledgerv4.SQLiteAuditPolicy{OrdinaryRecords: 1, SafetyRecords: 1})
	ctx := context.Background()
	r, wire := h.Request(t, 1)
	h.Begin(t, r)
	response, _ := h.Response(t, r)
	p := serviceAdapter(t, h, func(_ context.Context, _ ledgerv4.TopUpServerSnapshot, dst []byte) (controlv4.PoolIssueResult, error) {
		return controlv4.PoolIssueResult{ResponseBytes: copy(dst, response)}, nil
	})
	d := serviceDecoder(t, h)
	envelope := make([]byte, 524288)
	n, failure, err := p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, envelope)
	if err != nil || !failure || n == 0 {
		t.Fatal("audit capacity published a batch", n, failure, err)
	}
	out, err := d.DecodePoolControlResult(ctx, controlv4.ControlPoolTopUp, true, envelope[:n], nil)
	if err != nil || out.Code != protocolv4.V4TopUpErrorCodeCapacityExhausted || out.Evidence != nil || out.FenceEvidence != nil || out.ResponseBytes != 0 {
		t.Fatal("audit capacity fabricated a terminal fact", out, err)
	}
	defer out.Release()
	client, err := h.Client.Recover(ctx)
	if err != nil || client.State != ledgerv4.TopUpJournalPending || client.Request != r || client.RetiredSequence != 0 || client.ArtifactFrontier != 0 {
		t.Fatal("audit failure released original client intent", client, err)
	}
	server, err := h.Store.Recover(ctx, h.Access)
	if err != nil || server.State != ledgerv4.TopUpServerPending || server.HighestArtifact != 0 {
		t.Fatal(server, err)
	}
}

func TestPoolServiceTerminalRetirementAndPermanentFence(t *testing.T) {
	for _, fenced := range []bool{false, true} {
		t.Run(map[bool]string{false: "original-terminal", true: "source-fence"}[fenced], func(t *testing.T) {
			h := ledgerv4.NewPoolServiceTestHarness(t)
			ctx := context.Background()
			r, wire := h.Request(t, 1)
			h.Begin(t, r)
			p := serviceAdapter(t, h, func(_ context.Context, s ledgerv4.TopUpServerSnapshot, dst []byte) (controlv4.PoolIssueResult, error) {
				return controlv4.PoolIssueResult{Deny: protocolv4.V4TopUpErrorCodeCapacityExhausted}, nil
			})
			d := serviceDecoder(t, h)
			envelope := make([]byte, 524288)
			if fenced {
				h.Fence()
			}
			n, failure, e := p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, envelope)
			if e != nil || !failure {
				t.Fatal(n, failure, e)
			}
			out, e := d.DecodePoolControlResult(ctx, controlv4.ControlPoolTopUp, true, envelope[:n], nil)
			if e != nil {
				t.Fatal(e)
			}
			defer out.Release()
			if fenced {
				if out.FenceEvidence == nil || out.Terminal != (ledgerv4.TopUpServerSnapshot{}) {
					t.Fatal("fabricated operation history", out)
				}
				e = h.Client.ConfirmPermanentFence(ctx, out.Fence, out.FenceEvidence)
			} else {
				if out.Evidence == nil || out.Terminal.State != ledgerv4.TopUpServerTerminal {
					t.Fatal(out)
				}
				e = h.Client.ConfirmTerminal(ctx, r, out.Terminal, out.Evidence)
			}
			if e != nil {
				t.Fatal(e)
			}
			out.Release()
			state, e := h.Client.Recover(ctx)
			if e != nil || state.State != ledgerv4.TopUpJournalTerminal || state.ArtifactFrontier != 0 {
				t.Fatal(state, e)
			}
			if fenced {
				if state.PermanentFenceGeneration != 1 || state.RetiredSequence != 1 {
					t.Fatal(state)
				}
				return
			}
			if state.RetiredSequence != 0 {
				t.Fatal("unretired terminal released operation")
			}
			h.Tick(500)
			n, failure, e = p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, envelope)
			if e != nil || !failure {
				t.Fatal(n, failure, e)
			}
			out, e = d.DecodePoolControlResult(ctx, controlv4.ControlPoolTopUp, true, envelope[:n], nil)
			if e != nil {
				t.Fatal(e)
			}
			defer out.Release()
			if out.Terminal.State != ledgerv4.TopUpServerRetired {
				t.Fatal(out)
			}
			if e = h.Client.ConfirmTerminal(ctx, r, out.Terminal, out.Evidence); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestPoolServicePermissionAndIssuerTail(t *testing.T) {
	h := ledgerv4.NewPoolServiceTestHarness(t)
	ctx := context.Background()
	_, wire := h.Request(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	p := serviceAdapter(t, h, func(context.Context, ledgerv4.TopUpServerSnapshot, []byte) (controlv4.PoolIssueResult, error) {
		close(entered)
		<-release
		return controlv4.PoolIssueResult{}, errors.New("issuer failed")
	})
	done := make(chan error, 1)
	go func() {
		n, _, e := p.Exchange(ctx, controlv4.ControlPoolTopUp, h.Access, wire, make([]byte, 524288))
		if n != 0 {
			done <- errors.New("closed service published")
			return
		}
		done <- e
	}()
	<-entered
	h.Denied(true)
	envelope := make([]byte, 524288)
	n, failure, e := p.Exchange(ctx, controlv4.ControlPoolAck, h.Access, []byte{0xff}, envelope)
	if e != nil || !failure || !bytes.Contains(envelope[:n], []byte("permission_denied")) {
		t.Fatal("permission lost to busy/malformed", n, failure, e)
	}
	p.Close()
	wait, cancel := context.WithCancel(ctx)
	cancel()
	if e = p.WaitCleanup(wait); !errors.Is(e, context.Canceled) {
		t.Fatal("live issuer refunded", e)
	}
	close(release)
	if e = <-done; e == nil {
		t.Fatal("canceled issuer returned success")
	}
	if e = p.WaitCleanup(ctx); e != nil {
		t.Fatal(e)
	}
}
