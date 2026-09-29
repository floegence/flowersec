package controlv4

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
	"github.com/floegence/flowersec/flowersec-go/v6/internal/sessionv4"
)

type poolTestDecoder func(context.Context, uint32, bool, []byte, []byte) (sessionv4.TopUpExchangeResult, error)

func (f poolTestDecoder) DecodePoolControlResult(ctx context.Context, method uint32, failure bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
	return f(ctx, method, failure, body, dst)
}

func testPoolHTTPS(t *testing.T, handler http.Handler, decode poolTestDecoder) (*PoolHTTPSTransport, *resourcev4.Root) {
	t.Helper()
	bootstrap, root := testHTTPSBootstrap(t, handler, nil)
	config := PoolHTTPSConfig{HTTPS: bootstrap.config, Decoder: decode, RuntimeBytes: 65536}
	config.HTTPS.TLS = bootstrap.tls
	charge, err := PoolHTTPSTransportCharge(config)
	if err != nil {
		t.Fatal(err)
	}
	providerCharge, err := HTTPSBootstrapCharge(config.HTTPS)
	if err != nil {
		t.Fatal(err)
	}
	reserve := func(id byte, charge resourcev4.Vector) resourcev4.Reference {
		ref, e := root.Reserve(resourcev4.OwnerKey{ProfileRevision: [32]byte{1}, Environment: [16]byte{1}, Instance: [16]byte{id}, Backing: [16]byte{id}, Kind: 1}, charge)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(ref.Release)
		return ref
	}
	p, err := NewPoolHTTPSTransport(config, reserve(30, charge), reserve(31, providerCharge), reserve(32, resourcev4.Vector{resourcev4.SDKBytes: 4096}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := p.WaitCleanup(ctx); err != nil {
			t.Error(err)
		}
	})
	return p, root
}

func TestPoolHTTPSOriginalMethodsAndApplicationErrors(t *testing.T) {
	var calls atomic.Int32
	p, _ := testPoolHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/cbor" || r.Header.Get("Accept-Encoding") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Cache-Control") != "no-store" || r.ContentLength != 3 || r.URL.RawQuery != "" {
			t.Error("changed explicit control request")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, []byte{0xa1, 0, 1}) {
			t.Error("original request changed", err)
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "3")
		switch r.URL.Path {
		case "/revocation/pool/top-up":
		case "/revocation/pool/ack":
			w.WriteHeader(http.StatusConflict)
		default:
			t.Error("wrong application endpoint")
		}
		_, _ = w.Write([]byte{0xa1, 0, 2})
	}), func(_ context.Context, method uint32, failure bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
		if !bytes.Equal(body, []byte{0xa1, 0, 2}) {
			t.Error("decoder received different original envelope")
		}
		if method == ControlPoolAck && failure {
			return sessionv4.TopUpExchangeResult{Code: protocolv4.V4TopUpErrorCodePermissionDenied}, nil
		}
		if method != ControlPoolTopUp || failure {
			return sessionv4.TopUpExchangeResult{}, ErrResponse
		}
		return sessionv4.TopUpExchangeResult{ResponseBytes: copy(dst, body)}, nil
	})
	dst := make([]byte, 524288)
	r, err := p.TopUp(context.Background(), []byte{0xa1, 0, 1}, dst)
	if err != nil || r.ResponseBytes != 3 || !bytes.Equal(dst[:3], []byte{0xa1, 0, 2}) {
		t.Fatal(r, err)
	}
	r, err = p.Ack(context.Background(), []byte{0xa1, 0, 1})
	if err != nil || r.Code != protocolv4.V4TopUpErrorCodePermissionDenied || r.Evidence != nil || calls.Load() != 2 {
		t.Fatal(r, err, calls.Load())
	}
}

func TestPoolHTTPSRejectsRedirectsOversizeAndResultKind(t *testing.T) {
	for _, mode := range []string{"redirect", "oversize", "compressed", "application-error-as-success"} {
		t.Run(mode, func(t *testing.T) {
			var calls, decodes atomic.Int32
			p, _ := testPoolHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/cbor")
				w.Header().Set("Content-Length", "1")
				switch mode {
				case "redirect":
					w.Header().Set("Location", "/unexpected")
					w.WriteHeader(http.StatusTemporaryRedirect)
				case "oversize":
					w.Header().Set("Content-Length", strconv.Itoa(524289))
				case "compressed":
					w.Header().Set("Content-Encoding", "gzip")
				case "application-error-as-success":
					w.WriteHeader(http.StatusConflict)
				}
				_, _ = w.Write([]byte{0xa0})
			}), func(_ context.Context, _ uint32, _ bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
				decodes.Add(1)
				return sessionv4.TopUpExchangeResult{ResponseBytes: copy(dst, body)}, nil
			})
			dst := make([]byte, 524288)
			r, err := p.TopUp(context.Background(), []byte{0xa0}, dst)
			if !errors.Is(err, ErrResponse) || r != (sessionv4.TopUpExchangeResult{}) || calls.Load() != 1 || !bytes.Equal(dst, make([]byte, len(dst))) {
				t.Fatal("invalid response escaped", r, err, calls.Load())
			}
			if mode != "application-error-as-success" && decodes.Load() != 0 {
				t.Fatal("invalid HTTP body entered decoder")
			}
		})
	}
}

func TestPoolHTTPSCloseJoinsLateDecoderAndClearsOutput(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	p, root := testPoolHTTPS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("Content-Length", "1")
		_, _ = w.Write([]byte{0xa0})
	}), func(_ context.Context, _ uint32, _ bool, body, dst []byte) (sessionv4.TopUpExchangeResult, error) {
		close(entered)
		<-release
		return sessionv4.TopUpExchangeResult{ResponseBytes: copy(dst, body)}, nil
	})
	dst := make([]byte, 524288)
	done := make(chan error, 1)
	go func() { _, err := p.TopUp(context.Background(), []byte{0xa0}, dst); done <- err }()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("decoder not reached", err)
	case <-time.After(time.Second):
		t.Fatal("decoder not reached")
	}
	if _, err := p.Ack(context.Background(), []byte{0xa0}); !errors.Is(err, ErrBusy) {
		t.Fatal("late decoder's physical position reused", err)
	}
	before := root.Snapshot()
	p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := p.WaitCleanup(ctx); !errors.Is(err, context.DeadlineExceeded) || root.Snapshot() != before {
		t.Fatal("live decoder refunded", err)
	}
	once.Do(func() { close(release) })
	if err := <-done; !errors.Is(err, context.Canceled) || !bytes.Equal(dst, make([]byte, len(dst))) {
		t.Fatal("late decoder output published", err)
	}
	if err := p.WaitCleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}
