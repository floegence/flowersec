package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v7"
)

// The extra ordinary methods permit a long sequence on one session even with a
// single inbound handler slot. They are outside the four canonical contracts.
const sequenceBase, sequenceMethods = 8000, 128

func installSequence(r registrar, a *application) error {
	for n := range uint32(sequenceMethods) {
		id := uint32(sequenceBase) + n
		a.grant[id] = true
		if err := r.HandleRPC(id, func(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) {
			var item struct {
				Method   uint32 `json:"method"`
				Sequence int    `json:"sequence"`
			}
			if decode(raw, &item) != nil || item.Method != id || item.Sequence < 0 {
				return nil, bad(400)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if !a.allowed(ctx, id) {
				return nil, bad(403)
			}
			return raw, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func runEndpoint(args []string) error {
	f := flag.NewFlagSet("endpoint", flag.ContinueOnError)
	inv := f.String("invitation", "", "local endpoint invitation file")
	ingress := f.String("ingress", "", "authorized local Tunnel URL; omit for Direct or a single authorized Tunnel URL")
	roots := f.String("roots", "", "trusted CA bundle (PEM)")
	dir := f.String("state", "", "private durable spend directory")
	fixture := f.String("contracts", "parity-contracts.json", "shared contract manifest")
	role := f.String("role", "", "first or second; with FSEC_EXAMPLE_LARGE_RPC=1, first calls the 32 MiB echo and second serves it")
	sequence := f.Int("sequence", 0, "additional bilateral RPC sequence length")
	if err := f.Parse(args); err != nil {
		return err
	}
	if (*role != "first" && *role != "second") || *sequence < 0 {
		return errors.New("role and nonnegative sequence length required")
	}
	var large bool
	switch os.Getenv("FSEC_EXAMPLE_LARGE_RPC") {
	case "", "0":
	case "serve":
		if *role != "second" {
			return errors.New("FSEC_EXAMPLE_LARGE_RPC=serve requires -role second")
		}
		fallthrough
	case "1":
		large = true
	default:
		return errors.New("FSEC_EXAMPLE_LARGE_RPC must be 0, 1, or serve")
	}
	limits, err := endpointFrameLimits(large)
	if err != nil {
		return err
	}
	if err := privateDir(*dir); err != nil {
		return err
	}
	encoded, err := os.ReadFile(*inv)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(*roots)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("invalid trusted roots")
	}
	want, err := readContracts(*fixture)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	regs := fs.NewRPCHandlers()
	a, err := install(regs, want, time.Now().Add(90*time.Second), large)
	if err != nil {
		return err
	}
	if *sequence > 0 {
		if err = installSequence(regs, a); err != nil {
			return err
		}
	}
	artifact, err := fs.ParseArtifact(encoded)
	if err != nil {
		return err
	}
	lease, err := fs.NewArtifactLease(artifact, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return mark(*dir, fmt.Sprintf("spent-%x", sha256.Sum256(encoded)))
	})
	if err != nil {
		return err
	}
	s, err := fs.Connect(ctx, lease, fs.ConnectorOptions{TrustRoots: pool, Origin: origin, RPCHandlers: regs, TunnelEndpoint: *ingress, MaxConcurrentRPCRequests: 1, RPCFrameLimits: limits})
	if err != nil {
		return err
	}
	defer s.Close()
	a.bind(s)
	// An echo-only caller need not serve reverse queries. Peers running both
	// workloads may still request the four-contract check in large mode.
	if !large || os.Getenv("FSEC_EXAMPLE_QUERY") == "1" {
		if err = verifyContracts(ctx, s, want); err != nil {
			return err
		}
	}
	if err = runSequence(ctx, s, *sequence); err != nil {
		return err
	}
	if large {
		if *role == "first" {
			if err = verifyLargeEcho(ctx, s); err != nil {
				return err
			}
			if err = s.Close(); err != nil {
				return err
			}
		} else if err = serveLargeEchoPeer(ctx, s, a); err != nil {
			return err
		}
		if err = waitEndpointClose(ctx, s); err != nil {
			return err
		}
		if *role == "second" {
			if err = s.Close(); err != nil {
				return err
			}
		}
		fmt.Printf("role=%s large_echo=7010 close=%s\n", *role, fs.SessionClosed)
		return nil
	}
	var echo value
	if err = s.RPC().Call(ctx, 7001, value{"ping"}, &echo); err != nil || echo.Value != "ping" {
		return errors.Join(errors.New("echo mismatch"), err)
	}
	if *role == "first" {
		md, err := fs.NewStreamMetadata(map[string]any{"cell": "tunnel"})
		if err != nil {
			return err
		}
		st, err := s.OpenStream(ctx, "parity.echo", md)
		if err != nil {
			return err
		}
		defer st.Close()
		if err = writeAndFinish(st, "hello"); err != nil {
			return err
		}
		if err = readExact(st, "world"); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.datagramReady:
		}
	} else {
		in, err := s.AcceptStream(ctx)
		if err != nil {
			return err
		}
		st := in.Stream
		defer st.Close()
		if in.Kind != "parity.echo" || in.Metadata.Values()["cell"] != "tunnel" {
			return errors.New("incorrect stream metadata")
		}
		if err = answerEcho(st); err != nil {
			return err
		}
		var observed value
		if err = s.RPC().Call(ctx, 7005, value{"datagram-ready"}, &observed); err != nil || observed.Value != "datagram-ready" {
			return errors.Join(errors.New("completion acknowledgment failed"), err)
		}
		// Only the caller knows the complete acknowledgment has arrived.
		if err = s.Close(); err != nil {
			return err
		}
	}
	if err = waitEndpointClose(ctx, s); err != nil {
		return err
	}
	fmt.Printf("role=%s contracts_verified=4 sequence=%d stream=complete close=%s\n", *role, *sequence, fs.SessionClosed)
	return nil
}

func endpointFrameLimits(large bool) (fs.RPCFrameLimits, error) {
	var limits fs.RPCFrameLimits
	raw, ok := os.LookupEnv("FSEC_RPC_FRAME_BYTES")
	if !ok {
		if large {
			return limits, errors.New("32 MiB echo requires FSEC_RPC_FRAME_BYTES on both endpoints")
		}
		return limits, nil
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || n == 0 || int(n) <= 0 {
		return limits, errors.New("FSEC_RPC_FRAME_BYTES must be a positive 32-bit frame size supported on this platform")
	}
	// Request and response each carry at most one nonzero 53-bit request ID.
	const minFrame = (largeEchoBytes+2)/3*4 + len(`{"type_id":7010,"request_id":9007199254740991,"response_to":0,"payload":""}`)
	if large && n < uint64(minFrame) {
		return limits, fmt.Errorf("32 MiB echo requires FSEC_RPC_FRAME_BYTES >= %d", minFrame)
	}
	return fs.RPCFrameLimits{ReadBytes: int(n), WriteBytes: int(n)}, nil
}

func serveLargeEchoPeer(ctx context.Context, s fs.Session, a *application) error {
	// The peer closes after verifying the RPC reply. Some clients also run
	// their ordinary stream echo before closing; others use only the RPC.
	for {
		in, err := s.AcceptStream(ctx)
		if err != nil {
			var terminal *fs.SessionError
			if !errors.As(err, &terminal) || terminal.Code() != fs.SessionClosed && terminal.Code() != fs.SessionGoingAway {
				return err
			}
			break
		}
		if in.Kind != "parity.echo" {
			_ = in.Stream.Reset()
			return errors.New("unexpected application stream during 32 MiB echo")
		}
		stop := context.AfterFunc(ctx, func() { _ = in.Stream.Reset() })
		err = answerEcho(in.Stream)
		stop()
		if err = errors.Join(err, in.Stream.Close()); err != nil {
			return err
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.largeEchoHandled {
		return errors.New("peer closed without an authorized 32 MiB echo")
	}
	return nil
}

func answerEcho(st fs.ByteStream) error {
	if err := readExact(st, "hello"); err != nil {
		return err
	}
	return writeAndFinish(st, "world")
}

func waitEndpointClose(ctx context.Context, s fs.Session) error {
	term, err := s.WaitTermination(ctx)
	if err != nil {
		return err
	}
	if term.Error.Code() != fs.SessionClosed {
		return fmt.Errorf("unexpected terminal state %s", term.Error.Code())
	}
	return nil
}

func runSequence(ctx context.Context, s fs.Session, n int) error {
	for i := range n {
		id := uint32(sequenceBase + i%sequenceMethods)
		type item struct {
			Method   uint32 `json:"method"`
			Sequence int    `json:"sequence"`
		}
		send := item{id, i}
		var got item
		if err := s.RPC().Call(ctx, id, send, &got); err != nil {
			return err
		}
		if got != send {
			return errors.New("sequence response mismatch")
		}
	}
	return nil
}

func writeAndFinish(st fs.ByteStream, v string) error {
	n, err := io.WriteString(st, v)
	if err != nil {
		return err
	}
	if n != len(v) {
		return io.ErrShortWrite
	}
	return st.CloseWrite()
}
func readExact(st fs.ByteStream, v string) error {
	b, err := io.ReadAll(io.LimitReader(st, int64(len(v)+1)))
	if err != nil {
		return err
	}
	if string(b) != v {
		return errors.New("stream data differs")
	}
	return nil
}
