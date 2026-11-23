package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v7"
)

const namespace = "flowersec.parity"
const queryID = 7004
const largeEchoID = 7010 // A separate binary echo; parity unary declarations allow only 4096 bytes.
const largeEchoBytes = 32 << 20

var types = [...]uint32{7001, 7002, 7003, 7005}

type manifest struct {
	Namespace string            `json:"namespace"`
	Query     uint32            `json:"query_type_id"`
	Contracts map[uint32]string `json:"contracts"`
}

func readContracts(path string) (map[uint32][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := decode(data, &m); err != nil {
		return nil, err
	}
	if m.Namespace != namespace || m.Query != queryID || len(m.Contracts) != len(types) {
		return nil, errors.New("invalid parity manifest")
	}
	want := make(map[uint32][]byte, len(types))
	for _, id := range types {
		b, err := strictBase64(m.Contracts[id])
		if err != nil {
			return nil, err
		}
		want[id] = b
	}
	return want, nil
}

func strictBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("noncanonical contract encoding")
	}
	return b, nil
}

func decode(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

type registrar interface {
	HandleRPC(uint32, fs.RPCHandler) error
	HandleNotification(uint32, fs.RPCNotificationHandler) error
}

type query struct {
	Namespace string   `json:"namespace"`
	TypeIDs   []uint32 `json:"type_ids"`
}

type reply struct {
	Contracts []string `json:"contracts"`
}
type value struct {
	Value string `json:"value"`
}

type largeEchoPayload []byte

func (p *largeEchoPayload) UnmarshalJSON(raw []byte) error {
	// encoding/json also accepts numeric arrays for []byte. The wire value
	// for this method is a Base64 JSON string in both directions.
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return errors.New("32 MiB echo requires a Base64 string")
	}
	encoded := raw[1 : len(raw)-1]
	codec := base64.StdEncoding.Strict()
	var decoded []byte
	var err error
	if bytes.IndexByte(encoded, '\\') >= 0 {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		if len(text) != codec.EncodedLen(largeEchoBytes) {
			return errors.New("incorrect 32 MiB echo size")
		}
		decoded, err = codec.DecodeString(text)
	} else {
		if len(encoded) != codec.EncodedLen(largeEchoBytes) {
			return errors.New("incorrect 32 MiB echo size")
		}
		decoded, err = codec.AppendDecode(nil, encoded)
	}
	if err != nil || len(decoded) != largeEchoBytes {
		return errors.New("invalid 32 MiB Base64 payload")
	}
	*p = decoded
	return nil
}

// Each application is bound to its own authorized endpoint and session. The
// grant is live: a check on admission alone cannot authorize a later effect.
type application struct {
	mu                             sync.Mutex
	until                          time.Time
	grant                          map[uint32]bool
	registered                     map[uint32][]byte
	current                        fs.Session
	observed                       int
	largeEchoHandled               bool
	notifications                  chan struct{}
	ready, complete, datagramReady chan struct{}
}

func install(r registrar, declarations map[uint32][]byte, until time.Time, large bool) (*application, error) {
	a := &application{until: until, grant: map[uint32]bool{queryID: true}, registered: make(map[uint32][]byte), notifications: make(chan struct{}), ready: make(chan struct{}), complete: make(chan struct{}), datagramReady: make(chan struct{})}
	for _, id := range types {
		var err error
		if id == 7002 {
			err = r.HandleNotification(id, a.notify)
		} else {
			err = r.HandleRPC(id, func(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) { return a.unary(ctx, id, raw) })
		}
		if err != nil {
			return nil, err
		}
		a.registered[id] = bytes.Clone(declarations[id])
		a.grant[id] = true
	}
	if err := r.HandleRPC(queryID, a.query); err != nil {
		return nil, err
	}
	if large {
		a.grant[largeEchoID] = true
		if err := r.HandleRPC(largeEchoID, func(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) {
			a.mu.Lock()
			allowed := a.allowed(ctx, largeEchoID)
			a.mu.Unlock()
			if !allowed {
				return nil, bad(403)
			}
			var b largeEchoPayload
			if err := b.UnmarshalJSON(raw); err != nil {
				return nil, bad(400)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if !a.allowed(ctx, largeEchoID) {
				return nil, bad(403)
			}
			a.largeEchoHandled = true
			return b, nil
		}); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func bad(code uint32) *fs.RPCError { return &fs.RPCError{Code: code} }
func (a *application) allowed(ctx context.Context, id uint32) bool {
	return ctx.Err() == nil && time.Now().Before(a.until) && a.grant[id]
}
func (a *application) bind(s fs.Session) { a.mu.Lock(); a.current = s; a.mu.Unlock() }
func signal(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func (a *application) query(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) {
	var q query
	if decode(raw, &q) != nil || q.Namespace != namespace || len(q.TypeIDs) == 0 {
		return nil, bad(400)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowed(ctx, queryID) {
		return nil, bad(403)
	}
	result := reply{Contracts: make([]string, 0, len(q.TypeIDs))}
	for _, id := range q.TypeIDs {
		b, ok := a.registered[id]
		if !ok || !a.allowed(ctx, id) {
			return nil, bad(403)
		}
		result.Contracts = append(result.Contracts, base64.StdEncoding.EncodeToString(b))
	}
	return result, nil
}

func (a *application) unary(ctx context.Context, id uint32, raw json.RawMessage) (any, *fs.RPCError) {
	var v value
	if len(raw) > 4096 || decode(raw, &v) != nil {
		return nil, bad(400)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowed(ctx, id) {
		return nil, bad(403)
	}
	switch id {
	case 7001:
		if v.Value != "ping" && v.Value != "notifications-observed" {
			return nil, bad(400)
		}
		for v.Value == "notifications-observed" && a.observed < 2 {
			changed := a.notifications
			bounded, cancel := context.WithDeadline(ctx, a.until)
			a.mu.Unlock()
			select {
			case <-changed:
			case <-bounded.Done():
			}
			cancel()
			a.mu.Lock()
			if !a.allowed(ctx, id) {
				return nil, bad(403)
			}
		}
		signal(a.ready)
	case 7003:
		if v.Value != "complete" {
			return nil, bad(400)
		}
		if a.current == nil {
			return nil, bad(503)
		}
		s := a.current
		bounded, cancel := context.WithDeadline(ctx, a.until)
		defer cancel()
		if s.Rekey(bounded) != nil {
			return nil, bad(503)
		}
		if !a.allowed(ctx, id) {
			return nil, bad(403)
		}
		if _, err := s.ProbeLiveness(bounded); err != nil {
			return nil, bad(503)
		}
		if !a.allowed(ctx, id) {
			return nil, bad(403)
		}
		signal(a.complete)
	case 7005:
		if v.Value != "datagram-ready" {
			return nil, bad(400)
		}
		signal(a.datagramReady)
	default:
		return nil, bad(404)
	}
	return raw, nil
}

func (a *application) notify(ctx context.Context, raw json.RawMessage) error {
	var v value
	if len(raw) > 4096 || decode(raw, &v) != nil || v.Value != "notify" {
		return errors.New("invalid notification")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.allowed(ctx, 7002) || a.observed >= 2 {
		return errors.New("notification refused")
	}
	a.observed++
	close(a.notifications)
	a.notifications = make(chan struct{})
	return nil
}

func verifyContracts(ctx context.Context, session fs.Session, want map[uint32][]byte) error {
	var r reply
	if err := session.RPC().Call(ctx, queryID, query{Namespace: namespace, TypeIDs: types[:]}, &r); err != nil {
		return err
	}
	if len(r.Contracts) != len(types) {
		return fmt.Errorf("received %d contracts, want %d", len(r.Contracts), len(types))
	}
	for i, id := range types {
		b, err := strictBase64(r.Contracts[i])
		if err != nil || !bytes.Equal(b, want[id]) {
			return fmt.Errorf("contract %d differs from its declaration", id)
		}
	}
	return nil
}
