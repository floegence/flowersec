package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v7"
	cp "github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

const capacityPairs = 1000

type capacityOptions struct {
	NativeSDK, Carrier, ServerCarrier, MaterialPath, StoreDirectory string
	Sessions, StreamsPerSession, OperationTimeoutMS                 int
	DirectReplacement, TunnelReplacement                            bool
	OverlapSuccessors                                               int
}
type capacityRequest struct {
	ID, Cancel                   uint64
	Op, Session, ExpectedSession string
	TimeoutMS, Count, Generation int
	Index                        *int
	Options                      capacityOptions
	Operation                    string
	Bytes                        int
}
type capacityPair struct {
	id                   string
	index                int
	generation           int
	keys                 [2]string
	expires              [2]time.Time
	ends                 [2]fs.Session
	accepted             chan fs.Session
	acceptDone           <-chan struct{}
	unsubscribe          [2]func()
	terminated           sync.Once
	watchers             sync.WaitGroup
	stopWatching         context.CancelFunc
	observed             [2]atomic.Int32
	live, closing        atomic.Bool
	established, retired atomic.Bool
	responsive           atomic.Bool
	mu                   sync.Mutex
}
type capacityProduct struct {
	mu                        sync.RWMutex
	opts                      capacityOptions
	prepared, closing         bool
	pairs                     map[string]*capacityPair
	seen                      map[int]string
	drainedPositions          int
	byKey                     map[string]*capacityPair
	url, invitations, records string
	local                     [2]string
	roots                     *x509.CertPool
	want                      map[uint32][]byte
	client, tunnelServer      *fs.RPCHandlers
	tunnelStreams             *fs.StreamHandlers
	overlap                   []capacitySuccession
	overlapPeak               atomic.Bool
	server                    *fs.SessionHandlers
	listener                  fs.DirectListener
	http                      *fs.WebSocketHTTPServer
	stop                      context.CancelFunc
	ready                     chan error
	uplink                    func(any) error
	ctx                       context.Context
	wg                        sync.WaitGroup
	terminated                atomic.Uint64
	directLeases              int
	releaseErr                error
	releaseChanged            chan struct{}
}

type capacitySuccession struct{ old, next *capacityPair }

func (d *capacityProduct) successorsResponsiveLocked() bool {
	if len(d.overlap) != d.opts.OverlapSuccessors {
		return false
	}
	for _, generation := range d.overlap {
		next := generation.next
		if !next.responsive.Load() || !next.live.Load() || next.closing.Load() {
			return false
		}
	}
	return true
}

func (d *capacityProduct) mayRetire(p *capacityPair) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.overlapPeak.Load() {
		return false
	}
	for _, generation := range d.overlap {
		if !generation.old.retired.Load() {
			return generation.old == p && d.successorsResponsiveLocked()
		}
	}
	return true
}

func readPrivate(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&077 != 0 || st.Size() < 1 || st.Size() > max {
		return nil, errors.New("invalid capacity credential file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) != st.Size() {
		return nil, errors.New("incomplete capacity credential file")
	}
	return b, nil
}

func (d *capacityProduct) permitted(ctx context.Context, role int) (*capacityPair, bool) {
	id, ok := fs.RPCChannelID(ctx)
	if !ok || ctx.Err() != nil {
		return nil, false
	}
	d.mu.RLock()
	p := d.pairs[id]
	d.mu.RUnlock()
	return p, d.hasGrant(p, role)
}

func (d *capacityProduct) hasGrant(p *capacityPair, role int) bool {
	if p == nil || p.closing.Load() || !time.Now().Before(p.expires[role]) {
		return false
	}
	info, err := os.Lstat(filepath.Join(d.records, p.keys[role]+".json"))
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&077 == 0
}

// Each role registers its routes once. Both the query and the actual methods
// consult the same live grant for the authenticated channel on every request.
func (d *capacityProduct) register(r registrar, role int) error {
	declared := make(map[uint32][]byte, len(types))
	for _, id := range types {
		if id == 7002 {
			if err := r.HandleNotification(id, func(ctx context.Context, raw json.RawMessage) error {
				var in value
				if _, ok := d.permitted(ctx, role); !ok || decode(raw, &in) != nil || in.Value != "notify" {
					return errors.New("notification denied")
				}
				return nil
			}); err != nil {
				return err
			}
		} else if err := r.HandleRPC(id, func(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) {
			p, ok := d.permitted(ctx, role)
			if !ok {
				return nil, bad(403)
			}
			var in value
			if len(raw) > 4096 || decode(raw, &in) != nil {
				return nil, bad(400)
			}
			switch id {
			case 7001:
				if in.Value != "ping" && !(in.Value == "notifications-observed" && p.observed[role].Load() >= 2) {
					return nil, bad(400)
				}
			case 7003:
				p.mu.Lock()
				s := p.ends[role]
				p.mu.Unlock()
				if in.Value != "complete" || s == nil {
					return nil, bad(400)
				}
				if err := s.Rekey(ctx); err != nil {
					return nil, bad(503)
				}
				if _, err := s.ProbeLiveness(ctx); err != nil {
					return nil, bad(503)
				}
			case 7005:
				if in.Value != "datagram-ready" {
					return nil, bad(400)
				}
			}
			return raw, nil
		}); err != nil {
			return err
		}
		declared[id] = d.want[id]
	}
	return r.HandleRPC(queryID, func(ctx context.Context, raw json.RawMessage) (any, *fs.RPCError) {
		if _, ok := d.permitted(ctx, role); !ok {
			return nil, bad(403)
		}
		var q query
		if decode(raw, &q) != nil || q.Namespace != namespace || len(q.TypeIDs) == 0 || len(q.TypeIDs) > len(declared) {
			return nil, bad(400)
		}
		result := reply{}
		for _, id := range q.TypeIDs {
			b, ok := declared[id]
			if !ok {
				return nil, bad(404)
			}
			result.Contracts = append(result.Contracts, base64.StdEncoding.EncodeToString(b))
		}
		return result, nil
	})
}

func (d *capacityProduct) init(o capacityOptions) (any, error) {
	if o.NativeSDK != "go" || o.Sessions != capacityPairs || o.StreamsPerSession != 0 || o.OperationTimeoutMS < 1 || !filepath.IsAbs(o.MaterialPath) || !filepath.IsAbs(o.StoreDirectory) {
		return nil, errors.New("Go Direct1000 or Tunnel1000 configuration required")
	}
	if o.TunnelReplacement && (o.DirectReplacement || o.Carrier != "raw-quic" || o.ServerCarrier != "raw-quic") {
		return nil, errCapacityConfiguration
	}
	if o.OverlapSuccessors != 0 {
		directWSS := o.ServerCarrier == "" && o.Carrier == "websocket"
		tunnelQQ := o.ServerCarrier == "raw-quic" && o.Carrier == "raw-quic"
		if o.OverlapSuccessors != 4 || o.TunnelReplacement || o.DirectReplacement || (!directWSS && !tunnelQQ) {
			return nil, errCapacityConfiguration
		}
	}
	if err := privateDir(o.StoreDirectory); err != nil {
		return nil, err
	}
	d.opts = o
	d.pairs = make(map[string]*capacityPair)
	d.seen = make(map[int]string)
	d.byKey = make(map[string]*capacityPair)
	base := filepath.Dir(o.MaterialPath)
	d.invitations = envPath("FSEC_CAPACITY_INVITATION_DIR", filepath.Join(base, "invitations"))
	d.records = envPath("FSEC_CAPACITY_RECORD_DIR", filepath.Join(base, "records"))
	var err error
	d.want, err = readContracts(envPath("FSEC_PARITY_CONTRACTS", "parity-contracts.json"))
	if err != nil {
		return nil, err
	}
	d.client = fs.NewRPCHandlers()
	if err = d.register(d.client, 0); err != nil {
		return nil, err
	}
	if o.ServerCarrier != "" {
		d.tunnelServer = fs.NewRPCHandlers()
		if err = d.register(d.tunnelServer, 1); err != nil {
			return nil, err
		}
		d.local = [2]string{os.Getenv("FSEC_CAPACITY_INGRESS_A"), os.Getenv("FSEC_CAPACITY_INGRESS_B")}
		if d.local[0] == "" || d.local[1] == "" {
			return nil, errors.New("each Tunnel leg requires its deployed ingress URL")
		}
		if o.OverlapSuccessors != 0 {
			if d.local[0] != d.local[1] || !strings.HasPrefix(d.local[0], "quic://") {
				return nil, errCapacityConfiguration
			}
			d.tunnelStreams, err = fs.NewStreamHandlers(fs.StreamHandlerOptions{})
			if err != nil {
				return nil, err
			}
			if err = d.registerCapacityBusiness(d.tunnelServer, d.tunnelStreams.HandleStream); err != nil {
				return nil, err
			}
		}
		pem, err := os.ReadFile(os.Getenv("FSEC_CAPACITY_ROOTS"))
		if err != nil {
			return nil, err
		}
		d.roots = x509.NewCertPool()
		if !d.roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid ingress roots")
		}
		return map[string]any{"ingressURLs": d.local}, nil
	}
	d.server, err = fs.NewSessionHandlers(fs.SessionHandlerOptions{})
	if err != nil {
		return nil, err
	}
	if err = d.register(d.server, 1); err != nil {
		return nil, err
	}
	var frame fs.RPCFrameLimits
	if o.OverlapSuccessors != 0 {
		if err = d.registerCapacityBusiness(d.server, d.server.HandleStream); err != nil {
			return nil, err
		}
		frame = capacityBusinessFrame()
	}
	var tc *tls.Config
	tc, d.roots, err = cert()
	if err != nil {
		return nil, err
	}
	var ln net.Listener
	switch o.Carrier {
	case "websocket":
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		d.url = "wss://" + ln.Addr().String() + fs.WebSocketDirectPath
		d.listener = fs.NewWebSocketDirectListener()
	case "raw-quic":
		d.listener, err = fs.NewRawQUICDirectListener(fs.RawQUICListenerOptions{Address: "127.0.0.1:0", TLSConfig: tc, MaxInboundStreams: 32})
		if err != nil {
			return nil, err
		}
		d.url = "quic://" + d.listener.Address()
	case "webtransport":
		d.listener, err = fs.NewWebTransportDirectListener(fs.WebTransportListenerOptions{Address: "127.0.0.1:0", TLSConfig: tc, MaxInboundStreams: 32, CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == origin }})
		if err != nil {
			return nil, err
		}
		d.url = "https://" + d.listener.Address() + "/flowersec/webtransport/v5/direct"
	default:
		return nil, errors.New("unsupported Direct carrier")
	}
	d.releaseChanged = make(chan struct{}, 1)
	a, err := fs.NewAcceptor(fs.AcceptorOptions{RPCFrameLimits: frame, AllowedOrigins: []string{origin}, Listeners: []fs.DirectListener{d.listener}, MaxDirectSessions: uint16(o.Sessions + o.OverlapSuccessors), Authorize: d.authorize, Release: d.releaseDirect, ResolveHandlers: func(ctx context.Context, r cp.RuntimeAuthorizationRequest) (*fs.SessionHandlers, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return d.server, nil
	}, OnSession: func(ctx context.Context, s fs.Session, id string) error {
		d.mu.RLock()
		p := d.pairs[id]
		d.mu.RUnlock()
		if p == nil {
			return errors.New("unexpected accepted channel")
		}
		select {
		case p.accepted <- s:
		case <-p.acceptDone:
			return context.Canceled
		case <-ctx.Done():
			return ctx.Err()
		}
		<-ctx.Done()
		return ctx.Err()
	}})
	if err != nil {
		if ln != nil {
			ln.Close()
		}
		d.listener.Close()
		return nil, err
	}
	var addr string
	if ln != nil {
		d.http, err = fs.NewWebSocketHTTPServer(fs.WebSocketHTTPServerOptions{Handler: a.Handler(), TLSConfig: tc})
		if err != nil {
			ln.Close()
			d.listener.Close()
			return nil, err
		}
		addr = ln.Addr().String()
		d.ready = make(chan error, 1)
		go func() { d.ready <- d.http.Serve(ln) }()
	} else {
		addr = d.listener.Address()
		d.ready = make(chan error, 1)
		go func() { d.ready <- a.Serve(d.ctx) }()
	}
	return map[string]string{"endpointAddress": addr, "endpointURL": d.url}, nil
}

func envPath(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func (d *capacityProduct) authorize(ctx context.Context, r cp.RuntimeAuthorizationRequest) (cp.AuthorizationResponse, error) {
	key := r.LookupKey()
	if !validLookupKey(key) {
		return cp.AuthorizationResponse{}, errors.New("invalid credential key")
	}
	d.mu.RLock()
	p := d.byKey[key]
	d.mu.RUnlock()
	if p == nil || p.closing.Load() {
		return cp.RejectRuntime("invalid_credential", false)
	}
	b, err := readPrivate(filepath.Join(d.records, key+".json"), 96<<10)
	if err != nil {
		return cp.AuthorizationResponse{}, err
	}
	rec, err := cp.ParseAuthorizationRecord(b)
	if err != nil {
		return cp.AuthorizationResponse{}, err
	}
	resp, err := cp.AuthorizeRuntime(r, rec, key)
	if err != nil {
		return resp, err
	}
	var v struct{ Decision string }
	if json.Unmarshal(resp.JSON(), &v) != nil {
		return cp.AuthorizationResponse{}, errors.New("invalid authorization decision")
	}
	if v.Decision == "allow" {
		d.mu.Lock()
		if d.closing || p.closing.Load() {
			d.mu.Unlock()
			return cp.RejectRuntime("invalid_credential", false)
		}
		d.directLeases++
		d.mu.Unlock()
		if err = ctx.Err(); err == nil {
			err = mark(d.opts.StoreDirectory, "admitted-"+key)
		}
		if err != nil {
			d.finishDirectLease(nil)
			return cp.AuthorizationResponse{}, err
		}
	}
	return resp, nil
}

func (d *capacityProduct) releaseDirect(_ context.Context, key string) {
	var err error
	if validLookupKey(key) {
		err = mark(d.opts.StoreDirectory, "released-"+key)
	} else {
		err = errors.New("invalid direct lease ID")
	}
	d.finishDirectLease(err)
}

func (d *capacityProduct) finishDirectLease(err error) {
	d.mu.Lock()
	d.directLeases--
	if d.directLeases < 0 && err == nil {
		err = errors.New("unexpected direct release")
	}
	if d.releaseErr == nil {
		d.releaseErr = err
	}
	d.mu.Unlock()
	select {
	case d.releaseChanged <- struct{}{}:
	default:
	}
}

func (d *capacityProduct) waitDirectReleases(ctx context.Context) error {
	for {
		d.mu.RLock()
		pending, err := d.directLeases, d.releaseErr
		d.mu.RUnlock()
		if pending <= 0 {
			return err
		}
		select {
		case <-ctx.Done():
			return errors.Join(err, fmt.Errorf("waiting for %d direct lease releases: %w", pending, ctx.Err()))
		case <-d.releaseChanged:
		}
	}
}

type offered struct {
	handle  fs.Artifact
	key     string
	expires time.Time
}

func (d *capacityProduct) offered(id string, role int) (offered, error) {
	path := filepath.Join(d.invitations, id+".json")
	if d.opts.ServerCarrier != "" {
		path = filepath.Join(d.invitations, id, []string{"first.json", "second.json"}[role])
	}
	raw, err := readPrivate(path, 65536)
	if err != nil {
		return offered{}, err
	}
	a, err := fs.ParseArtifact(raw)
	if err != nil {
		return offered{}, err
	}
	var v struct {
		Session struct {
			Channel string `json:"channel_id"`
			Expiry  int64  `json:"init_expire_at_unix_s"`
		}
		Path struct {
			Kind, Token string
			Routing     string `json:"routing_token"`
			Role        int
			Candidates  []struct {
				URL string `json:"url"`
			}
		}
	}
	if err = json.Unmarshal(raw, &v); err != nil || v.Session.Channel != id || len(v.Path.Candidates) == 0 {
		return offered{}, errors.New("unexpected invitation channel")
	}
	credential := v.Path.Routing
	if d.opts.ServerCarrier == "" {
		if v.Path.Kind != "direct" || len(v.Path.Candidates) != 1 || v.Path.Candidates[0].URL != d.url {
			return offered{}, errors.New("unexpected Direct endpoint")
		}
	} else {
		if v.Path.Kind != "tunnel" || v.Path.Role != role+1 {
			return offered{}, errors.New("unexpected Tunnel role")
		}
		if d.opts.OverlapSuccessors != 0 && (len(v.Path.Candidates) != 1 || v.Path.Candidates[0].URL != d.local[role]) {
			return offered{}, errors.New("unexpected Tunnel ingress")
		}
		credential = v.Path.Token
	}
	if credential == "" {
		return offered{}, errors.New("missing signed credential")
	}
	digest := sha256.Sum256([]byte(credential))
	return offered{a, base64.RawURLEncoding.EncodeToString(digest[:]), time.Unix(v.Session.Expiry, 0)}, nil
}

var capacityID = regexp.MustCompile(`^[A-Za-z0-9_~.-]{1,128}$`)
var errCapacityConfiguration = errors.New("configuration")

func (d *capacityProduct) connect(ctx context.Context, index int, id string, previous *capacityPair) (any, error) {
	if index < 0 || index >= capacityPairs || !capacityID.MatchString(id) || id == "." || id == ".." {
		return nil, errors.New("invalid capacity position")
	}
	connectCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	p := &capacityPair{id: id, index: index}
	if d.opts.ServerCarrier == "" {
		p.accepted = make(chan fs.Session)
		p.acceptDone = connectCtx.Done()
	}
	var offers [2]offered
	var err error
	offers[0], err = d.offered(id, 0)
	if err != nil {
		return nil, err
	}
	offers[1] = offers[0]
	if d.opts.ServerCarrier != "" {
		offers[1], err = d.offered(id, 1)
		if err != nil {
			return nil, err
		}
	}
	for i, o := range offers {
		p.keys[i], p.expires[i] = o.key, o.expires
	}
	d.mu.Lock()
	current := d.pairs[d.seen[index]]
	direct := d.opts.ServerCarrier == ""
	strict := direct || d.opts.TunnelReplacement
	overlap := d.opts.OverlapSuccessors != 0
	if d.closing || !d.prepared || d.pairs[id] != nil || current != previous || !overlap && previous != nil && (!previous.closing.Load() || strict && (!previous.retired.Load() || previous.live.Load())) {
		d.mu.Unlock()
		return nil, errCapacityConfiguration
	}
	if overlap {
		if d.byKey[p.keys[0]] != nil || !direct && (p.keys[0] == p.keys[1] || d.byKey[p.keys[1]] != nil) || previous != nil && (len(d.overlap) >= d.opts.OverlapSuccessors || previous.generation != 1 || !previous.established.Load() || !previous.live.Load() || previous.closing.Load()) {
			d.mu.Unlock()
			return nil, errCapacityConfiguration
		}
		if !direct {
			d.byKey[p.keys[1]] = p
		}
		if previous != nil {
			d.overlap = append(d.overlap, capacitySuccession{previous, p})
		}
	}
	p.generation = 1
	if previous != nil {
		p.generation = previous.generation + 1
		if d.opts.TunnelReplacement && (p.keys[0] == p.keys[1] || p.keys[0] == previous.keys[0] || p.keys[0] == previous.keys[1] || p.keys[1] == previous.keys[0] || p.keys[1] == previous.keys[1]) {
			d.mu.Unlock()
			return nil, errCapacityConfiguration
		}
		if strict && !overlap {
			delete(d.pairs, previous.id)
			delete(d.byKey, previous.keys[0])
		}
	}
	d.pairs[id], d.seen[index], d.byKey[p.keys[0]] = p, id, p
	d.mu.Unlock()
	type result struct {
		role int
		s    fs.Session
		err  error
	}
	ch := make(chan result, 2)
	for i, o := range offers {
		go func() {
			if i == 1 && d.opts.ServerCarrier == "" {
				select {
				case s := <-p.accepted:
					ch <- result{i, s, nil}
				case <-connectCtx.Done():
					ch <- result{i, nil, connectCtx.Err()}
				}
				return
			}
			lease, err := fs.NewArtifactLease(o.handle, func(ctx context.Context) error {
				if err := ctx.Err(); err != nil {
					return err
				}
				return mark(d.opts.StoreDirectory, "spent-"+o.key)
			})
			if err != nil {
				ch <- result{i, nil, err}
				return
			}
			h := d.client
			if i == 1 {
				h = d.tunnelServer
			}
			options := fs.ConnectorOptions{Origin: origin, TrustRoots: d.roots, RPCHandlers: h, TunnelEndpoint: d.local[i]}
			if overlap {
				options.RPCFrameLimits = capacityBusinessFrame()
			}
			s, err := fs.Connect(connectCtx, lease, options)
			ch <- result{i, s, err}
		}()
	}
	for range 2 {
		x := <-ch
		if x.err != nil {
			cancel()
			err = errors.Join(err, x.err)
		}
		p.mu.Lock()
		p.ends[x.role] = x.s
		p.mu.Unlock()
	}
	if err != nil {
		return nil, errors.Join(err, d.closePair(p))
	}
	checks := make(chan error, 2)
	for i, s := range p.ends {
		go func() {
			if err := verifyContracts(connectCtx, s, d.want); err != nil {
				checks <- err
				return
			}
			unsub := s.RPC().OnNotify(7002, func(c context.Context, raw json.RawMessage) {
				var v value
				if granted, ok := d.permitted(c, i); ok && granted == p && decode(raw, &v) == nil && v.Value == "notify" {
					p.observed[i].Add(1)
				}
			})
			p.mu.Lock()
			p.unsubscribe[i] = unsub
			p.mu.Unlock()
			checks <- nil
		}()
	}
	for range 2 {
		if e := <-checks; e != nil {
			err = errors.Join(err, e)
			cancel()
		}
	}
	if err != nil {
		return nil, errors.Join(err, d.closePair(p))
	}
	watchCtx, stopWatching := context.WithCancel(d.ctx)
	p.stopWatching = stopWatching
	p.live.Store(true)
	if overlap && !direct {
		server := p.ends[1]
		p.watchers.Add(1)
		go func() {
			defer p.watchers.Done()
			_ = d.tunnelStreams.Serve(context.WithValue(watchCtx, capacityStreamOwner{}, p), server)
		}()
	}
	for _, s := range p.ends {
		d.wg.Add(1)
		p.watchers.Add(1)
		go func() {
			defer d.wg.Done()
			defer p.watchers.Done()
			_, err := s.WaitTermination(watchCtx)
			if err == nil {
				p.live.Store(false)
				p.terminated.Do(func() {
					if d.opts.TunnelReplacement || overlap {
						d.terminated.Add(1)
					}
					_ = d.uplink(map[string]any{"event": "terminated", "session": id})
				})
			}
		}()
	}
	p.established.Store(true)
	if direct && overlap {
		if previous != nil {
			return map[string]any{"id": id, "generation": p.generation, "lookupKey": p.keys[0], "verifiedContractsPerEndpoint": len(d.want)}, nil
		}
		return map[string]any{"id": id, "generation": p.generation}, nil
	}
	if d.opts.TunnelReplacement || overlap {
		return map[string]any{"id": id, "generation": p.generation, "legKeys": p.keys, "verifiedContractsPerEndpoint": len(d.want)}, nil
	}
	return map[string]any{"id": id, "generation": p.generation}, nil
}
func (d *capacityProduct) closePair(p *capacityPair) error {
	p.closing.Store(true)
	p.mu.Lock()
	ends, subs := p.ends, p.unsubscribe
	p.mu.Unlock()
	for _, un := range subs {
		if un != nil {
			un()
		}
	}
	var result error
	for _, s := range ends {
		if s != nil {
			result = errors.Join(result, s.Close())
			active, n, ok := fs.SessionInventory(s)
			if !ok || active || n != 0 {
				result = errors.Join(result, fmt.Errorf("terminal session inventory: active=%t, streams=%d", active, n))
			}
		}
	}
	if p.established.Load() {
		if result != nil {
			p.stopWatching()
		}
		p.watchers.Wait()
		p.stopWatching()
	}
	if result == nil {
		p.mu.Lock()
		p.ends = [2]fs.Session{}
		p.unsubscribe = [2]func(){}
		p.mu.Unlock()
	}
	return result
}

func (d *capacityProduct) op(ctx context.Context, r capacityRequest) (any, error) {
	if r.Op == "goroutines" {
		return runtime.NumGoroutine(), nil
	}
	if r.Op == "initialize" {
		return d.init(r.Options)
	}
	if d.opts.Sessions != capacityPairs {
		return nil, errors.New("missing capacity initialization")
	}
	if r.Index != nil && (*r.Index < 0 || *r.Index >= capacityPairs) {
		return nil, errCapacityConfiguration
	}
	d.mu.RLock()
	p := d.pairs[r.Session]
	overlap := d.opts.OverlapSuccessors != 0
	strict := d.opts.ServerCarrier == "" || d.opts.TunnelReplacement || overlap
	matchIndex := r.Index == nil || p != nil && p.index == *r.Index && (overlap || d.seen[*r.Index] == p.id)
	if strict && (r.Op == "probe" || r.Op == "close_session" || r.Op == "check_live" && r.Session != "" || overlap && r.Op == "business") && (p == nil || !matchIndex || r.Generation != 0 && p.generation != r.Generation || r.ExpectedSession != "") {
		d.mu.RUnlock()
		return nil, errCapacityConfiguration
	}
	d.mu.RUnlock()
	switch r.Op {
	case "business":
		if !overlap {
			return nil, errors.New("unsupported capacity operation")
		}
		return d.capacityBusiness(ctx, p, r)
	case "connect_successor":
		if !overlap {
			return nil, errors.New("unsupported capacity operation")
		}
		if r.Index == nil || p == nil || p.id != fmt.Sprintf("p%d", *r.Index) || r.ExpectedSession != p.id+"-g2" || r.Generation != 0 && r.Generation != 2 {
			return nil, errCapacityConfiguration
		}
		return d.connect(ctx, *r.Index, r.ExpectedSession, p)
	case "prepare":
		d.mu.Lock()
		defer d.mu.Unlock()
		if r.Count != capacityPairs || d.prepared {
			return nil, errors.New("incorrect capacity preparation")
		}
		d.prepared = true
	case "connect":
		if r.Index == nil || r.Session != "" || r.ExpectedSession != "" || r.Generation != 0 {
			return nil, errCapacityConfiguration
		}
		return d.connect(ctx, *r.Index, "p"+strconv.Itoa(*r.Index), nil)
	case "replace_direct", "replace_tunnel":
		if overlap {
			return nil, errCapacityConfiguration
		}
		if r.Op == "replace_tunnel" && !d.opts.TunnelReplacement {
			if d.opts.ServerCarrier == "" || r.Index == nil || p == nil || !matchIndex || !p.established.Load() || !capacityID.MatchString(r.ExpectedSession) || r.ExpectedSession == r.Session {
				return nil, errCapacityConfiguration
			}
			if err := d.closePair(p); err != nil {
				return nil, err
			}
			return d.connect(ctx, *r.Index, r.ExpectedSession, p)
		}
		if r.Op == "replace_direct" && (d.opts.ServerCarrier != "" || !d.opts.DirectReplacement) || r.Index == nil || *r.Index < 0 || *r.Index >= capacityPairs || p == nil || !p.retired.Load() || p.live.Load() || r.Generation != p.generation+1 || r.ExpectedSession != fmt.Sprintf("p%d-g%d", *r.Index, r.Generation) {
			return nil, errCapacityConfiguration
		}
		d.mu.RLock()
		matches := d.seen[*r.Index] == p.id
		d.mu.RUnlock()
		if !matches {
			return nil, errCapacityConfiguration
		}
		if d.opts.TunnelReplacement {
			for _, key := range p.keys {
				data, err := readPrivate(filepath.Join(d.records, "released-"+key), 32)
				if err != nil || string(data) != "flowersec/5\n" {
					return nil, errCapacityConfiguration
				}
			}
		}
		return d.connect(ctx, *r.Index, r.ExpectedSession, p)
	case "probe":
		if p == nil || !p.live.Load() || p.closing.Load() {
			return nil, errCapacityConfiguration
		}
		p.mu.Lock()
		ends := p.ends
		p.mu.Unlock()
		if ends[0] == nil || ends[1] == nil {
			return nil, errCapacityConfiguration
		}
		if _, err := ends[0].ProbeLiveness(ctx); err != nil {
			return nil, err
		}
		if d.opts.TunnelReplacement || (overlap || d.opts.ServerCarrier == "") && p.generation > 1 {
			if _, err := ends[1].ProbeLiveness(ctx); err != nil {
				return nil, err
			}
			if overlap && p.generation == 2 {
				p.responsive.Store(true)
			}
			if overlap && d.opts.ServerCarrier != "" || d.opts.TunnelReplacement {
				return map[string]any{"id": p.id, "generation": p.generation, "complete": true, "outcome": "Responsive", "responsiveEnds": 2}, nil
			}
			return map[string]any{"id": p.id, "generation": p.generation, "clientResponsive": true, "serverResponsive": true}, nil
		}
		if overlap && d.opts.ServerCarrier != "" {
			return map[string]any{"id": p.id, "generation": p.generation, "complete": true, "outcome": "Responsive", "responsiveEnds": 1}, nil
		}
		return nil, nil
	case "close_session":
		if overlap && !d.mayRetire(p) {
			return nil, errCapacityConfiguration
		}
		if p == nil || !p.established.Load() || strict && !p.closing.CompareAndSwap(false, true) {
			return nil, errCapacityConfiguration
		}
		if err := d.closePair(p); err != nil {
			return nil, err
		}
		p.retired.Store(true)
		return map[string]any{"id": p.id, "generation": p.generation, "closed": true}, nil
	case "open_streams":
		if r.Count != 0 {
			return nil, errors.New("idle 1000 case has no separate stream ramp")
		}
	case "snapshot", "check_live":
		d.mu.RLock()
		requested := r.Count
		selected := r.Op == "check_live" && r.Session != ""
		if selected {
			if p == nil || !p.live.Load() || p.closing.Load() || r.Count != 0 {
				d.mu.RUnlock()
				return nil, errCapacityConfiguration
			}
			requested = 1
		}
		seen := make(map[fs.Session]bool)
		seenEnds := 0
		var liveEnds [2]int
		acquired, bound := len(d.seen), 0
		acquired += d.drainedPositions
		n, streams, residual := 0, 0, 0
		for _, p := range d.pairs {
			if selected && p.id != r.Session {
				continue
			}
			p.mu.Lock()
			ends := p.ends
			p.mu.Unlock()
			both := true
			if ends[0] != nil && ends[1] != nil {
				bound++
			}
			for role, s := range ends {
				if s == nil {
					both = false
					continue
				}
				if r.Op == "check_live" {
					if seen[s] {
						d.mu.RUnlock()
						return nil, errors.New("reused endpoint session")
					}
					seen[s] = true
					seenEnds++
				}
				active, count, ok := fs.SessionInventory(s)
				if !ok {
					d.mu.RUnlock()
					return nil, errors.New("session inventory unavailable")
				}
				both = both && active
				if active {
					liveEnds[role]++
				}
				streams += count
				if !active {
					residual += count
				}
			}
			if both && p.live.Load() && !p.closing.Load() {
				n++
			}
		}
		d.mu.RUnlock()
		peak := overlap && requested == capacityPairs+d.opts.OverlapSuccessors
		if r.Op == "check_live" && (!selected && !peak && requested != capacityPairs && (!d.opts.TunnelReplacement || requested < 1 || requested != acquired) || n != requested || seenEnds != 2*requested) {
			return nil, fmt.Errorf("live pairs %d, requested %d", n, requested)
		}
		if overlap && selected {
			return map[string]any{"id": p.id, "generation": p.generation, "liveEnds": liveEnds}, nil
		}
		if r.Op == "check_live" && peak {
			d.mu.RLock()
			ready := d.successorsResponsiveLocked()
			d.mu.RUnlock()
			if !ready {
				return nil, errCapacityConfiguration
			}
			d.overlapPeak.Store(true)
		}
		if d.opts.TunnelReplacement || overlap && d.opts.ServerCarrier != "" {
			return map[string]any{"positions": d.opts.Sessions, "acquired": acquired, "bound": bound, "liveEnds": liveEnds, "activeSessions": n, "activeStreams": streams, "residualStreams": residual, "terminated": d.terminated.Load(), "closed": false}, nil
		}
		return map[string]any{"activeSessions": n, "activeStreams": streams, "residualStreams": residual, "closed": false}, nil
	case "quiesce", "close":
		d.mu.Lock()
		d.closing = true
		all := make([]*capacityPair, 0, len(d.pairs))
		for _, p := range d.pairs {
			all = append(all, p)
		}
		d.mu.Unlock()
		var err error
		for _, p := range all {
			if !p.retired.Load() {
				err = errors.Join(err, d.closePair(p))
			}
		}
		if r.Op == "quiesce" && d.releaseChanged != nil {
			err = errors.Join(err, d.waitDirectReleases(ctx))
		}
		if err == nil && r.Op == "quiesce" && overlap && d.opts.ServerCarrier != "" {
			d.mu.Lock()
			for _, pair := range d.pairs {
				pair.mu.Lock()
				active := pair.live.Load() || pair.ends[0] != nil || pair.ends[1] != nil
				pair.mu.Unlock()
				if active {
					d.mu.Unlock()
					return nil, errors.New("quiesced Tunnel position retains a live endpoint")
				}
			}
			d.drainedPositions += len(d.seen)
			d.seen, d.pairs, d.byKey, d.overlap = nil, nil, nil, nil
			d.mu.Unlock()
		}
		if r.Op == "close" {
			d.stop()
			if d.http != nil {
				err = errors.Join(err, d.http.Shutdown(ctx))
			}
			if d.listener != nil {
				if closeErr := d.listener.Close(); !errors.Is(closeErr, net.ErrClosed) {
					err = errors.Join(err, closeErr)
				}
			}
			if d.ready != nil {
				select {
				case e := <-d.ready:
					d.ready = nil
					if !errors.Is(e, context.Canceled) && !errors.Is(e, http.ErrServerClosed) && !errors.Is(e, net.ErrClosed) {
						err = errors.Join(err, e)
					}
				case <-ctx.Done():
					err = errors.Join(err, ctx.Err())
				}
			}
			d.wg.Wait()
			if d.releaseChanged != nil {
				err = errors.Join(err, d.waitDirectReleases(ctx))
			}
		}
		return nil, err
	default:
		return nil, errors.New("unsupported capacity operation")
	}
	return nil, nil
}

func capacityWorker() (resultErr error) {
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	listenerCtx, stopListeners := context.WithCancel(ctx)
	defer stopListeners()
	var output sync.Mutex
	d := capacityProduct{ctx: listenerCtx, stop: stopListeners, uplink: func(v any) error { output.Lock(); defer output.Unlock(); return json.NewEncoder(os.Stdout).Encode(v) }}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 1024), 16<<10)
	var calls sync.WaitGroup
	var mu sync.Mutex
	active := map[uint64]context.CancelFunc{}
	var last uint64
	var closed bool
	defer func() {
		stop()
		calls.Wait()
		if !closed && d.opts.Sessions == capacityPairs {
			timeout := time.Duration(min(d.opts.OperationTimeoutMS, 86400000)) * time.Millisecond
			cleanup, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			_, err := d.op(cleanup, capacityRequest{Op: "close"})
			resultErr = errors.Join(resultErr, err)
		}
	}()
	var draining, finishing bool
	for scan.Scan() {
		var r capacityRequest
		if err := json.NewDecoder(bytes.NewReader(scan.Bytes())).Decode(&r); err != nil {
			return err
		}
		mu.Lock()
		if r.Cancel != 0 {
			if r.Cancel > last {
				mu.Unlock()
				return errors.New("invalid capacity cancellation")
			}
			if f := active[r.Cancel]; f != nil {
				f()
			}
			mu.Unlock()
			continue
		}
		if r.ID <= last || len(active) >= capacityPairs+16 || r.TimeoutMS < 1 || r.TimeoutMS > 86400000 {
			mu.Unlock()
			return errors.New("invalid capacity command")
		}
		if (last == 0) != (r.Op == "initialize") {
			mu.Unlock()
			return errors.New("capacity initialization must be first and unique")
		}
		if finishing || draining && r.Op != "close" && r.Op != "quiesce" && r.Op != "goroutines" && r.Op != "snapshot" {
			mu.Unlock()
			last = r.ID
			_ = d.uplink(map[string]any{"id": r.ID, "error": errCapacityConfiguration.Error()})
			continue
		}
		if r.Op == "quiesce" || r.Op == "close" {
			draining = true
			finishing = r.Op == "close"
			for _, cancel := range active {
				cancel()
			}
			mu.Unlock()
			calls.Wait()
			mu.Lock()
		}
		last = r.ID
		call, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutMS)*time.Millisecond)
		active[r.ID] = cancel
		mu.Unlock()
		calls.Add(1)
		execute := func() {
			defer calls.Done()
			defer cancel()
			result, err := d.op(call, r)
			if r.Op == "close" && err == nil {
				closed = true
			}
			reply := map[string]any{"id": r.ID}
			if err != nil {
				reply["error"] = err.Error()
			} else {
				if result == nil {
					result = struct{}{}
				}
				reply["result"] = result
			}
			mu.Lock()
			delete(active, r.ID)
			mu.Unlock()
			_ = d.uplink(reply)
		}
		if r.Op == "initialize" {
			execute()
		} else {
			go execute()
		}
	}
	return scan.Err()
}
