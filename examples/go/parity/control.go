package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	ossignal "os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cp "github.com/floegence/flowersec/flowersec-go/v7/controlplane"
)

type issuePairReceipt struct {
	ChannelID string `json:"channel_id"`
	Error     string `json:"error,omitempty"`
	FirstRef  string `json:"first_ref,omitempty"`
	SecondRef string `json:"second_ref,omitempty"`
}

func privateDir(path string) error {
	i, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !i.IsDir() || i.Mode().Perm()&077 != 0 {
		return errors.New("expected a private directory (0700)")
	}
	return nil
}

func issuePair(args []string) (result error) {
	f := flag.NewFlagSet("issue-pair", flag.ContinueOnError)
	a := f.String("a", "", "public ingress URL for the first endpoint")
	b := f.String("b", "", "public ingress URL for the second endpoint")
	records := f.String("records", "", "private control-plane records directory")
	out := f.String("out", "", "private output directory for the two invitations")
	id := f.String("pair", "", "unique channel and rendezvous identifier")
	stream := f.Bool("stream", false, "serve NDJSON channel_id requests, publishing one subdirectory per pair")
	if err := f.Parse(args); err != nil {
		return err
	}
	for _, path := range []string{*records, *out} {
		if err := privateDir(path); err != nil {
			return err
		}
	}
	first, err := cp.NewEndpointSet(cp.EndpointConfig{ID: "entry-a", URL: *a, TLS: cp.CAPolicy()})
	if err != nil {
		return err
	}
	second, err := cp.NewEndpointSet(cp.EndpointConfig{ID: "entry-b", URL: *b, TLS: cp.CAPolicy()})
	if err != nil {
		return err
	}
	flush := publicationSync((*os.File).Sync)
	issue := func(id, out string) error { return flush.publishPair(id, out, *records, first, second) }
	if !*stream {
		if !capacityID.MatchString(*id) {
			return errors.New("a pair identifier is required")
		}
		if err := issue(*id, *out); err != nil {
			return err
		}
		fmt.Println("issued_pairs=1 invitations=2")
		return nil
	}
	if *id != "" {
		return errors.New("-stream and -pair are mutually exclusive")
	}
	flush, closeSync, err := newIssuerSync()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, closeSync()) }()
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 512), 4096)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failure error
	slots := make(chan struct{}, issuerParallelism)
	for scanner.Scan() {
		var q struct {
			ID string `json:"channel_id"`
		}
		if decode(scanner.Bytes(), &q) != nil || !capacityID.MatchString(q.ID) || q.ID == "." || q.ID == ".." {
			mu.Lock()
			failure = errors.Join(failure, errors.New("invalid channel_id"))
			mu.Unlock()
			break
		}
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			path := filepath.Join(*out, q.ID)
			err := os.Mkdir(path, 0700)
			if err == nil {
				err = issue(q.ID, path)
			}
			if err == nil {
				err = flush.directory(*out)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failure = errors.Join(failure, err)
				_ = json.NewEncoder(os.Stdout).Encode(issuePairReceipt{ChannelID: q.ID, Error: "pair publication failed"})
				return
			}
			failure = errors.Join(failure, json.NewEncoder(os.Stdout).Encode(issuePairReceipt{ChannelID: q.ID, FirstRef: filepath.Join(q.ID, "first.json"), SecondRef: filepath.Join(q.ID, "second.json")}))
		}()
	}
	wg.Wait()
	return errors.Join(failure, scanner.Err())
}

const issuerParallelism = 8

func (flush publicationSync) publishPair(id, out, records string, first, second cp.EndpointSet) error {
	p, err := cp.NewIssuer().IssueTunnelPair(cp.TunnelIssueOptions{Session: cp.SessionOptions{ChannelID: id, ExpiresAt: time.Now().Add(2 * time.Minute)}, FirstEndpoints: first, SecondEndpoints: second, RendezvousGroupID: id, ListenerAudience: "parity", FirstEndpointID: "first", SecondEndpointID: "second"})
	if err != nil {
		return err
	}
	for _, leg := range []cp.IssuedArtifact{p.First, p.Second} {
		r := leg.AuthorizationRecord()
		data, err := r.Encode()
		if err != nil {
			return err
		}
		if err = flush.publish(records, r.LookupKey()+".json", data); err != nil {
			return err
		}
	}
	if err = flush.publish(out, "first.json", p.First.ArtifactJSON()); err != nil {
		return err
	}
	if err = flush.publish(out, "second.json", p.Second.ArtifactJSON()); err != nil {
		return err
	}
	return nil
}

func serveAuthorizer(args []string) error {
	f := flag.NewFlagSet("authorize", flag.ContinueOnError)
	addr := f.String("listen", "", "private HTTPS listen address")
	crt := f.String("cert", "", "HTTPS certificate")
	key := f.String("key", "", "HTTPS key")
	records := f.String("records", "", "private control-plane records directory")
	tokenVar := f.String("token-env", "FSEC_PARITY_AUTH_TOKEN", "environment variable shared with M")
	if err := f.Parse(args); err != nil {
		return err
	}
	if err := privateDir(*records); err != nil {
		return err
	}
	token := os.Getenv(*tokenVar)
	if len(token) < 32 || *addr == "" {
		return errors.New("private listen address and at least a 32-byte bearer token are required")
	}
	markers := newAuthorizationMarkers(*records)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authorize", func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		req, err := cp.ParseRuntimeAuthorizationRequest(raw)
		if err != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		deny := func() {
			response, err := cp.RejectTunnelRuntime("authorization_denied", false)
			if err != nil {
				http.Error(w, "denied", 403)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(response.JSON())
		}
		id := req.LookupKey()
		data, err := os.ReadFile(filepath.Join(*records, id+".json"))
		if err != nil {
			deny()
			return
		}
		record, err := cp.ParseAuthorizationRecord(data)
		if err != nil {
			deny()
			return
		}
		response, err := cp.AuthorizeTunnelRuntime(req, record, id)
		if err != nil {
			deny()
			return
		}
		if response.Allowed() {
			if err = r.Context().Err(); err != nil {
				return
			}
			if err = markers.admit("admitted-" + id); err != nil {
				deny()
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response.JSON())
	})
	mux.HandleFunc("POST /release", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ID string `json:"lease_id"`
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if err != nil || decode(raw, &in) != nil {
			http.Error(w, "invalid lease", 400)
			return
		}
		key, ok := decodeLookupKey(in.ID)
		if !ok {
			http.Error(w, "invalid lease", 400)
			return
		}
		id := base64.RawURLEncoding.EncodeToString(key[:])
		if _, err = os.Stat(filepath.Join(*records, "admitted-"+id)); err != nil {
			http.Error(w, "unknown lease", 404)
			return
		}
		if err = markers.release("released-" + id); err != nil {
			http.Error(w, "release failed", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := &http.Server{Addr: *addr, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(auth), []byte(token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		mux.ServeHTTP(w, r)
	})}
	ctx, stop := ossignal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServeTLS(*crt, *key) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}
}

type authorizationMarkers struct {
	dir     string
	flush   func() error
	started atomic.Uint64
	mu      sync.Mutex
	lastErr error
}

func newAuthorizationMarkers(dir string) *authorizationMarkers {
	return &authorizationMarkers{dir: dir, flush: func() error { return syncPublicationDirectory(dir) }}
}

func (m *authorizationMarkers) commit() error {
	// A directory sync can cover this link only if it starts after publication.
	return m.commitSince(m.started.Load())
}

func (m *authorizationMarkers) commitSince(seen uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started.Load() != seen && m.lastErr == nil {
		return nil
	}
	m.started.Add(1)
	m.lastErr = m.flush()
	return m.lastErr
}

func (m *authorizationMarkers) admit(name string) error {
	if err := linkPublication(m.dir, name, []byte(markerContents)); err != nil {
		return err
	}
	return m.commit()
}

func (m *authorizationMarkers) release(name string) error {
	err := m.admit(name)
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) || linkErr.Op != "link" || !errors.Is(linkErr.Err, os.ErrExist) {
		return err
	}
	// A concurrent release may have linked the marker but not synced its directory yet.
	data, err := readPrivate(filepath.Join(m.dir, name), int64(len(markerContents)))
	if err != nil {
		return err
	}
	if string(data) != markerContents {
		return errors.New("invalid release marker")
	}
	return m.commit()
}

func validLookupKey(key string) bool {
	_, ok := decodeLookupKey(key)
	return ok
}

func decodeLookupKey(key string) ([sha256.Size]byte, bool) {
	var raw [sha256.Size]byte
	if len(key) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return raw, false
	}
	n, err := base64.RawURLEncoding.Strict().Decode(raw[:], []byte(key))
	return raw, err == nil && n == len(raw)
}
