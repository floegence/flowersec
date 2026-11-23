package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	flowersec "github.com/floegence/flowersec/flowersec-go/v7"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/artifactv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/protocolv3"
)

type directClientConfig struct {
	Role           string                    `json:"role"`
	SpendDirectory string                    `json:"spend_directory"`
	Ingress        []directClientIngressSpec `json:"ingress"`
}

type directClientIngressSpec struct {
	Address          string         `json:"address"`
	ArtifactFile     string         `json:"artifact_file"`
	TLSRootsFile     string         `json:"tls_roots_file"`
	Origin           string         `json:"origin"`
	Kind             string         `json:"kind"`
	Metadata         map[string]any `json:"metadata"`
	Slots            uint16         `json:"slots"`
	TimeoutMS        uint32         `json:"timeout_ms"`
	ConnectTimeoutMS uint32         `json:"connect_timeout_ms"`
}

type directClient struct {
	spends  *os.Root
	ingress []*directClientIngress
}

type directClientIngress struct {
	spec     directClientIngressSpec
	listener *net.TCPListener
	artifact flowersec.Artifact
	options  flowersec.ConnectorOptions
	metadata flowersec.StreamMetadata
}

func listenDirectClient(raw []byte) (*directClient, error) {
	if err := checkClientJSON(json.NewDecoder(bytes.NewReader(raw)), 0, false); err != nil {
		return nil, &ConfigError{Field: "direct-client", Err: errors.New("invalid or duplicate configuration field")}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var config directClientConfig
	if decoder.Decode(&config) != nil || requireJSONEOF(decoder) != nil || config.Role != "direct-client" {
		return nil, &ConfigError{Field: "direct-client", Err: errors.New("invalid configuration")}
	}
	if len(config.Ingress) == 0 || len(config.Ingress) > 64 {
		return nil, &ConfigError{Field: "ingress", Err: errors.New("requires 1 to 64 entries")}
	}
	info, err := os.Lstat(config.SpendDirectory)
	if !filepath.IsAbs(config.SpendDirectory) || err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, &ConfigError{Field: "spend_directory", Err: errors.New("requires an existing private (0700) directory at an absolute path")}
	}
	root, err := os.OpenRoot(config.SpendDirectory)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm() != 0700 {
		_ = root.Close()
		return nil, &ConfigError{Field: "spend_directory", Err: errors.New("directory changed while opening")}
	}
	client := &directClient{spends: root}
	seen := make(map[string]bool)
	for index, spec := range config.Ingress {
		ingress, err := prepareDirectClientIngress(spec)
		if err == nil {
			key := ingress.artifact.LookupKey()
			if _, statErr := root.Lstat(key); seen[key] || !errors.Is(statErr, os.ErrNotExist) {
				err = errors.New("credential is duplicated, already spent or unavailable")
			} else {
				seen[key] = true
				address := netip.MustParseAddrPort(spec.Address)
				ingress.listener, err = net.ListenTCP("tcp", net.TCPAddrFromAddrPort(address))
			}
		}
		if err != nil {
			client.close()
			return nil, &ConfigError{Field: fmt.Sprintf("ingress[%d]", index), Err: err}
		}
		client.ingress = append(client.ingress, ingress)
	}
	return client, nil
}

func checkClientJSON(decoder *json.Decoder, depth int, metadata bool) error {
	if depth > 64 {
		return errors.New("excessive nesting")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	for decoder.More() {
		childMetadata := metadata
		if delim == '{' {
			field, err := decoder.Token()
			key, ok := field.(string)
			if err != nil || !ok || seen[key] || (!metadata && strings.ToLower(key) != key) {
				return errors.New("invalid field")
			}
			seen[key] = true
			childMetadata = metadata || key == "metadata"
		}
		if err := checkClientJSON(decoder, depth+1, childMetadata); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}

func prepareDirectClientIngress(spec directClientIngressSpec) (*directClientIngress, error) {
	address, err := netip.ParseAddrPort(spec.Address)
	if err != nil || !address.Addr().IsLoopback() || address.Addr().Zone() != "" || address.Port() == 0 {
		return nil, errors.New("address must be a numeric loopback TCP address with a nonzero port")
	}
	if spec.Slots == 0 || spec.Slots > 128 || spec.TimeoutMS == 0 || spec.TimeoutMS > 86_400_000 || spec.ConnectTimeoutMS == 0 || spec.ConnectTimeoutMS > 90_000 {
		return nil, errors.New("requires 1 to 128 slots, timeout_ms from 1 to 86400000 and connect_timeout_ms from 1 to 90000")
	}
	if !protocolv3.ValidApplicationStreamKind(spec.Kind) || spec.Kind == "flowersec.rpc.v5" || spec.Kind == "flowersec.rpc.v2" {
		return nil, errors.New("invalid application stream kind")
	}
	metadata, err := flowersec.NewStreamMetadata(spec.Metadata)
	if err != nil {
		return nil, err
	}
	options := flowersec.ConnectorOptions{Origin: spec.Origin, ConnectTimeout: time.Duration(spec.ConnectTimeoutMS) * time.Millisecond}
	origin, err := url.Parse(spec.Origin)
	if err != nil || validateOrigin(spec.Origin) != nil || origin.Hostname() == "" || strings.ContainsAny(spec.Origin, "*?#") {
		return nil, errors.New("origin must be an exact HTTPS origin")
	}
	if spec.TLSRootsFile != "" {
		if !filepath.IsAbs(spec.TLSRootsFile) {
			return nil, errors.New("tls_roots_file must be an absolute path")
		}
		pem, err := os.ReadFile(spec.TLSRootsFile)
		options.TrustRoots = x509.NewCertPool()
		if err != nil || !options.TrustRoots.AppendCertsFromPEM(pem) {
			return nil, errors.New("cannot load TLS roots")
		}
	}
	info, err := os.Lstat(spec.ArtifactFile)
	if !filepath.IsAbs(spec.ArtifactFile) || err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("artifact_file must be a private regular file at an absolute path")
	}
	file, err := os.Open(spec.ArtifactFile)
	if err != nil {
		return nil, errors.New("cannot open artifact_file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("artifact_file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, artifactv3.MaxArtifactJSONBytes+1))
	if err != nil {
		return nil, errors.New("cannot read artifact_file")
	}
	defer clear(raw)
	artifact, err := flowersec.ParseArtifact(raw)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Path struct {
			Kind string `json:"kind"`
		} `json:"path"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Path.Kind != "direct" {
		return nil, errors.New("artifact_file must contain a direct artifact")
	}
	return &directClientIngress{spec: spec, artifact: artifact, metadata: metadata, options: options}, nil
}

func (client *directClient) close() {
	for _, ingress := range client.ingress {
		_ = ingress.listener.Close()
	}
	_ = client.spends.Close()
}

func (client *directClient) serve(parent context.Context) error {
	defer client.close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan error, len(client.ingress))
	for _, ingress := range client.ingress {
		go func() { results <- ingress.serve(ctx, client.spends) }()
	}
	var result error
	for range client.ingress {
		if err := <-results; err != nil {
			result = errors.Join(result, err)
		}
		cancel()
	}
	return result
}

func (ingress *directClientIngress) connect(ctx context.Context, spends *os.Root) (flowersec.Session, error) {
	var mu sync.Mutex
	finished := false
	defer func() { mu.Lock(); finished = true; mu.Unlock() }()
	lease, err := flowersec.NewArtifactLease(ingress.artifact, func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		if finished || ctx.Err() != nil {
			return context.Canceled
		}
		marker, err := spends.OpenFile(ingress.artifact.LookupKey(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("cannot commit single-use credential")
		}
		if err := errors.Join(marker.Sync(), marker.Close()); err != nil {
			return err
		}
		directory, err := spends.Open(".")
		if err != nil {
			return err
		}
		return errors.Join(directory.Sync(), directory.Close())
	})
	if err != nil {
		return nil, err
	}
	return flowersec.Connect(ctx, lease, ingress.options)
}

func (ingress *directClientIngress) serve(parent context.Context, spends *os.Root) (result error) {
	ctx, cancel := context.WithCancelCause(parent)
	listenerDone := make(chan struct{})
	context.AfterFunc(ctx, func() { _ = ingress.listener.Close(); close(listenerDone) })
	var session flowersec.Session
	var workers sync.WaitGroup
	defer func() {
		cancel(context.Canceled)
		<-listenerDone
		workers.Wait()
		if session != nil {
			result = errors.Join(result, session.Close())
		}
	}()
	slots := make(chan struct{}, ingress.spec.Slots)
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return directClientStopError(ctx)
		}
		connection, err := ingress.listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				return directClientStopError(ctx)
			}
			return err
		}
		if session == nil {
			session, err = ingress.connect(ctx, spends)
			if err != nil {
				_ = connection.Close()
				if ctx.Err() != nil {
					return directClientStopError(ctx)
				}
				return fmt.Errorf("direct-client connect: %w", err)
			}
			workers.Go(func() {
				if terminal, err := session.WaitTermination(ctx); err == nil {
					cancel(fmt.Errorf("direct-client session ended: %w", &terminal.Error))
				}
			})
		}
		workers.Go(func() {
			defer func() { <-slots }()
			defer connection.Close()
			call, stop := context.WithTimeout(ctx, time.Duration(ingress.spec.TimeoutMS)*time.Millisecond)
			defer stop()
			stream, err := session.OpenStream(call, ingress.spec.Kind, ingress.metadata)
			if err == nil {
				err = flowersec.RelayStreams(call, stream, connection)
			}
			if err != nil && ctx.Err() == nil {
				log.Print("flowersec-runtime: direct-client stream ended before completion")
			}
		})
	}
}

func directClientStopError(ctx context.Context) error {
	if errors.Is(context.Cause(ctx), context.Canceled) {
		return nil
	}
	return context.Cause(ctx)
}
