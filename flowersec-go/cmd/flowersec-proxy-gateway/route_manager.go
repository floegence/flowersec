package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/floegence/flowersec/flowersec-go/client"
	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	"github.com/floegence/flowersec/flowersec-go/protocolio"
)

type streamOpener interface {
	OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error)
}

type grantSource interface {
	LoadGrant(ctx context.Context) (*controlv1.ChannelInitGrant, error)
	Description() string
}

type clientFactory func(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) (client.Client, error)

func defaultClientFactory(ctx context.Context, origin string, grant *controlv1.ChannelInitGrant) (client.Client, error) {
	return client.ConnectTunnel(
		ctx,
		grant,
		client.WithOrigin(origin),
		client.WithConnectTimeout(10*time.Second),
		client.WithHandshakeTimeout(10*time.Second),
		client.WithMaxRecordBytes(1<<20),
	)
}

type routeManager struct {
	host   string
	origin string
	source grantSource
	dial   clientFactory

	mu     sync.Mutex
	client client.Client
}

func newRouteManager(host string, origin string, source grantSource) *routeManager {
	return &routeManager{
		host:   host,
		origin: origin,
		source: source,
		dial:   defaultClientFactory,
	}
}

func (m *routeManager) OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error) {
	cli, err := m.ensureClient(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := cli.OpenStream(ctx, kind)
	if err == nil {
		return stream, nil
	}

	m.invalidate(cli)
	cli, freshErr := m.ensureClient(ctx)
	if freshErr != nil {
		return nil, freshErr
	}
	stream, err = cli.OpenStream(ctx, kind)
	if err != nil {
		m.invalidate(cli)
		return nil, err
	}
	return stream, nil
}

func (m *routeManager) Close() error {
	m.mu.Lock()
	cli := m.client
	m.client = nil
	m.mu.Unlock()
	if cli != nil {
		return cli.Close()
	}
	return nil
}

func (m *routeManager) ensureClient(ctx context.Context) (client.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	grant, err := m.source.LoadGrant(ctx)
	if err != nil {
		return nil, fmt.Errorf("load grant for host %q from %s: %w", m.host, m.source.Description(), err)
	}
	cli, err := m.dial(ctx, m.origin, grant)
	if err != nil {
		return nil, fmt.Errorf("connect host %q: %w", m.host, err)
	}
	m.client = cli
	return cli, nil
}

func (m *routeManager) invalidate(target client.Client) {
	m.mu.Lock()
	if m.client != target {
		m.mu.Unlock()
		return
	}
	cli := m.client
	m.client = nil
	m.mu.Unlock()
	if cli != nil {
		_ = cli.Close()
	}
}

type fileGrantSource struct {
	path string
}

func (s fileGrantSource) LoadGrant(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return protocolio.DecodeGrantClientJSON(f)
}

func (s fileGrantSource) Description() string {
	return "file:" + s.path
}

type execGrantSource struct {
	command []string
	timeout time.Duration
}

func (s execGrantSource) LoadGrant(ctx context.Context) (*controlv1.ChannelInitGrant, error) {
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, s.command[0], s.command[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	grant, decodeErr := protocolio.DecodeGrantClientJSON(stdout)
	waitErr := cmd.Wait()
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return nil, waitErr
		}
		return nil, fmt.Errorf("%w: %s", waitErr, msg)
	}
	if decodeErr != nil {
		return nil, decodeErr
	}
	return grant, nil
}

func (s execGrantSource) Description() string {
	return "exec:" + strings.Join(s.command, " ")
}

func newGrantSource(cfg grantSourceConfig) (grantSource, error) {
	if cfg.File != "" {
		return fileGrantSource{path: cfg.File}, nil
	}
	if len(cfg.Command) > 0 {
		return execGrantSource{command: cfg.Command, timeout: cfg.timeout()}, nil
	}
	return nil, fmt.Errorf("missing grant source")
}
