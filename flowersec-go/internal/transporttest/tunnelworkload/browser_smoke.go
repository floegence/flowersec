package tunnelworkload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	flowersession "github.com/floegence/flowersec/flowersec-go/v7/internal/sessionv3"
	"github.com/floegence/flowersec/flowersec-go/v7/internal/tunnelv3"
)

type browserSmokeLease struct{ releases atomic.Int32 }

func (lease *browserSmokeLease) ReleaseContext(context.Context) { lease.releases.Add(1) }

func ServeBrowserRawQUICSmoke(ctx context.Context, origin string, output io.Writer) (err error) {
	var client, server browserSmokeLease
	endpoint, err := openBrowserEndpoint(ctx, BrowserTunnelWTQUIC, "127.0.0.1", origin, tunnelv3.Config{}, defaultMaxInboundStreams, func(role uint8) tunnelv3.Lease {
		switch role {
		case 1:
			return &client
		case 2:
			return &server
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = errors.Join(err, endpoint.Close(cleanup))
		if err == nil && (client.releases.Load() != 1 || server.releases.Load() != 1) {
			err = fmt.Errorf("tunnel lease releases: client=%d server=%d", client.releases.Load(), server.releases.Load())
		}
	}()
	issued, err := endpoint.IssueBrowserArtifact()
	if err != nil {
		return err
	}
	defer issued.Cancel()
	if err := issued.Start(ctx); err != nil {
		return err
	}
	pin, err := endpoint.CertificateHashBase64URL()
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(map[string]string{"artifact_json": issued.ArtifactJSON(), "certificate_hash": pin}); err != nil {
		return err
	}
	session, err := issued.AwaitServer(ctx)
	if err != nil {
		return err
	}
	defer session.Close()
	if session.Path() != flowersession.PathTunnel {
		return fmt.Errorf("unexpected session path %s", session.Path())
	}
	incoming, err := session.AcceptStream(ctx)
	if err != nil {
		return err
	}
	defer incoming.Stream.Close()
	if incoming.Kind != "accept.bridge" || incoming.Metadata["topology"] != string(BrowserTunnelWTQUIC) {
		return errors.New("unexpected tunnel stream kind or metadata")
	}
	want := "request:" + string(BrowserTunnelWTQUIC)
	request, err := io.ReadAll(io.LimitReader(incoming.Stream, int64(len(want)+1)))
	if err != nil {
		return err
	}
	if string(request) != want {
		return errors.New("unexpected browser tunnel request")
	}
	reply := "reply:" + string(BrowserTunnelWTQUIC)
	if written, err := io.WriteString(incoming.Stream, reply); err != nil {
		return err
	} else if written != len(reply) {
		return io.ErrShortWrite
	}
	if err := incoming.Stream.CloseWrite(); err != nil {
		return err
	}
	if err := session.WaitClosed(ctx); !errors.Is(err, flowersession.ErrSessionClosed) {
		return fmt.Errorf("expected the peer to close the tunnel normally, got %v", err)
	}
	return nil
}
