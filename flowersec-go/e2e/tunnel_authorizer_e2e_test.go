package e2e_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/floegence/flowersec/flowersec-go/controlplane/channelinit"
	"github.com/floegence/flowersec/flowersec-go/tunnel/server"
)

func TestE2E_TunnelHTTPAuthorizerAttachAndObserve(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	iss, keyFile := newTestIssuerWithSeed(t, 33)
	recorder := newAuthorizerRecorder()
	recorder.observeResponder = func(req server.ObserveChannelsRequest) server.ObserveChannelsResponse {
		if recorder.attachCallCount() < 2 || len(req.Channels) == 0 {
			return server.ObserveChannelsResponse{}
		}
		return server.ObserveChannelsResponse{
			Decisions: []server.ChannelObservationDecision{{
				ChannelID: req.Channels[0].ChannelID,
				Allowed:   false,
			}},
		}
	}

	authSrv := httptest.NewServer(recorder.handler())
	defer authSrv.Close()

	authorizer, err := server.NewHTTPAuthorizer(server.HTTPAuthorizerConfig{
		AttachURL:  authSrv.URL + "/attach",
		ObserveURL: authSrv.URL + "/observe",
		Headers: http.Header{
			"X-Test-Token": []string{"shared-secret"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	fixture := newTunnelE2EFixture(t, server.Config{
		Path:                  server.DefaultConfig().Path,
		TunnelAudience:        "flowersec-tunnel:authorizer",
		TunnelIssuer:          "issuer-authorizer",
		IssuerKeysFile:        keyFile,
		AllowedOrigins:        []string{tunnelOrigin},
		Authorizer:            authorizer,
		CleanupInterval:       20 * time.Millisecond,
		PolicyObserveInterval: 20 * time.Millisecond,
		PolicyRequestTimeout:  200 * time.Millisecond,
		PolicyBatchSize:       8,
	})

	ci := &channelinit.Service{
		Issuer: iss,
		Params: channelinit.Params{
			TunnelURL:          fixture.wsURL,
			TunnelAudience:     "flowersec-tunnel:authorizer",
			IssuerID:           "issuer-authorizer",
			TokenExpSeconds:    60,
			IdleTimeoutSeconds: 5,
		},
	}
	grantC, grantS, err := ci.NewChannelInit("ch_http_authorizer")
	if err != nil {
		t.Fatal(err)
	}

	cli, sess := connectTunnelPair(ctx, t, grantC, grantS)
	defer cli.Close()
	defer sess.Close()

	recorder.waitForAttachCalls(t, 2, 2*time.Second)
	recorder.waitForObserveCalls(t, 1, 2*time.Second)
	fixture.waitForChannelCount(0, 3*time.Second)

	waitForCondition(t, 2*time.Second, func() bool {
		return cli.Ping() != nil
	}, "expected client ping to fail after observe-based close")
	waitForCondition(t, 2*time.Second, func() bool {
		return sess.Ping() != nil
	}, "expected endpoint ping to fail after observe-based close")

	attachRequests := recorder.snapshotAttachRequests()
	if len(attachRequests) != 2 {
		t.Fatalf("expected 2 attach requests, got %d", len(attachRequests))
	}
	roles := []string{attachRequests[0].Role, attachRequests[1].Role}
	slices.Sort(roles)
	if !slices.Equal(roles, []string{"client", "server"}) {
		t.Fatalf("unexpected attach roles: %v", roles)
	}
	for _, req := range attachRequests {
		if req.ChannelID != "ch_http_authorizer" {
			t.Fatalf("unexpected attach channel id: %q", req.ChannelID)
		}
		if req.Audience != "flowersec-tunnel:authorizer" {
			t.Fatalf("unexpected attach audience: %q", req.Audience)
		}
		if req.Issuer != "issuer-authorizer" {
			t.Fatalf("unexpected attach issuer: %q", req.Issuer)
		}
		if req.Origin != tunnelOrigin {
			t.Fatalf("unexpected attach origin: %q", req.Origin)
		}
		if req.RemoteAddr == "" {
			t.Fatal("expected non-empty remote addr")
		}
	}

	for _, header := range recorder.snapshotAttachHeaders() {
		if got := header.Get("X-Test-Token"); got != "shared-secret" {
			t.Fatalf("unexpected attach auth header: %q", got)
		}
		if got := header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected attach content-type: %q", got)
		}
		if got := header.Get("Accept"); got != "application/json" {
			t.Fatalf("unexpected attach accept: %q", got)
		}
	}

	observeRequests := recorder.snapshotObserveRequests()
	if len(observeRequests) == 0 {
		t.Fatal("expected observe requests")
	}
	foundObservedChannel := false
	for _, req := range observeRequests {
		for _, observed := range req.Channels {
			if observed.ChannelID != "ch_http_authorizer" {
				continue
			}
			foundObservedChannel = true
			if observed.Audience != "flowersec-tunnel:authorizer" {
				t.Fatalf("unexpected observed audience: %q", observed.Audience)
			}
			if observed.Issuer != "issuer-authorizer" {
				t.Fatalf("unexpected observed issuer: %q", observed.Issuer)
			}
		}
	}
	if !foundObservedChannel {
		t.Fatal("expected observe payload to include active channel")
	}

	for _, header := range recorder.snapshotObserveHeaders() {
		if got := header.Get("X-Test-Token"); got != "shared-secret" {
			t.Fatalf("unexpected observe auth header: %q", got)
		}
		if got := header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected observe content-type: %q", got)
		}
		if got := header.Get("Accept"); got != "application/json" {
			t.Fatalf("unexpected observe accept: %q", got)
		}
	}
}
