package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewHTTPAuthorizerRejectsInvalidResponseLimit(t *testing.T) {
	_, err := NewHTTPAuthorizer(HTTPAuthorizerConfig{
		AttachURL:        "https://authorizer.example.test/attach",
		MaxResponseBytes: -1,
	})
	if err == nil {
		t.Fatal("expected negative response limit to fail")
	}
}

func TestHTTPAuthorizerRejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 33)))
	}))
	defer server.Close()

	authorizer, err := NewHTTPAuthorizer(HTTPAuthorizerConfig{
		AttachURL:        server.URL,
		MaxResponseBytes: 32,
	})
	if err != nil {
		t.Fatalf("NewHTTPAuthorizer: %v", err)
	}
	_, err = authorizer.AuthorizeAttach(context.Background(), AttachAuthorizationRequest{})
	if err == nil || !strings.Contains(err.Error(), "exceeds 32 bytes") {
		t.Fatalf("expected response limit error, got %v", err)
	}
}

func TestHTTPAuthorizerRejectsCrossOriginRedirectBeforeSendingHeaders(t *testing.T) {
	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		if got := r.Header.Get("X-Authorizer-Key"); got != "" {
			t.Errorf("credential header reached redirected origin: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer redirected.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	authorizer, err := NewHTTPAuthorizer(HTTPAuthorizerConfig{
		AttachURL: origin.URL,
		Headers: http.Header{
			"X-Authorizer-Key": []string{"secret"},
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPAuthorizer: %v", err)
	}
	_, err = authorizer.AuthorizeAttach(context.Background(), AttachAuthorizationRequest{})
	if err == nil || !strings.Contains(err.Error(), "original origin") {
		t.Fatalf("expected cross-origin redirect error, got %v", err)
	}
	if got := redirectedCalls.Load(); got != 0 {
		t.Fatalf("redirect target calls = %d, want 0", got)
	}
}

func TestHTTPAuthorizerAllowsSameOriginRedirectAndPreservesHeaders(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, server.URL+"/final", http.StatusTemporaryRedirect)
			return
		}
		if got := r.Header.Get("X-Authorizer-Key"); got != "secret" {
			t.Fatalf("credential header = %q, want secret", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer server.Close()

	authorizer, err := NewHTTPAuthorizer(HTTPAuthorizerConfig{
		AttachURL: server.URL + "/start",
		Headers: http.Header{
			"X-Authorizer-Key": []string{"secret"},
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPAuthorizer: %v", err)
	}
	decision, err := authorizer.AuthorizeAttach(context.Background(), AttachAuthorizationRequest{})
	if err != nil {
		t.Fatalf("AuthorizeAttach: %v", err)
	}
	if !decision.Allowed {
		t.Fatal("expected allowed decision")
	}
}

func TestHTTPAuthorizerRunsCallerRedirectPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer server.Close()

	var redirectChecks atomic.Int32
	callerErr := errors.New("caller rejected redirect")
	authorizer, err := NewHTTPAuthorizer(HTTPAuthorizerConfig{
		AttachURL: server.URL + "/start",
		HTTPClient: &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			redirectChecks.Add(1)
			return callerErr
		}},
	})
	if err != nil {
		t.Fatalf("NewHTTPAuthorizer: %v", err)
	}
	_, err = authorizer.AuthorizeAttach(context.Background(), AttachAuthorizationRequest{})
	if err == nil || !strings.Contains(err.Error(), callerErr.Error()) {
		t.Fatalf("expected caller redirect policy error, got %v", err)
	}
	if got := redirectChecks.Load(); got != 1 {
		t.Fatalf("redirect checks = %d, want 1", got)
	}
}

func TestHTTPAuthorizerCapsHTTPErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", maxHTTPAuthorizerErrorBodyBytes+100)))
	}))
	defer server.Close()

	authorizer, err := NewHTTPAuthorizer(HTTPAuthorizerConfig{AttachURL: server.URL})
	if err != nil {
		t.Fatalf("NewHTTPAuthorizer: %v", err)
	}
	_, err = authorizer.AuthorizeAttach(context.Background(), AttachAuthorizationRequest{})
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if len(err.Error()) > maxHTTPAuthorizerErrorBodyBytes+100 {
		t.Fatalf("error body was not capped: %d bytes", len(err.Error()))
	}
}
