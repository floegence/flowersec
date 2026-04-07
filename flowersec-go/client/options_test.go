package client

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/observability"
)

func TestWithHeader_MergesAndOverridesByKey(t *testing.T) {
	cfg, err := applyConnectOptions([]ConnectOption{
		WithHeader(http.Header{
			"X-A":      []string{"1"},
			"X-Shared": []string{"a"},
		}),
		WithHeader(http.Header{
			"X-B":      []string{"2"},
			"X-Shared": []string{"b"},
		}),
	})
	if err != nil {
		t.Fatalf("applyConnectOptions() failed: %v", err)
	}

	want := http.Header{
		"X-A":      []string{"1"},
		"X-B":      []string{"2"},
		"X-Shared": []string{"b"},
	}
	if !reflect.DeepEqual(cfg.header, want) {
		t.Fatalf("merged header mismatch: got=%v want=%v", cfg.header, want)
	}
}

func TestWithHeader_DoesNotAliasInput(t *testing.T) {
	h := http.Header{"X-Test": []string{"1"}}

	cfg, err := applyConnectOptions([]ConnectOption{WithHeader(h)})
	if err != nil {
		t.Fatalf("applyConnectOptions() failed: %v", err)
	}

	h.Set("X-Test", "2")
	if got := cfg.header.Get("X-Test"); got != "1" {
		t.Fatalf("expected config header to be independent, got=%q", got)
	}
}

func TestConnectOptions_AdditionalStableOptions(t *testing.T) {
	observer := observability.NoopClientObserver
	cfg, err := applyConnectOptions([]ConnectOption{
		WithMaxBufferedBytes(4096),
		WithClientFeatures(7),
		WithObserver(observer),
	})
	if err != nil {
		t.Fatalf("applyConnectOptions() failed: %v", err)
	}
	if cfg.maxBufferedBytes != 4096 {
		t.Fatalf("maxBufferedBytes = %d", cfg.maxBufferedBytes)
	}
	if cfg.clientFeatures != 7 {
		t.Fatalf("clientFeatures = %d", cfg.clientFeatures)
	}
	if cfg.observer != observer {
		t.Fatal("observer mismatch")
	}
}

func TestWithMaxBufferedBytes_RejectsNonPositive(t *testing.T) {
	if _, err := applyConnectOptions([]ConnectOption{WithMaxBufferedBytes(0)}); err == nil {
		t.Fatal("expected error")
	}
}
