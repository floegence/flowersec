package main

import (
	"net/http"
	"testing"
)

func TestNewHTTPServerConfig(t *testing.T) {
	srv := newHTTPServer(http.NewServeMux())
	if srv.ReadHeaderTimeout != httpReadHeaderTimeout {
		t.Fatalf("ReadHeaderTimeout mismatch: got=%v want=%v", srv.ReadHeaderTimeout, httpReadHeaderTimeout)
	}
	if srv.ReadTimeout != httpReadTimeout {
		t.Fatalf("ReadTimeout mismatch: got=%v want=%v", srv.ReadTimeout, httpReadTimeout)
	}
	if srv.WriteTimeout != httpWriteTimeout {
		t.Fatalf("WriteTimeout mismatch: got=%v want=%v", srv.WriteTimeout, httpWriteTimeout)
	}
	if srv.IdleTimeout != httpIdleTimeout {
		t.Fatalf("IdleTimeout mismatch: got=%v want=%v", srv.IdleTimeout, httpIdleTimeout)
	}
	if srv.MaxHeaderBytes != httpMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes mismatch: got=%v want=%v", srv.MaxHeaderBytes, httpMaxHeaderBytes)
	}
}
