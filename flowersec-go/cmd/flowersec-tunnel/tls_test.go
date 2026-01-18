package main

import "testing"

func TestValidateTLSFiles(t *testing.T) {
	if err := validateTLSFiles("", ""); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if err := validateTLSFiles("cert.pem", ""); err == nil {
		t.Fatalf("expected error for missing key file")
	}
	if err := validateTLSFiles("", "key.pem"); err == nil {
		t.Fatalf("expected error for missing cert file")
	}
	if err := validateTLSFiles("cert.pem", "key.pem"); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}
