package client

import "testing"

func TestClientCloseNil(t *testing.T) {
	var c *Client
	if err := c.Close(); err != nil {
		t.Fatalf("Close() on nil client should be nil, got %v", err)
	}
}

func TestClientOpenStreamValidation(t *testing.T) {
	c := &Client{}
	if _, err := c.OpenStream(""); err == nil {
		t.Fatal("OpenStream(\"\") should fail")
	}
	if _, err := c.OpenStream("echo"); err == nil {
		t.Fatal("OpenStream(\"echo\") should fail when not connected")
	}
}
