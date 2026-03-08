package proxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

type StreamOpener interface {
	OpenStream(ctx context.Context, kind string) (io.ReadWriteCloser, error)
}

type Bridge struct {
	cfg *compiledContractOptions
}

type BridgeError struct {
	Code    string
	Status  int
	Message string
	Err     error
}

func (e *BridgeError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
}

func (e *BridgeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func NewBridge(opts BridgeOptions) (*Bridge, error) {
	cfg, err := compileContractOptions(ContractOptions(opts))
	if err != nil {
		return nil, err
	}
	return &Bridge{cfg: cfg}, nil
}

func newBridgeError(code string, status int, message string, err error) *BridgeError {
	return &BridgeError{Code: code, Status: status, Message: message, Err: err}
}

func writeBridgeHTTPError(w http.ResponseWriter, code string, status int, message string, err error) error {
	http.Error(w, message, status)
	return newBridgeError(code, status, message, err)
}

func opaqueID(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "rand_failed"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
