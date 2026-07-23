// Package admissionv2 runs the transport-neutral FSB2/FSA2 admission exchange
// on one bounded carrier stream.
package admissionv2

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/floegence/flowersec/flowersec-go/v2/artifactv2"
	"github.com/floegence/flowersec/flowersec-go/v2/carrier"
)

var (
	ErrTrailingBytes      = errors.New("trailing bytes on Flowersec v2 admission stream")
	ErrAdmissionRejected  = errors.New("Flowersec v2 admission rejected")
	ErrAdmissionRetryable = errors.New("Flowersec v2 admission retryable with a fresh artifact")
	ErrInvalidAuthorizer  = errors.New("invalid Flowersec v2 admission authorizer")
)

type ResponseError struct {
	Status artifactv2.AdmissionStatus
	Reason string
}

func (err *ResponseError) Error() string {
	return fmt.Sprintf("Flowersec v2 admission status=%d reason=%q", err.Status, err.Reason)
}

func (err *ResponseError) Unwrap() error {
	if err.Status == artifactv2.AdmissionRetryable {
		return ErrAdmissionRetryable
	}
	return ErrAdmissionRejected
}

type Authorize func(context.Context, *artifactv2.DecodedRequest) (artifactv2.AdmissionResponse, error)

// Commit writes the one-shot credential frame and reads an exact FSA2 response.
// Callers must mark the artifact spent before invoking this function.
func Commit(ctx context.Context, stream carrier.Stream, rawFSB2 []byte, reasons artifactv2.ReasonRegistry) (response artifactv2.AdmissionResponse, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return response, io.ErrClosedPipe
	}
	if _, err := artifactv2.ParseRequest(rawFSB2); err != nil {
		return response, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = stream.Reset()
		}
	}()
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	if err := writeFull(stream, rawFSB2); err != nil {
		return response, preferContextError(ctx, err)
	}
	if err := stream.CloseWrite(); err != nil {
		return response, preferContextError(ctx, err)
	}
	response, err = artifactv2.ReadResponse(stream, reasons)
	if err != nil {
		return response, preferContextError(ctx, err)
	}
	if err := requireCleanEOF(stream); err != nil {
		return response, preferContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return response, err
	}
	succeeded = true
	if response.Status != artifactv2.AdmissionSuccess {
		return response, &ResponseError{Status: response.Status, Reason: response.Reason}
	}
	return response, nil
}

// Serve validates the exact request boundary before invoking the generic
// authorizer. The callback owns token interpretation; this package does not.
func Serve(ctx context.Context, stream carrier.Stream, reasons artifactv2.ReasonRegistry, authorize Authorize) (decoded *artifactv2.DecodedRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return nil, io.ErrClosedPipe
	}
	if authorize == nil {
		_ = stream.Reset()
		return nil, ErrInvalidAuthorizer
	}
	decoded, err = Receive(ctx, stream)
	if err != nil {
		return nil, err
	}
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	response, err := authorize(ctx, decoded)
	if err != nil {
		_ = stream.Reset()
		return nil, err
	}
	if err := Respond(ctx, stream, response, reasons); err != nil {
		return nil, err
	}
	if response.Status != artifactv2.AdmissionSuccess {
		return decoded, &ResponseError{Status: response.Status, Reason: response.Reason}
	}
	return decoded, nil
}

// Receive consumes exactly one FSB2 request and its peer FIN without sending a
// response. Tunnel pairing uses this split phase to hold SUCCESS until both
// independently authorized legs are ready.
func Receive(ctx context.Context, stream carrier.Stream) (decoded *artifactv2.DecodedRequest, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return nil, io.ErrClosedPipe
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = stream.Reset()
		}
	}()
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	decoded, err = artifactv2.ReadRequest(stream)
	if err != nil {
		return nil, preferContextError(ctx, err)
	}
	if err := requireCleanEOF(stream); err != nil {
		return nil, preferContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	succeeded = true
	return decoded, nil
}

// Respond writes exactly one FSA2 response and closes the response direction.
func Respond(ctx context.Context, stream carrier.Stream, response artifactv2.AdmissionResponse, reasons artifactv2.ReasonRegistry) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if stream == nil {
		return io.ErrClosedPipe
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = stream.Reset()
		}
	}()
	stopInterrupt := interruptOnCancellation(ctx, stream)
	defer stopInterrupt()
	rawResponse, err := artifactv2.MarshalResponse(response, reasons)
	if err != nil {
		return err
	}
	if err := writeFull(stream, rawResponse); err != nil {
		return preferContextError(ctx, err)
	}
	if err := stream.CloseWrite(); err != nil {
		return preferContextError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	succeeded = true
	return nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written < 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func requireCleanEOF(reader io.Reader) error {
	var one [1]byte
	read, err := reader.Read(one[:])
	if read != 0 || err == nil {
		return ErrTrailingBytes
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func interruptOnCancellation(ctx context.Context, stream carrier.Stream) func() {
	stop := context.AfterFunc(ctx, func() { _ = stream.Reset() })
	return func() { _ = stop() }
}

func preferContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}
