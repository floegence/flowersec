package sessionv4

import (
	"context"
	"net/http"
	"time"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/resourcev4"
)

// ControlledHTTPService reserves native parsing and I/O as a Session service.
// Setup runs on the original ordinary invocation before acceptance. Every
// subsequent request enters a new ordinary permit and keeps it until all
// handler defers return. Idle keep-alive consumes only native service backing.
// RequestClass is fixed registration, not inferred from a handler's awaits.
// Native allocations remain covered by Options.ExternalRuntime; callback
// allocations belong to the original executor's declared invocation envelope.
type ControlledHTTPService struct {
	Options          HTTPStreamOptions
	Upgrade          *ControlledHTTPUpgradeConfig
	RequestClass     ApplicationWorkClass
	RequestTimeoutMS uint64
	Setup            func(context.Context, any, []byte) (http.Handler, error)
}

type controlledHTTPExecution struct {
	executor  *ApplicationExecutor
	task      *resourcev4.ProtectedReservation
	class     ApplicationWorkClass
	timeoutMS uint64
	upgrade   *ControlledHTTPUpgradeConfig
}

func (c *controlledHTTPExecution) serve(h *HTTPStream, handler http.Handler, w http.ResponseWriter, request *http.Request) error {
	ref, err := c.task.Checkout()
	if err != nil {
		return err
	}
	defer ref.Release()
	h.conn.owner.mu.Lock()
	group := h.conn.owner.allocationGroup
	h.conn.owner.mu.Unlock()
	permit, err := c.executor.tryAcquireInGroup(group, c.class, ref, h.reservation)
	if err != nil {
		return err
	}
	defer permit.Close()
	ctx, cancel := context.WithTimeout(request.Context(), time.Duration(c.timeoutMS)*time.Millisecond)
	defer cancel()
	result := ErrHTTPHandlerExit
	response := &controlledHTTPResponse{writer: w, service: h}
	h.mu.Lock()
	h.response = response
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.response = nil
		h.mu.Unlock()
	}()
	task, err := permit.Start(func() {
		// Recover inside the actual executor task, never at its waiting caller.
		// Panic and Goexit retain the fixed failure and still join all defers.
		defer func() { _ = recover() }()
		h.mu.Lock()
		h.conn.mu.Lock()
		current := h.response == response && !h.conn.closed
		var admissionError error
		if current {
			admissionError = h.conn.owner.enterCallback()
		}
		h.conn.mu.Unlock()
		h.mu.Unlock()
		if !current {
			result = ErrHTTPHandlerExit
			return
		}
		if admissionError != nil {
			result = admissionError
			return
		}
		callCtx, exit, err := enterApplicationContext(ctx, c.executor, ordinaryApplicationLane, c.class, h.reservation, nil)
		if err != nil {
			result = err
			return
		}
		defer exit()
		handler.ServeHTTP(response, request.WithContext(callCtx))
		result = ctx.Err()
	})
	if err != nil {
		return err
	}
	select {
	case <-task.Done():
	case <-ctx.Done():
		// Cancellation stops the endpoint, never refunds a live handler.
		h.fail(ctx.Err())
		<-task.Done()
	}
	h.startControlledUpgrade(result)
	return result
}

// A controlled request cannot hand an unaccounted connection to arbitrary
// upgraded work. Native Hijacker is available on the explicit delegated HTTP
// registration. Do not expose Unwrap: ResponseController must obey this gate.
type controlledHTTPResponse struct {
	writer  http.ResponseWriter
	service *HTTPStream
	status  int
}

func (w *controlledHTTPResponse) Header() http.Header { return w.writer.Header() }
func (w *controlledHTTPResponse) WriteHeader(status int) {
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.writer.WriteHeader(status)
}
func (w *controlledHTTPResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.writer.Write(p)
}
func (w *controlledHTTPResponse) FlushError() error {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return http.NewResponseController(w.writer).Flush()
}
func (w *controlledHTTPResponse) SetReadDeadline(deadline time.Time) error {
	return http.NewResponseController(w.writer).SetReadDeadline(deadline)
}
func (w *controlledHTTPResponse) SetWriteDeadline(deadline time.Time) error {
	return http.NewResponseController(w.writer).SetWriteDeadline(deadline)
}
func (w *controlledHTTPResponse) EnableFullDuplex() error {
	return http.NewResponseController(w.writer).EnableFullDuplex()
}
