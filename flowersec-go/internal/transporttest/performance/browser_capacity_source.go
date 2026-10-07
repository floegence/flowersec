package performance

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	fs "github.com/floegence/flowersec/flowersec-go/v6"
)

type browserCapacityArtifact interface {
	ArtifactJSON() string
	Start(context.Context) error
	AwaitServer(context.Context) (browserServerSession, error)
	Cancel()
}

type browserCapacityRecord struct {
	id          string
	token       string
	artifact    browserCapacityArtifact
	termination chan struct{}
	terminate   sync.Once
	spend       sync.Once

	mu             sync.Mutex
	spent          bool
	session        browserServerSession
	monitorDone    chan struct{}
	connectContext context.Context
	cancelConnect  context.CancelFunc
	connectDone    chan struct{}
}

func (record *browserCapacityRecord) markTerminated() {
	record.terminate.Do(func() { close(record.termination) })
}

type browserCapacityArtifactBroker struct {
	issue func() (browserCapacityArtifact, error)
	limit int

	mu      sync.Mutex
	next    uint64
	records map[string]*browserCapacityRecord
	closed  bool
}

func newBrowserCapacityArtifactBroker(issue func() (browserCapacityArtifact, error), limit int) (*browserCapacityArtifactBroker, error) {
	if issue == nil || (limit != 1000 && limit != 100) {
		return nil, errors.New("browser capacity artifact broker requires an exact frozen session issuer")
	}
	return &browserCapacityArtifactBroker{issue: issue, limit: limit, records: make(map[string]*browserCapacityRecord, limit)}, nil
}

func (broker *browserCapacityArtifactBroker) issueRecord() (*browserCapacityRecord, error) {
	return broker.newRecord(nil, nil)
}
func (broker *browserCapacityArtifactBroker) issueConnectionRecord(ctx context.Context) (*browserCapacityRecord, error) {
	child, cancel := context.WithCancel(ctx)
	record, err := broker.newRecord(child, cancel)
	if err != nil {
		cancel()
	}
	return record, err
}
func (broker *browserCapacityArtifactBroker) newRecord(ctx context.Context, cancel context.CancelFunc) (*browserCapacityRecord, error) {
	broker.mu.Lock()
	closed := broker.closed
	broker.mu.Unlock()
	if closed {
		return nil, errors.New("browser capacity artifact broker is closed")
	}
	artifact, err := broker.issue()
	if err != nil {
		return nil, err
	}
	token, err := browserCapacityToken()
	if err != nil {
		artifact.Cancel()
		return nil, err
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.closed || len(broker.records) >= broker.limit {
		artifact.Cancel()
		return nil, errors.New("browser capacity artifact broker exceeded its frozen session count")
	}
	broker.next++
	id := fmt.Sprintf("browser-capacity-%04d-%s", broker.next, token[:12])
	record := &browserCapacityRecord{id: id, token: token, artifact: artifact, termination: make(chan struct{}), connectContext: ctx, cancelConnect: cancel}
	if cancel != nil {
		record.connectDone = make(chan struct{})
	}
	broker.records[id] = record
	return record, nil
}

func (broker *browserCapacityArtifactBroker) snapshotRecords() []*browserCapacityRecord {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	records := make([]*browserCapacityRecord, 0, len(broker.records))
	for _, record := range broker.records {
		records = append(records, record)
	}
	return records
}

func (broker *browserCapacityArtifactBroker) remove(record *browserCapacityRecord) {
	if record == nil {
		return
	}
	broker.mu.Lock()
	if broker.records[record.id] == record {
		delete(broker.records, record.id)
	}
	broker.mu.Unlock()
}

func (broker *browserCapacityArtifactBroker) residual() int {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	return len(broker.records)
}

// Cancellation joins the actual connection callback and Session observer before
// removing a record. A timed-out cleanup remains in the residual inventory.
func (broker *browserCapacityArtifactBroker) cancelAll(ctx context.Context) error {
	if ctx == nil {
		return errors.New("browser capacity cleanup requires its original context")
	}
	cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	broker.mu.Lock()
	broker.closed = true
	records := make([]*browserCapacityRecord, 0, len(broker.records))
	for _, record := range broker.records {
		records = append(records, record)
	}
	broker.mu.Unlock()
	// Cancel every admission first so one slow callback cannot keep others alive.
	for _, record := range records {
		if record.cancelConnect != nil {
			record.cancelConnect()
		}
	}
	for _, record := range records {
		record.artifact.Cancel()
	}
	var result error
	for _, record := range records {
		if record.connectDone != nil {
			select {
			case <-record.connectDone:
			case <-cleanup.Done():
				result = errors.Join(result, fmt.Errorf("browser capacity %s connection cleanup: %w", record.id, context.Cause(cleanup)))
				continue
			}
		}
		record.mu.Lock()
		session, monitorDone := record.session, record.monitorDone
		record.mu.Unlock()
		var closeErr error
		if session != nil {
			closeErr = errors.Join(normalizeBrowserCapacitySessionClose(session.Close()), session.WaitCleanup(cleanup))
		}
		if monitorDone != nil {
			select {
			case <-monitorDone:
			case <-cleanup.Done():
				closeErr = errors.Join(closeErr, context.Cause(cleanup))
			}
		}
		if closeErr != nil {
			result = errors.Join(result, fmt.Errorf("browser capacity %s native cleanup: %w", record.id, closeErr))
			continue
		}
		record.markTerminated()
		broker.remove(record)
	}
	return result
}

func (broker *browserCapacityArtifactBroker) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var input struct {
		SchemaVersion int    `json:"schema_version"`
		Action        string `json:"action"`
		SessionID     string `json:"session_id,omitempty"`
		Token         string `json:"token"`
	}
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.SchemaVersion != 1 || input.Token == "" {
		http.Error(writer, "request rejected", http.StatusBadRequest)
		return
	}
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		http.Error(writer, "broker is closing", http.StatusServiceUnavailable)
		return
	}
	var record *browserCapacityRecord
	if input.SessionID != "" {
		record = broker.records[input.SessionID]
	} else {
		for _, candidate := range broker.records {
			if candidate.token == input.Token {
				record = candidate
				break
			}
		}
	}
	broker.mu.Unlock()
	if record == nil || record.token != input.Token {
		http.Error(writer, "request rejected", http.StatusConflict)
		return
	}
	switch input.Action {
	case "spend":
		if input.SessionID != "" {
			http.Error(writer, "request rejected", http.StatusBadRequest)
			return
		}
		spent := false
		var startErr error
		record.spend.Do(func() {
			if startErr = record.artifact.Start(request.Context()); startErr != nil {
				return
			}
			record.mu.Lock()
			record.spent = true
			record.mu.Unlock()
			spent = true
		})
		if startErr != nil {
			http.Error(writer, "artifact start rejected", http.StatusServiceUnavailable)
			return
		}
		if !spent {
			http.Error(writer, "artifact already spent", http.StatusConflict)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	case "terminated":
		if input.SessionID == "" {
			http.Error(writer, "request rejected", http.StatusBadRequest)
			return
		}
		record.markTerminated()
		writer.WriteHeader(http.StatusNoContent)
	default:
		http.Error(writer, "request rejected", http.StatusBadRequest)
	}
}

func browserCapacityToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

// This is the application's projection of the original current SDK owner. It
// adds no admission or transport lifecycle and cannot create a Session.
type browserServerSession interface {
	AcceptStream(context.Context) (fs.AcceptedStream, error)
	ProbeLiveness(context.Context, uint64) (fs.LivenessResult, error)
	WaitTermination(context.Context) error
	WaitCleanup(context.Context) error
	Close() error
}
