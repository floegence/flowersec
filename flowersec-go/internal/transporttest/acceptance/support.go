package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// configureServerDiagnostics enables the explicit debug-only qlog path for
// the Go WebTransport endpoint. Ordinary acceptance runs leave the server
// tracer disabled; the caller owns cleanup through the returned restore hook.
func configureServerDiagnostics(run RunContext) (func(), error) {
	if !run.Debug {
		return func() {}, nil
	}
	qlogDirectory := filepath.Join(run.TempDir, "server-qlog")
	if err := os.Mkdir(qlogDirectory, 0o700); err != nil {
		return nil, err
	}
	previousOutputs, hadOutputs := os.LookupEnv("FLOWERSEC_TRANSPORT_TEST_OUTPUTS")
	previousQLOG, hadQLOG := os.LookupEnv("QLOGDIR")
	if err := os.Setenv("FLOWERSEC_TRANSPORT_TEST_OUTPUTS", "1"); err != nil {
		return nil, err
	}
	if err := os.Setenv("QLOGDIR", qlogDirectory); err != nil {
		return nil, err
	}
	return func() {
		if hadOutputs {
			_ = os.Setenv("FLOWERSEC_TRANSPORT_TEST_OUTPUTS", previousOutputs)
		} else {
			_ = os.Unsetenv("FLOWERSEC_TRANSPORT_TEST_OUTPUTS")
		}
		if hadQLOG {
			_ = os.Setenv("QLOGDIR", previousQLOG)
		} else {
			_ = os.Unsetenv("QLOGDIR")
		}
	}, nil
}

func boundedText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit {
		value = value[len(value)-limit:]
	}
	return value
}

type boundedBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.data = append(buffer.data, value...)
	if len(buffer.data) > buffer.limit {
		buffer.data = append([]byte(nil), buffer.data[len(buffer.data)-buffer.limit:]...)
	}
	return len(value), nil
}
func (buffer *boundedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return string(append([]byte(nil), buffer.data...))
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
