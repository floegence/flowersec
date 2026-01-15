package yamuxinterop

import (
	"errors"
	"fmt"
)

// Scenario defines the yamux interop test parameters.
type Scenario struct {
	Scenario              string  `json:"scenario"`
	Streams               int     `json:"streams"`
	BytesPerStream        int     `json:"bytes_per_stream"`
	ChunkBytes            int     `json:"chunk_bytes"`
	Direction             string  `json:"direction"`
	ReadDelayMs           int     `json:"read_delay_ms"`
	WriteDelayMs          int     `json:"write_delay_ms"`
	DeadlineMs            int     `json:"deadline_ms"`
	Seed                  int64   `json:"seed"`
	RstAfterBytes         int     `json:"rst_after_bytes"`
	CloseImmediatelyRatio float64 `json:"close_immediately_ratio"`
	CloseAfterBytes       int     `json:"close_after_bytes"`
	SessionCloseDelayMs   int     `json:"session_close_delay_ms"`
}

const (
	ScenarioWindowUpdateRace = "window_update_race"
	ScenarioRstMidWriteTS    = "rst_mid_write_ts"
	ScenarioRstMidWriteGo    = "rst_mid_write_go"
	ScenarioConcurrentClose  = "concurrent_open_close"
	ScenarioSessionClose     = "session_close"
)

const (
	DirectionTsToGo = "ts_to_go"
	DirectionBidi   = "bidi"
)

// Normalize validates the scenario and applies defaults.
func (s *Scenario) Normalize() error {
	if s.ChunkBytes <= 0 {
		s.ChunkBytes = 16 * 1024
	}
	if s.Streams <= 0 {
		return errors.New("streams must be > 0")
	}
	if s.BytesPerStream <= 0 {
		return errors.New("bytes_per_stream must be > 0")
	}
	if s.DeadlineMs <= 0 {
		return errors.New("deadline_ms must be > 0")
	}
	switch s.Direction {
	case "", DirectionTsToGo:
		s.Direction = DirectionTsToGo
	case DirectionBidi:
	default:
		return fmt.Errorf("unsupported direction: %s", s.Direction)
	}
	switch s.Scenario {
	case ScenarioWindowUpdateRace:
	case ScenarioRstMidWriteTS, ScenarioRstMidWriteGo:
		if s.RstAfterBytes <= 0 {
			return errors.New("rst_after_bytes must be > 0 for rst scenarios")
		}
	case ScenarioConcurrentClose:
		if s.CloseAfterBytes <= 0 {
			return errors.New("close_after_bytes must be > 0 for concurrent_open_close")
		}
	case ScenarioSessionClose:
		if s.SessionCloseDelayMs <= 0 {
			return errors.New("session_close_delay_ms must be > 0 for session_close")
		}
	default:
		return fmt.Errorf("unsupported scenario: %s", s.Scenario)
	}
	if s.CloseImmediatelyRatio < 0 || s.CloseImmediatelyRatio > 1 {
		return errors.New("close_immediately_ratio must be between 0 and 1")
	}
	return nil
}
