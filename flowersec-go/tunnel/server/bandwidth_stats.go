package server

import (
	"sync/atomic"
	"time"
)

const (
	// bandwidthStatsRetention keeps recently-closed channel counters available for stats collectors.
	// This reduces undercounting when a channel closes between polling intervals.
	bandwidthStatsRetention = 2 * time.Minute
)

// BandwidthChannelStats is a point-in-time snapshot for a single channel.
//
// Bytes are counted as raw websocket binary frame payload bytes forwarded by the tunnel.
// This intentionally includes encryption overhead (the tunnel cannot decrypt).
type BandwidthChannelStats struct {
	ChannelID      string
	BytesToClient  uint64
	BytesToServer  uint64
	ClosedAtUnixMs int64 // 0 means the channel is currently active.
}

// BandwidthSnapshot captures a point-in-time view of bandwidth counters.
type BandwidthSnapshot struct {
	NowUnixMs int64
	Channels  []BandwidthChannelStats
}

// bandwidthEntry is stored in Server.bw and updated by the write pumps.
type bandwidthEntry struct {
	toClient uint64
	toServer uint64
	// closedAtUnixMs is set once the channel is closed and retained for a short period.
	closedAtUnixMs int64
}

func (s *Server) ensureBandwidthEntry(channelID string) *bandwidthEntry {
	if s == nil || channelID == "" {
		return nil
	}

	if v, ok := s.bw.Load(channelID); ok {
		e := v.(*bandwidthEntry)
		// Re-open if the same channel_id is reused (e.g. reconnect within init window).
		atomic.StoreInt64(&e.closedAtUnixMs, 0)
		return e
	}

	e := &bandwidthEntry{}
	actual, loaded := s.bw.LoadOrStore(channelID, e)
	if loaded {
		e = actual.(*bandwidthEntry)
	}
	atomic.StoreInt64(&e.closedAtUnixMs, 0)
	return e
}

func (s *Server) markBandwidthClosed(channelID string, now time.Time) {
	if s == nil || channelID == "" {
		return
	}
	v, ok := s.bw.Load(channelID)
	if !ok {
		return
	}
	e := v.(*bandwidthEntry)
	ts := now.UnixMilli()

	// Preserve the earliest close timestamp.
	for {
		prev := atomic.LoadInt64(&e.closedAtUnixMs)
		if prev != 0 {
			return
		}
		if atomic.CompareAndSwapInt64(&e.closedAtUnixMs, 0, ts) {
			return
		}
	}
}

func (s *Server) pruneBandwidthStats(now time.Time) {
	if s == nil {
		return
	}
	cutoff := now.Add(-bandwidthStatsRetention).UnixMilli()

	s.bw.Range(func(key, value any) bool {
		e, ok := value.(*bandwidthEntry)
		if !ok || e == nil {
			s.bw.Delete(key)
			return true
		}
		closedAt := atomic.LoadInt64(&e.closedAtUnixMs)
		if closedAt != 0 && closedAt <= cutoff {
			s.bw.Delete(key)
		}
		return true
	})
}

// BandwidthSnapshot returns a point-in-time view of channel bandwidth counters.
func (s *Server) BandwidthSnapshot(now time.Time) BandwidthSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	if s == nil {
		return BandwidthSnapshot{NowUnixMs: now.UnixMilli(), Channels: nil}
	}

	out := BandwidthSnapshot{NowUnixMs: now.UnixMilli()}
	s.bw.Range(func(key, value any) bool {
		channelID, _ := key.(string)
		e, ok := value.(*bandwidthEntry)
		if channelID == "" || !ok || e == nil {
			return true
		}
		out.Channels = append(out.Channels, BandwidthChannelStats{
			ChannelID:      channelID,
			BytesToClient:  atomic.LoadUint64(&e.toClient),
			BytesToServer:  atomic.LoadUint64(&e.toServer),
			ClosedAtUnixMs: atomic.LoadInt64(&e.closedAtUnixMs),
		})
		return true
	})
	return out
}
