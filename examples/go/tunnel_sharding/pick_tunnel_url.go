package tunnelsharding

import (
	"crypto/sha256"
	"encoding/binary"
)

// PickTunnelURL selects a stable tunnel URL for a channel using rendezvous hashing (HRW).
//
// Highest-score wins: score = sha256(channelID + "|" + url)[:8] interpreted as big-endian uint64.
func PickTunnelURL(channelID string, urls []string) string {
	var best string
	var bestScore uint64
	for _, u := range urls {
		h := sha256.Sum256([]byte(channelID + "|" + u))
		score := binary.BigEndian.Uint64(h[:8])
		if best == "" || score > bestScore {
			best, bestScore = u, score
		}
	}
	return best
}
