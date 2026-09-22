package protocolv4

import (
	"encoding/json"
	"slices"
	"sync"
)

// BootstrapSpec is the fixed initial ordinary channel declaration from the
// generated registry. Runtime callers never choose its scope, kind or credit.
type BootstrapSpec struct {
	Profiles      []string  `json:"profiles"`
	Scope         uint64    `json:"scope"`
	Opener        Direction `json:"opener"`
	Kind          string    `json:"kind"`
	MetadataBytes int       `json:"metadata_bytes"`
	ReceiveLimit  uint64    `json:"initial_receive_limit"`
	Creation      string    `json:"creation"`
}

var bootstrapSpec = sync.OnceValues(func() (BootstrapSpec, error) {
	var registry struct{ Bootstrap BootstrapSpec }
	if err := json.Unmarshal([]byte(StreamStateRegistryJSON), &registry); err != nil {
		return BootstrapSpec{}, err
	}
	return registry.Bootstrap, nil
})

func Bootstrap(applicationProfile string) (BootstrapSpec, bool, error) {
	if _, err := EnumValue("SessionContract", "application_profile", applicationProfile); err != nil {
		return BootstrapSpec{}, false, err
	}
	spec, err := bootstrapSpec()
	if err != nil {
		return BootstrapSpec{}, false, err
	}
	enabled := slices.Contains(spec.Profiles, applicationProfile)
	// Do not loan the shared registry's slice to a caller.
	spec.Profiles = nil
	return spec, enabled, nil
}

func (b BootstrapSpec) ValidatePrefix(f *Frame) bool {
	if f == nil || f.Type != FrameOpenStream || f.Header.Scope != b.Scope || f.Header.Sequence != 0 {
		return false
	}
	kind, a := f.Field("kind").Text()
	metadata, c := f.Field("metadata").ByteString()
	limit, d := f.Field("initial_receive_limit").Uint()
	direction, e := f.Field("direction").Uint()
	return a && c && d && e && direction == uint64(b.Opener) && kind == b.Kind && len(metadata) == b.MetadataBytes && limit == b.ReceiveLimit
}
