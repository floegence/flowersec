package preset

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/floegence/flowersec/flowersec-go/framing/jsonframe"
	fsproxy "github.com/floegence/flowersec/flowersec-go/proxy"
)

type Limits struct {
	MaxJSONFrameBytes *int   `json:"max_json_frame_bytes,omitempty"`
	MaxChunkBytes     *int   `json:"max_chunk_bytes,omitempty"`
	MaxBodyBytes      *int64 `json:"max_body_bytes,omitempty"`
	MaxWSFrameBytes   *int   `json:"max_ws_frame_bytes,omitempty"`
	TimeoutMS         *int   `json:"timeout_ms,omitempty"`
}

type Manifest struct {
	V          int    `json:"v"`
	PresetID   string `json:"preset_id"`
	Deprecated bool   `json:"deprecated,omitempty"`
	Limits     Limits `json:"limits"`
}

var presetIDRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

func builtinDefaultManifest() *Manifest {
	maxJSON := jsonframe.DefaultMaxJSONFrameBytes
	maxChunk := fsproxy.DefaultMaxChunkBytes
	maxBody := int64(fsproxy.DefaultMaxBodyBytes)
	maxWS := fsproxy.DefaultMaxWSFrameBytes
	return &Manifest{
		V:        1,
		PresetID: "default",
		Limits: Limits{
			MaxJSONFrameBytes: &maxJSON,
			MaxChunkBytes:     &maxChunk,
			MaxBodyBytes:      &maxBody,
			MaxWSFrameBytes:   &maxWS,
		},
	}
}

func builtinCodeServerManifest() *Manifest {
	maxJSON := jsonframe.DefaultMaxJSONFrameBytes
	maxChunk := fsproxy.DefaultMaxChunkBytes
	maxBody := int64(fsproxy.DefaultMaxBodyBytes)
	maxWS := 32 * 1024 * 1024
	return &Manifest{
		V:          1,
		PresetID:   "codeserver",
		Deprecated: true,
		Limits: Limits{
			MaxJSONFrameBytes: &maxJSON,
			MaxChunkBytes:     &maxChunk,
			MaxBodyBytes:      &maxBody,
			MaxWSFrameBytes:   &maxWS,
		},
	}
}

// ResolveBuiltin returns first-party reference manifests for deprecated named profiles.
//
// Deprecated: compatibility-only helper. Stable integrations should load a
// manifest file or consume a decoded Manifest object instead of depending on a
// named profile identifier.
func ResolveBuiltin(name string) (*Manifest, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "default":
		return builtinDefaultManifest(), nil
	case "codeserver":
		return builtinCodeServerManifest(), nil
	default:
		return nil, fmt.Errorf("unknown proxy profile: %q", name)
	}
}

func DecodeJSON(r io.Reader) (*Manifest, error) {
	var manifest Manifest
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&manifest); err != nil {
		return nil, err
	}
	if err := validateManifest(&manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func LoadFile(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeJSON(bytes.NewReader(b))
}

func ApplyBridgeOptions(opts fsproxy.BridgeOptions, manifest *Manifest) fsproxy.BridgeOptions {
	if manifest == nil {
		return opts
	}
	if opts.MaxJSONFrameBytes == 0 && manifest.Limits.MaxJSONFrameBytes != nil {
		opts.MaxJSONFrameBytes = *manifest.Limits.MaxJSONFrameBytes
	}
	if opts.MaxChunkBytes == 0 && manifest.Limits.MaxChunkBytes != nil {
		opts.MaxChunkBytes = *manifest.Limits.MaxChunkBytes
	}
	if opts.MaxBodyBytes == 0 && manifest.Limits.MaxBodyBytes != nil {
		opts.MaxBodyBytes = *manifest.Limits.MaxBodyBytes
	}
	if opts.MaxWSFrameBytes == 0 && manifest.Limits.MaxWSFrameBytes != nil {
		opts.MaxWSFrameBytes = *manifest.Limits.MaxWSFrameBytes
	}
	return opts
}

func validateManifest(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("missing manifest")
	}
	if manifest.V != 1 {
		return fmt.Errorf("invalid preset manifest version")
	}
	if !presetIDRe.MatchString(manifest.PresetID) {
		return fmt.Errorf("invalid preset_id")
	}
	if err := validatePositiveIntPtr("max_json_frame_bytes", manifest.Limits.MaxJSONFrameBytes); err != nil {
		return err
	}
	if err := validatePositiveIntPtr("max_chunk_bytes", manifest.Limits.MaxChunkBytes); err != nil {
		return err
	}
	if err := validatePositiveInt64Ptr("max_body_bytes", manifest.Limits.MaxBodyBytes); err != nil {
		return err
	}
	if err := validatePositiveIntPtr("max_ws_frame_bytes", manifest.Limits.MaxWSFrameBytes); err != nil {
		return err
	}
	if err := validatePositiveIntPtr("timeout_ms", manifest.Limits.TimeoutMS); err != nil {
		return err
	}
	return nil
}

func validatePositiveIntPtr(name string, value *int) error {
	if value != nil && *value <= 0 {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func validatePositiveInt64Ptr(name string, value *int64) error {
	if value != nil && *value <= 0 {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}
