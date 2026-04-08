package protocolio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	controlv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/controlplane/v1"
	directv1 "github.com/floegence/flowersec/flowersec-go/gen/flowersec/direct/v1"
)

type ConnectArtifactTransport string

const (
	ConnectArtifactTransportTunnel ConnectArtifactTransport = "tunnel"
	ConnectArtifactTransportDirect ConnectArtifactTransport = "direct"
)

type CorrelationKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type CorrelationContext struct {
	V         int             `json:"v"`
	TraceID   *string         `json:"trace_id,omitempty"`
	SessionID *string         `json:"session_id,omitempty"`
	Tags      []CorrelationKV `json:"tags"`
}

type ScopePayload map[string]any

type ScopeMetadataEntry struct {
	Scope        string       `json:"scope"`
	ScopeVersion int          `json:"scope_version"`
	Critical     bool         `json:"critical"`
	Payload      ScopePayload `json:"payload"`
}

type ConnectArtifact struct {
	V           int                         `json:"v"`
	Transport   ConnectArtifactTransport    `json:"transport"`
	TunnelGrant *controlv1.ChannelInitGrant `json:"tunnel_grant,omitempty"`
	DirectInfo  *directv1.DirectConnectInfo `json:"direct_info,omitempty"`
	Scoped      []ScopeMetadataEntry        `json:"scoped,omitempty"`
	Correlation *CorrelationContext         `json:"correlation,omitempty"`
}

// TunnelClientConnectArtifact is the named tunnel-client variant of ConnectArtifact.
//
// It stays data-only so Go integrations can depend on a stable, exported artifact
// type without taking on additional codegen/runtime machinery.
type TunnelClientConnectArtifact = ConnectArtifact

// DirectClientConnectArtifact is the named direct-client variant of ConnectArtifact.
//
// It stays data-only so Go integrations can depend on a stable, exported artifact
// type without taking on additional codegen/runtime machinery.
type DirectClientConnectArtifact = ConnectArtifact

var (
	scopeNameRe     = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	tagKeyRe        = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,31}$`)
	correlationIDRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{8,128}$`)
)

func DecodeConnectArtifactJSON(r io.Reader) (*ConnectArtifact, error) {
	b, err := readAllLimit(r, DefaultMaxJSONBytes)
	if err != nil {
		return nil, err
	}
	return decodeConnectArtifactBytes(b)
}

func decodeConnectArtifactBytes(b []byte) (*ConnectArtifact, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, err
	}
	v, err := decodeRequiredInt(top, "v")
	if err != nil {
		return nil, fmt.Errorf("bad ConnectArtifact.v: %w", err)
	}
	if v != 1 {
		return nil, fmt.Errorf("bad ConnectArtifact.v")
	}
	transport, err := decodeRequiredString(top, "transport")
	if err != nil {
		return nil, fmt.Errorf("bad ConnectArtifact.transport: %w", err)
	}
	out := &ConnectArtifact{V: 1}
	switch transport {
	case string(ConnectArtifactTransportTunnel):
		out.Transport = ConnectArtifactTransportTunnel
		if err := assertAllowedKeys(top, "TunnelClientConnectArtifact", map[string]struct{}{
			"v": {}, "transport": {}, "tunnel_grant": {}, "scoped": {}, "correlation": {},
		}); err != nil {
			return nil, err
		}
		grantRaw, ok := top["tunnel_grant"]
		if !ok {
			return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant")
		}
		grant, err := decodeArtifactTunnelGrant(grantRaw)
		if err != nil {
			return nil, err
		}
		out.TunnelGrant = grant
	case string(ConnectArtifactTransportDirect):
		out.Transport = ConnectArtifactTransportDirect
		if err := assertAllowedKeys(top, "DirectClientConnectArtifact", map[string]struct{}{
			"v": {}, "transport": {}, "direct_info": {}, "scoped": {}, "correlation": {},
		}); err != nil {
			return nil, err
		}
		infoRaw, ok := top["direct_info"]
		if !ok {
			return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info")
		}
		info, err := decodeArtifactDirectInfo(infoRaw)
		if err != nil {
			return nil, err
		}
		out.DirectInfo = info
	default:
		return nil, fmt.Errorf("bad ConnectArtifact.transport")
	}
	if raw, ok := top["scoped"]; ok {
		scoped, err := decodeScopedEntries(raw)
		if err != nil {
			return nil, err
		}
		out.Scoped = scoped
	}
	if raw, ok := top["correlation"]; ok {
		correlation, err := decodeCorrelation(raw)
		if err != nil {
			return nil, err
		}
		out.Correlation = correlation
	}
	return out, nil
}

func assertAllowedKeys(top map[string]json.RawMessage, kind string, allowed map[string]struct{}) error {
	for key := range top {
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("bad %s.%s", kind, key)
		}
	}
	return nil
}

func decodeRequiredString(top map[string]json.RawMessage, key string) (string, error) {
	raw, ok := top[key]
	if !ok {
		return "", fmt.Errorf("missing")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

func decodeRequiredInt(top map[string]json.RawMessage, key string) (int, error) {
	raw, ok := top[key]
	if !ok {
		return 0, fmt.Errorf("missing")
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n, nil
}

func decodeRequiredInt32(top map[string]json.RawMessage, key string) (int32, error) {
	raw, ok := top[key]
	if !ok {
		return 0, fmt.Errorf("missing")
	}
	var n int32
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n, nil
}

func decodeRequiredInt64(top map[string]json.RawMessage, key string) (int64, error) {
	raw, ok := top[key]
	if !ok {
		return 0, fmt.Errorf("missing")
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, err
	}
	return n, nil
}

func decodeRequiredIntSlice(top map[string]json.RawMessage, key string) ([]int, error) {
	raw, ok := top[key]
	if !ok {
		return nil, fmt.Errorf("missing")
	}
	var items []int
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func decodeArtifactTunnelGrant(raw json.RawMessage) (*controlv1.ChannelInitGrant, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant: %w", err)
	}
	if _, err := decodeRequiredString(top, "tunnel_url"); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.tunnel_url")
	}
	if _, err := decodeRequiredString(top, "channel_id"); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.channel_id")
	}
	if _, err := decodeRequiredInt64(top, "channel_init_expire_at_unix_s"); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.channel_init_expire_at_unix_s")
	}
	if _, err := decodeRequiredInt32(top, "idle_timeout_seconds"); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.idle_timeout_seconds")
	}
	role, err := decodeRequiredInt(top, "role")
	if err != nil || !validControlRole(controlv1.Role(role)) {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.role")
	}
	if _, err := decodeRequiredString(top, "token"); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.token")
	}
	if _, err := decodeRequiredString(top, "e2ee_psk_b64u"); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.e2ee_psk_b64u")
	}
	allowedSuites, err := decodeRequiredIntSlice(top, "allowed_suites")
	if err != nil || len(allowedSuites) == 0 {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.allowed_suites")
	}
	for _, suite := range allowedSuites {
		if !validControlSuite(controlv1.Suite(suite)) {
			return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.allowed_suites")
		}
	}
	defaultSuite, err := decodeRequiredInt(top, "default_suite")
	if err != nil || !validControlSuite(controlv1.Suite(defaultSuite)) {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.default_suite")
	}

	var grant controlv1.ChannelInitGrant
	if err := json.Unmarshal(raw, &grant); err != nil {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant: %w", err)
	}
	if grant.Role != controlv1.Role_client {
		return nil, fmt.Errorf("bad TunnelClientConnectArtifact.tunnel_grant.role")
	}
	return &grant, nil
}

func decodeArtifactDirectInfo(raw json.RawMessage) (*directv1.DirectConnectInfo, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info: %w", err)
	}
	if _, err := decodeRequiredString(top, "ws_url"); err != nil {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info.ws_url")
	}
	if _, err := decodeRequiredString(top, "channel_id"); err != nil {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info.channel_id")
	}
	if _, err := decodeRequiredString(top, "e2ee_psk_b64u"); err != nil {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info.e2ee_psk_b64u")
	}
	if _, err := decodeRequiredInt64(top, "channel_init_expire_at_unix_s"); err != nil {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info.channel_init_expire_at_unix_s")
	}
	defaultSuite, err := decodeRequiredInt(top, "default_suite")
	if err != nil || !validDirectSuite(directv1.Suite(defaultSuite)) {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info.default_suite")
	}

	var info directv1.DirectConnectInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return nil, fmt.Errorf("bad DirectClientConnectArtifact.direct_info: %w", err)
	}
	return &info, nil
}

func validControlRole(role controlv1.Role) bool {
	switch role {
	case controlv1.Role_client, controlv1.Role_server:
		return true
	default:
		return false
	}
}

func validControlSuite(suite controlv1.Suite) bool {
	switch suite {
	case controlv1.Suite_X25519_HKDF_SHA256_AES_256_GCM, controlv1.Suite_P256_HKDF_SHA256_AES_256_GCM:
		return true
	default:
		return false
	}
}

func validDirectSuite(suite directv1.Suite) bool {
	switch suite {
	case directv1.Suite_X25519_HKDF_SHA256_AES_256_GCM, directv1.Suite_P256_HKDF_SHA256_AES_256_GCM:
		return true
	default:
		return false
	}
}

func decodeScopedEntries(raw json.RawMessage) ([]ScopeMetadataEntry, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("bad ConnectArtifact.scoped: %w", err)
	}
	if len(entries) > 8 {
		return nil, fmt.Errorf("bad ConnectArtifact.scoped")
	}
	out := make([]ScopeMetadataEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entryRaw := range entries {
		entry, err := decodeScopeEntry(entryRaw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[entry.Scope]; ok {
			return nil, fmt.Errorf("bad ConnectArtifact.scoped")
		}
		seen[entry.Scope] = struct{}{}
		out = append(out, entry)
	}
	return out, nil
}

func decodeScopeEntry(raw json.RawMessage) (ScopeMetadataEntry, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return ScopeMetadataEntry{}, fmt.Errorf("bad ScopeMetadataEntry: %w", err)
	}
	if err := assertAllowedKeys(top, "ScopeMetadataEntry", map[string]struct{}{
		"scope": {}, "scope_version": {}, "critical": {}, "payload": {},
	}); err != nil {
		return ScopeMetadataEntry{}, err
	}
	scope, err := decodeRequiredString(top, "scope")
	if err != nil || !scopeNameRe.MatchString(scope) {
		return ScopeMetadataEntry{}, fmt.Errorf("bad ScopeMetadataEntry.scope")
	}
	scopeVersion, err := decodeRequiredInt(top, "scope_version")
	if err != nil || scopeVersion < 1 || scopeVersion > 65535 {
		return ScopeMetadataEntry{}, fmt.Errorf("bad ScopeMetadataEntry.scope_version")
	}
	var critical bool
	if err := json.Unmarshal(top["critical"], &critical); err != nil {
		return ScopeMetadataEntry{}, fmt.Errorf("bad ScopeMetadataEntry.critical")
	}
	payload, err := decodeScopePayload(top["payload"])
	if err != nil {
		return ScopeMetadataEntry{}, err
	}
	return ScopeMetadataEntry{
		Scope:        scope,
		ScopeVersion: scopeVersion,
		Critical:     critical,
		Payload:      payload,
	}, nil
}

func decodeScopePayload(raw json.RawMessage) (ScopePayload, error) {
	value, err := decodeJSONAny(raw)
	if err != nil {
		return nil, fmt.Errorf("bad ScopeMetadataEntry.payload: %w", err)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("bad ScopeMetadataEntry.payload")
	}
	normalized, err := normalizedJSONBytes(obj)
	if err != nil {
		return nil, fmt.Errorf("bad ScopeMetadataEntry.payload: %w", err)
	}
	if len(normalized) > 8192 {
		return nil, fmt.Errorf("bad ScopeMetadataEntry.payload")
	}
	if maxJSONContainerDepth(obj) > 8 {
		return nil, fmt.Errorf("bad ScopeMetadataEntry.payload")
	}
	return ScopePayload(obj), nil
}

func decodeCorrelation(raw json.RawMessage) (*CorrelationContext, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("bad CorrelationContext: %w", err)
	}
	if err := assertAllowedKeys(top, "CorrelationContext", map[string]struct{}{
		"v": {}, "trace_id": {}, "session_id": {}, "tags": {},
	}); err != nil {
		return nil, err
	}
	v, err := decodeRequiredInt(top, "v")
	if err != nil || v != 1 {
		return nil, fmt.Errorf("bad CorrelationContext.v")
	}
	traceID, err := decodeOptionalCorrelationID(top["trace_id"])
	if err != nil {
		return nil, err
	}
	sessionID, err := decodeOptionalCorrelationID(top["session_id"])
	if err != nil {
		return nil, err
	}
	tagsRaw, ok := top["tags"]
	if !ok {
		tagsRaw = json.RawMessage("[]")
	}
	tags, err := decodeCorrelationTags(tagsRaw)
	if err != nil {
		return nil, err
	}
	return &CorrelationContext{
		V:         1,
		TraceID:   traceID,
		SessionID: sessionID,
		Tags:      tags,
	}, nil
}

func decodeOptionalCorrelationID(raw json.RawMessage) (*string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("bad CorrelationContext.id")
	}
	trimmed := strings.TrimSpace(s)
	if !correlationIDRe.MatchString(trimmed) {
		return nil, nil
	}
	return &trimmed, nil
}

func decodeCorrelationTags(raw json.RawMessage) ([]CorrelationKV, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("bad CorrelationContext.tags")
	}
	if len(entries) > 8 {
		return nil, fmt.Errorf("bad CorrelationContext.tags")
	}
	out := make([]CorrelationKV, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entryRaw := range entries {
		entry, err := decodeCorrelationTag(entryRaw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[entry.Key]; ok {
			return nil, fmt.Errorf("bad CorrelationContext.tags")
		}
		seen[entry.Key] = struct{}{}
		out = append(out, entry)
	}
	return out, nil
}

func decodeCorrelationTag(raw json.RawMessage) (CorrelationKV, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return CorrelationKV{}, fmt.Errorf("bad CorrelationKV: %w", err)
	}
	if err := assertAllowedKeys(top, "CorrelationKV", map[string]struct{}{
		"key": {}, "value": {},
	}); err != nil {
		return CorrelationKV{}, err
	}
	key, err := decodeRequiredString(top, "key")
	if err != nil || !tagKeyRe.MatchString(key) || len([]byte(key)) > 32 {
		return CorrelationKV{}, fmt.Errorf("bad CorrelationKV.key")
	}
	value, err := decodeRequiredString(top, "value")
	if err != nil || len([]byte(value)) > 128 {
		return CorrelationKV{}, fmt.Errorf("bad CorrelationKV.value")
	}
	return CorrelationKV{Key: key, Value: value}, nil
}

func decodeJSONAny(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizedJSONBytes(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := appendNormalizedJSON(&buf, value); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func appendNormalizedJSON(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(v.String())
	case float64:
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, entry := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendNormalizedJSON(buf, entry); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return err
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := appendNormalizedJSON(buf, v[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported json value %T", value)
	}
	return nil
}

func maxJSONContainerDepth(value any) int {
	switch v := value.(type) {
	case []any:
		best := 1
		for _, entry := range v {
			if d := 1 + maxJSONContainerDepth(entry); d > best {
				best = d
			}
		}
		return best
	case map[string]any:
		best := 1
		for _, entry := range v {
			if d := 1 + maxJSONContainerDepth(entry); d > best {
				best = d
			}
		}
		return best
	default:
		return 0
	}
}
