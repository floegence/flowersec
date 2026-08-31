// Package runtimev3 defines runtime capability descriptors independently from
// the carrier-neutral session engine.
package runtimev3

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"

	"github.com/floegence/flowersec/flowersec-go/v4/internal/carrier"
)

const CapabilityDigestLabelV3 = "flowersec-v3-runtime-capability\x00"

var capabilityRegistryToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

const maxCapabilityJSONPreflightDepth = 128

type NetworkMode string
type SessionRole string
type SecurityMode string

const (
	NetworkDial   NetworkMode  = "dial"
	NetworkListen NetworkMode  = "listen"
	RoleClient    SessionRole  = "client"
	RoleServer    SessionRole  = "server"
	SecurityCA    SecurityMode = "ca"
	SecurityPin   SecurityMode = "pin"
)

type CapabilityTuple struct {
	Carrier         carrier.Kind   `json:"carrier"`
	Datagrams       bool           `json:"datagrams"`
	Migration       bool           `json:"migration"`
	NetworkMode     NetworkMode    `json:"networkMode"`
	Path            carrier.Path   `json:"path"`
	ReliableStreams bool           `json:"reliableStreams"`
	SecurityModes   []SecurityMode `json:"securityModes"`
	SessionRole     SessionRole    `json:"sessionRole"`
}

type UnsupportedCapability struct {
	Carrier carrier.Kind `json:"carrier"`
	Reason  string       `json:"reason"`
}

type CapabilityDescriptor struct {
	Language      string                  `json:"language"`
	Runtime       string                  `json:"runtime"`
	SchemaVersion uint8                   `json:"schemaVersion"`
	Tuples        []CapabilityTuple       `json:"tuples"`
	Unsupported   []UnsupportedCapability `json:"unsupported"`
}

var (
	ErrInvalidCapability   = errors.New("invalid capability")
	ErrDuplicateCapability = errors.New("duplicate capability")
)

func (d CapabilityDescriptor) Validate() error {
	if err := validateCapabilityDescriptorShape(d); err != nil {
		return ErrInvalidCapability
	}
	seen := make(map[capabilityIdentity]struct{}, len(d.Tuples))
	for index, tuple := range d.Tuples {
		if err := tuple.validate(); err != nil {
			return err
		}
		identity := identityOf(tuple)
		if _, ok := seen[identity]; ok {
			return fmt.Errorf("%w: %+v", ErrDuplicateCapability, tuple)
		}
		if index > 0 && !capabilityTupleLess(d.Tuples[index-1], tuple) {
			return ErrInvalidCapability
		}
		seen[identity] = struct{}{}
	}
	if err := validateUnsupportedCapabilities(d, seen); err != nil {
		return err
	}
	return validateRegisteredRuntime(d)
}

func (d CapabilityDescriptor) Supports(want CapabilityTuple) bool {
	for _, tuple := range d.Tuples {
		if identityOf(tuple) == identityOf(want) && tuple.ReliableStreams == want.ReliableStreams &&
			tuple.Datagrams == want.Datagrams && tuple.Migration == want.Migration && slices.Equal(tuple.SecurityModes, want.SecurityModes) {
			return true
		}
	}
	return false
}

func (t CapabilityTuple) validate() error {
	if err := t.Carrier.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCapability, err)
	}
	if t.NetworkMode != NetworkDial && t.NetworkMode != NetworkListen {
		return ErrInvalidCapability
	}
	if t.SessionRole != RoleClient && t.SessionRole != RoleServer {
		return ErrInvalidCapability
	}
	if t.Path != carrier.PathDirect && t.Path != carrier.PathTunnel {
		return ErrInvalidCapability
	}
	if !t.ReliableStreams || (t.Carrier == carrier.KindWebSocket && (t.Datagrams || t.Migration)) {
		return ErrInvalidCapability
	}
	if t.NetworkMode == NetworkListen {
		if len(t.SecurityModes) != 0 {
			return ErrInvalidCapability
		}
	} else if !slices.Equal(t.SecurityModes, []SecurityMode{SecurityCA}) &&
		!slices.Equal(t.SecurityModes, []SecurityMode{SecurityPin}) &&
		!slices.Equal(t.SecurityModes, []SecurityMode{SecurityCA, SecurityPin}) {
		return ErrInvalidCapability
	}
	switch t.Path {
	case carrier.PathDirect:
		if (t.NetworkMode != NetworkDial || t.SessionRole != RoleClient) &&
			(t.NetworkMode != NetworkListen || t.SessionRole != RoleServer) {
			return ErrInvalidCapability
		}
	case carrier.PathTunnel:
		if t.NetworkMode != NetworkDial {
			return ErrInvalidCapability
		}
	}
	return nil
}

// GoCapabilities explicitly lists all implemented Go runtime routes.
func GoCapabilities() CapabilityDescriptor {
	native := func(kind carrier.Kind, mode NetworkMode, role SessionRole, path carrier.Path) CapabilityTuple {
		securityModes := []SecurityMode{}
		if mode == NetworkDial {
			securityModes = []SecurityMode{SecurityCA, SecurityPin}
		}
		return CapabilityTuple{
			Carrier: kind, NetworkMode: mode, SessionRole: role, Path: path,
			ReliableStreams: true,
			Datagrams:       kind != carrier.KindWebSocket,
			Migration:       kind == carrier.KindRawQUIC && mode == NetworkDial,
			SecurityModes:   securityModes,
		}
	}
	tuples := []CapabilityTuple{
		native(carrier.KindRawQUIC, NetworkDial, RoleClient, carrier.PathDirect),
		native(carrier.KindRawQUIC, NetworkDial, RoleClient, carrier.PathTunnel),
		native(carrier.KindRawQUIC, NetworkDial, RoleServer, carrier.PathTunnel),
		native(carrier.KindRawQUIC, NetworkListen, RoleServer, carrier.PathDirect),
		native(carrier.KindWebSocket, NetworkDial, RoleClient, carrier.PathDirect),
		native(carrier.KindWebSocket, NetworkDial, RoleClient, carrier.PathTunnel),
		native(carrier.KindWebSocket, NetworkDial, RoleServer, carrier.PathTunnel),
		native(carrier.KindWebSocket, NetworkListen, RoleServer, carrier.PathDirect),
		native(carrier.KindWebTransport, NetworkDial, RoleClient, carrier.PathDirect),
		native(carrier.KindWebTransport, NetworkDial, RoleClient, carrier.PathTunnel),
		native(carrier.KindWebTransport, NetworkDial, RoleServer, carrier.PathTunnel),
		native(carrier.KindWebTransport, NetworkListen, RoleServer, carrier.PathDirect),
	}
	return CapabilityDescriptor{
		Language: "go", Runtime: "native", SchemaVersion: 3,
		Tuples: tuples, Unsupported: []UnsupportedCapability{},
	}
}

type capabilityDescriptorWire struct {
	Language      string                  `json:"language"`
	Runtime       string                  `json:"runtime"`
	SchemaVersion uint8                   `json:"schemaVersion"`
	Tuples        []CapabilityTuple       `json:"tuples"`
	Unsupported   []UnsupportedCapability `json:"unsupported"`
}

func EncodeCapabilityDescriptor(descriptor CapabilityDescriptor) ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}
	wire := capabilityDescriptorWire{
		Language: descriptor.Language, Runtime: descriptor.Runtime,
		SchemaVersion: descriptor.SchemaVersion,
		Tuples:        append([]CapabilityTuple{}, descriptor.Tuples...),
		Unsupported:   append([]UnsupportedCapability{}, descriptor.Unsupported...),
	}
	return json.Marshal(wire)
}

func DecodeCapabilityDescriptor(raw []byte) (CapabilityDescriptor, error) {
	if err := rejectDuplicateCapabilityJSONFields(raw); err != nil {
		return CapabilityDescriptor{}, fmt.Errorf("decode capability descriptor: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire capabilityDescriptorWire
	if err := decoder.Decode(&wire); err != nil {
		return CapabilityDescriptor{}, fmt.Errorf("decode capability descriptor: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CapabilityDescriptor{}, ErrInvalidCapability
	}
	descriptor := CapabilityDescriptor{
		Language: wire.Language, Runtime: wire.Runtime, SchemaVersion: wire.SchemaVersion,
		Tuples: wire.Tuples, Unsupported: wire.Unsupported,
	}
	canonical, err := EncodeCapabilityDescriptor(descriptor)
	if err != nil {
		return CapabilityDescriptor{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return CapabilityDescriptor{}, fmt.Errorf("%w: descriptor is not canonical JSON", ErrInvalidCapability)
	}
	return descriptor, nil
}

func rejectDuplicateCapabilityJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanCapabilityJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanCapabilityJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxCapabilityJSONPreflightDepth {
		return fmt.Errorf("capability JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanCapabilityJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("invalid JSON object terminator")
		}
	case '[':
		for decoder.More() {
			if err := scanCapabilityJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func CapabilityDescriptorDigest(descriptor CapabilityDescriptor) ([32]byte, error) {
	canonical, err := EncodeCapabilityDescriptor(descriptor)
	if err != nil {
		return [32]byte{}, err
	}
	length, err := capabilityDigestLength(uint64(len(canonical)))
	if err != nil {
		return [32]byte{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(CapabilityDigestLabelV3))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(canonical)
	var result [sha256.Size]byte
	digest.Sum(result[:0])
	return result, nil
}

func capabilityDigestLength(length uint64) ([4]byte, error) {
	if length > math.MaxUint32 {
		return [4]byte{}, fmt.Errorf("%w: canonical descriptor exceeds uint32 length", ErrInvalidCapability)
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(length))
	return encoded, nil
}

func validateCapabilityDescriptorShape(descriptor CapabilityDescriptor) error {
	if descriptor.SchemaVersion != 3 || !capabilityRegistryToken.MatchString(descriptor.Language) ||
		!capabilityRegistryToken.MatchString(descriptor.Runtime) ||
		len(descriptor.Tuples)+len(descriptor.Unsupported) == 0 {
		return ErrInvalidCapability
	}
	if !registeredRuntime(descriptor.Language, descriptor.Runtime) {
		return ErrInvalidCapability
	}
	return nil
}

func validateUnsupportedCapabilities(descriptor CapabilityDescriptor, tuples map[capabilityIdentity]struct{}) error {
	supportedCarriers := make(map[carrier.Kind]struct{}, 3)
	for tuple := range tuples {
		supportedCarriers[tuple.carrier] = struct{}{}
	}
	unsupportedCarriers := make(map[carrier.Kind]struct{}, len(descriptor.Unsupported))
	for index, unsupported := range descriptor.Unsupported {
		if err := unsupported.Carrier.Validate(); err != nil || !registeredUnsupportedReason(unsupported.Reason) {
			return ErrInvalidCapability
		}
		if _, ok := supportedCarriers[unsupported.Carrier]; ok {
			return ErrInvalidCapability
		}
		if _, ok := unsupportedCarriers[unsupported.Carrier]; ok {
			return ErrDuplicateCapability
		}
		if index > 0 && descriptor.Unsupported[index-1].Carrier >= unsupported.Carrier {
			return ErrInvalidCapability
		}
		unsupportedCarriers[unsupported.Carrier] = struct{}{}
	}
	for _, kind := range []carrier.Kind{carrier.KindRawQUIC, carrier.KindWebSocket, carrier.KindWebTransport} {
		_, supported := supportedCarriers[kind]
		_, unsupported := unsupportedCarriers[kind]
		if supported == unsupported {
			return ErrInvalidCapability
		}
	}
	return nil
}

func validateRegisteredRuntime(descriptor CapabilityDescriptor) error {
	expected, ok := registeredCarrierCapabilities(descriptor.Language, descriptor.Runtime)
	if !ok {
		return ErrInvalidCapability
	}
	for _, kind := range []carrier.Kind{carrier.KindRawQUIC, carrier.KindWebSocket, carrier.KindWebTransport} {
		actualTuples := tuplesForCarrier(descriptor.Tuples, kind)
		unsupported, isUnsupported := unsupportedForCarrier(descriptor.Unsupported, kind)
		want := expected[kind]
		if isUnsupported {
			if !slices.Contains(want.unsupportedReasons, unsupported.Reason) || len(actualTuples) != 0 {
				return ErrInvalidCapability
			}
			continue
		}
		if len(want.tupleSets) == 0 || !matchesRegisteredTupleSet(actualTuples, want.tupleSets) {
			return ErrInvalidCapability
		}
	}
	return nil
}

type registeredCarrierCapability struct {
	tupleSets          [][]CapabilityTuple
	unsupportedReasons []string
}

func registeredCarrierCapabilities(language, runtime string) (map[carrier.Kind]registeredCarrierCapability, bool) {
	ca := []SecurityMode{SecurityCA}
	caPin := []SecurityMode{SecurityCA, SecurityPin}
	websocket4 := func(modes []SecurityMode) []CapabilityTuple {
		return registeredTuples(carrier.KindWebSocket, false, false, true, modes)
	}
	websocket3 := func(modes []SecurityMode) []CapabilityTuple {
		return registeredTuples(carrier.KindWebSocket, false, false, false, modes)
	}
	rawQUIC4M := registeredTuples(carrier.KindRawQUIC, true, true, true, caPin)
	rawQUIC4N := registeredTuples(carrier.KindRawQUIC, true, false, true, caPin)
	webTransport4 := registeredTuples(carrier.KindWebTransport, true, false, true, caPin)
	webTransport3CA := registeredTuples(carrier.KindWebTransport, true, false, false, ca)
	webTransport3Pin := registeredTuples(carrier.KindWebTransport, true, false, false, caPin)
	switch language + "/" + runtime {
	case "go/native":
		return map[carrier.Kind]registeredCarrierCapability{
			carrier.KindRawQUIC:      {tupleSets: [][]CapabilityTuple{rawQUIC4M}},
			carrier.KindWebSocket:    {tupleSets: [][]CapabilityTuple{websocket4(caPin)}},
			carrier.KindWebTransport: {tupleSets: [][]CapabilityTuple{webTransport4}},
		}, true
	case "typescript/browser":
		return map[carrier.Kind]registeredCarrierCapability{
			carrier.KindRawQUIC:      {unsupportedReasons: []string{"browser_no_raw_udp"}},
			carrier.KindWebSocket:    {tupleSets: [][]CapabilityTuple{websocket3(ca)}, unsupportedReasons: []string{"browser_websocket_api_unavailable"}},
			carrier.KindWebTransport: {tupleSets: [][]CapabilityTuple{webTransport3CA, webTransport3Pin}, unsupportedReasons: []string{"browser_webtransport_api_unavailable"}},
		}, true
	case "typescript/node":
		return map[carrier.Kind]registeredCarrierCapability{
			carrier.KindRawQUIC:      {tupleSets: [][]CapabilityTuple{rawQUIC4N}, unsupportedReasons: []string{"node_native_transport_unavailable"}},
			carrier.KindWebSocket:    {tupleSets: [][]CapabilityTuple{websocket4(caPin)}},
			carrier.KindWebTransport: {unsupportedReasons: []string{"node_webtransport_driver_unavailable"}},
		}, true
	case "rust/native":
		return map[carrier.Kind]registeredCarrierCapability{
			carrier.KindRawQUIC:      {tupleSets: [][]CapabilityTuple{rawQUIC4M}},
			carrier.KindWebSocket:    {tupleSets: [][]CapabilityTuple{websocket4(caPin)}},
			carrier.KindWebTransport: {unsupportedReasons: []string{"driver_unavailable"}},
		}, true
	case "swift/ios", "swift/macos":
		return map[carrier.Kind]registeredCarrierCapability{
			carrier.KindRawQUIC:      {unsupportedReasons: []string{"swift_apple_client_profile_excludes_raw_quic"}},
			carrier.KindWebSocket:    {tupleSets: [][]CapabilityTuple{websocket3(caPin)}},
			carrier.KindWebTransport: {unsupportedReasons: []string{"swift_apple_client_profile_excludes_webtransport"}},
		}, true
	case "swift/linux":
		return map[carrier.Kind]registeredCarrierCapability{
			carrier.KindRawQUIC:      {unsupportedReasons: []string{"swift_apple_client_profile_excludes_raw_quic"}},
			carrier.KindWebSocket:    {unsupportedReasons: []string{"websocket_adapter_not_supported_on_linux"}},
			carrier.KindWebTransport: {unsupportedReasons: []string{"swift_apple_client_profile_excludes_webtransport"}},
		}, true
	default:
		return nil, false
	}
}

func registeredTuples(kind carrier.Kind, datagrams, dialMigration, includeListener bool, securityModes []SecurityMode) []CapabilityTuple {
	tuples := []CapabilityTuple{
		registeredTuple(kind, NetworkDial, RoleClient, carrier.PathDirect, datagrams, dialMigration, securityModes),
		registeredTuple(kind, NetworkDial, RoleClient, carrier.PathTunnel, datagrams, dialMigration, securityModes),
		registeredTuple(kind, NetworkDial, RoleServer, carrier.PathTunnel, datagrams, dialMigration, securityModes),
	}
	if includeListener {
		tuples = append(tuples, registeredTuple(kind, NetworkListen, RoleServer, carrier.PathDirect, datagrams, false, nil))
	}
	return tuples
}

func registeredTuple(kind carrier.Kind, networkMode NetworkMode, role SessionRole, path carrier.Path, datagrams, migration bool, modes []SecurityMode) CapabilityTuple {
	if modes == nil {
		modes = []SecurityMode{}
	}
	return CapabilityTuple{
		Carrier: kind, Datagrams: datagrams, Migration: migration, NetworkMode: networkMode,
		Path: path, ReliableStreams: true, SecurityModes: slices.Clone(modes), SessionRole: role,
	}
}

func tuplesForCarrier(tuples []CapabilityTuple, kind carrier.Kind) []CapabilityTuple {
	result := make([]CapabilityTuple, 0, len(tuples))
	for _, tuple := range tuples {
		if tuple.Carrier == kind {
			result = append(result, tuple)
		}
	}
	return result
}

func unsupportedForCarrier(entries []UnsupportedCapability, kind carrier.Kind) (UnsupportedCapability, bool) {
	for _, entry := range entries {
		if entry.Carrier == kind {
			return entry, true
		}
	}
	return UnsupportedCapability{}, false
}

func matchesRegisteredTupleSet(actual []CapabilityTuple, expected [][]CapabilityTuple) bool {
	for _, candidate := range expected {
		if slices.EqualFunc(actual, candidate, equalCapabilityTuple) {
			return true
		}
	}
	return false
}

func equalCapabilityTuple(left, right CapabilityTuple) bool {
	return left.Carrier == right.Carrier && left.Datagrams == right.Datagrams &&
		left.Migration == right.Migration && left.NetworkMode == right.NetworkMode &&
		left.Path == right.Path && left.ReliableStreams == right.ReliableStreams &&
		slices.Equal(left.SecurityModes, right.SecurityModes) && left.SessionRole == right.SessionRole
}

func registeredUnsupportedReason(reason string) bool {
	switch reason {
	case "adapter_not_composed", "browser_no_raw_udp", "browser_websocket_api_unavailable",
		"browser_webtransport_api_unavailable", "node_native_transport_unavailable",
		"node_webtransport_driver_unavailable", "driver_unavailable",
		"swift_apple_client_profile_excludes_raw_quic", "websocket_adapter_not_supported_on_linux",
		"swift_apple_client_profile_excludes_webtransport":
		return true
	default:
		return false
	}
}

func capabilityTupleLess(left, right CapabilityTuple) bool {
	return slices.Compare(
		[]string{string(left.Carrier), string(left.NetworkMode), string(left.SessionRole), string(left.Path)},
		[]string{string(right.Carrier), string(right.NetworkMode), string(right.SessionRole), string(right.Path)},
	) < 0
}

type capabilityIdentity struct {
	carrier     carrier.Kind
	networkMode NetworkMode
	sessionRole SessionRole
	path        carrier.Path
}

func identityOf(tuple CapabilityTuple) capabilityIdentity {
	return capabilityIdentity{tuple.Carrier, tuple.NetworkMode, tuple.SessionRole, tuple.Path}
}

func registeredRuntime(language, runtime string) bool {
	switch language + "/" + runtime {
	case "go/native", "typescript/browser", "typescript/node", "rust/native", "swift/ios", "swift/macos", "swift/linux":
		return true
	default:
		return false
	}
}

func SupportsSecurityMode(descriptor CapabilityDescriptor, kind carrier.Kind, role SessionRole, path carrier.Path, mode SecurityMode) bool {
	for _, tuple := range descriptor.Tuples {
		if tuple.Carrier == kind && tuple.NetworkMode == NetworkDial && tuple.SessionRole == role && tuple.Path == path && slices.Contains(tuple.SecurityModes, mode) {
			return true
		}
	}
	return false
}
