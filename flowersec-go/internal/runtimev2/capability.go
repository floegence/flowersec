// Package runtimev2 defines runtime capability descriptors independently from
// the carrier-neutral session engine.
package runtimev2

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/floegence/flowersec/flowersec-go/v2/internal/carrier"
)

const capabilityDigestLabel = "flowersec-v2-runtime-capability\x00"

var capabilityRegistryToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

type NetworkMode string
type SessionRole string

const (
	NetworkDial   NetworkMode = "dial"
	NetworkListen NetworkMode = "listen"
	RoleClient    SessionRole = "client"
	RoleServer    SessionRole = "server"
)

type CapabilityTuple struct {
	Carrier         carrier.Kind `json:"carrier"`
	Datagrams       bool         `json:"datagrams"`
	Migration       bool         `json:"migration"`
	NetworkMode     NetworkMode  `json:"networkMode"`
	Path            carrier.Path `json:"path"`
	ReliableStreams bool         `json:"reliableStreams"`
	SessionRole     SessionRole  `json:"sessionRole"`
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
	seen := make(map[CapabilityTuple]struct{}, len(d.Tuples))
	for index, tuple := range d.Tuples {
		if err := tuple.validate(); err != nil {
			return err
		}
		if _, ok := seen[tuple]; ok {
			return fmt.Errorf("%w: %+v", ErrDuplicateCapability, tuple)
		}
		if index > 0 && !capabilityTupleLess(d.Tuples[index-1], tuple) {
			return ErrInvalidCapability
		}
		seen[tuple] = struct{}{}
	}
	return validateUnsupportedCapabilities(d, seen)
}

func (d CapabilityDescriptor) Supports(want CapabilityTuple) bool {
	for _, tuple := range d.Tuples {
		if tuple == want {
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
	return GoCapabilitiesForCarriers(
		carrier.KindRawQUIC,
		carrier.KindWebSocket,
		carrier.KindWebTransport,
	)
}

// GoCapabilitiesForCarriers describes the adapters composed into one Go
// runtime. A carrier that was not composed is explicitly unsupported.
func GoCapabilitiesForCarriers(kinds ...carrier.Kind) CapabilityDescriptor {
	native := func(kind carrier.Kind, mode NetworkMode, role SessionRole, path carrier.Path) CapabilityTuple {
		return CapabilityTuple{
			Carrier: kind, NetworkMode: mode, SessionRole: role, Path: path,
			ReliableStreams: true,
			Datagrams:       kind != carrier.KindWebSocket,
			Migration:       kind == carrier.KindRawQUIC && mode == NetworkDial,
		}
	}
	all := []CapabilityTuple{
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
	supported := make(map[carrier.Kind]struct{}, len(kinds))
	for _, kind := range kinds {
		supported[kind] = struct{}{}
	}
	descriptor := CapabilityDescriptor{Language: "go", Runtime: "native", SchemaVersion: 2}
	for _, tuple := range all {
		if _, ok := supported[tuple.Carrier]; ok {
			descriptor.Tuples = append(descriptor.Tuples, tuple)
		}
	}
	for _, kind := range []carrier.Kind{carrier.KindRawQUIC, carrier.KindWebSocket, carrier.KindWebTransport} {
		if _, ok := supported[kind]; !ok {
			descriptor.Unsupported = append(descriptor.Unsupported, UnsupportedCapability{
				Carrier: kind,
				Reason:  "adapter_not_composed",
			})
		}
	}
	return descriptor
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

func CapabilityDescriptorDigest(descriptor CapabilityDescriptor) ([32]byte, error) {
	canonical, err := EncodeCapabilityDescriptor(descriptor)
	if err != nil {
		return [32]byte{}, err
	}
	preimage := make([]byte, 0, len(capabilityDigestLabel)+4+len(canonical))
	preimage = append(preimage, capabilityDigestLabel...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	preimage = append(preimage, length[:]...)
	preimage = append(preimage, canonical...)
	return sha256.Sum256(preimage), nil
}

func validateCapabilityDescriptorShape(descriptor CapabilityDescriptor) error {
	if descriptor.SchemaVersion != 2 || !capabilityRegistryToken.MatchString(descriptor.Language) ||
		!capabilityRegistryToken.MatchString(descriptor.Runtime) ||
		len(descriptor.Tuples)+len(descriptor.Unsupported) == 0 {
		return ErrInvalidCapability
	}
	return nil
}

func validateUnsupportedCapabilities(descriptor CapabilityDescriptor, tuples map[CapabilityTuple]struct{}) error {
	supportedCarriers := make(map[carrier.Kind]struct{}, 3)
	for tuple := range tuples {
		supportedCarriers[tuple.Carrier] = struct{}{}
	}
	unsupportedCarriers := make(map[carrier.Kind]struct{}, len(descriptor.Unsupported))
	for index, unsupported := range descriptor.Unsupported {
		if err := unsupported.Carrier.Validate(); err != nil || !capabilityRegistryToken.MatchString(unsupported.Reason) {
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

func capabilityTupleLess(left, right CapabilityTuple) bool {
	return slices.Compare(
		[]string{string(left.Carrier), string(left.NetworkMode), string(left.SessionRole), string(left.Path), fmt.Sprint(left.ReliableStreams), fmt.Sprint(left.Datagrams), fmt.Sprint(left.Migration)},
		[]string{string(right.Carrier), string(right.NetworkMode), string(right.SessionRole), string(right.Path), fmt.Sprint(right.ReliableStreams), fmt.Sprint(right.Datagrams), fmt.Sprint(right.Migration)},
	) < 0
}
