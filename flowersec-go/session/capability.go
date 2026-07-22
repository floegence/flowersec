package session

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

	"github.com/floegence/flowersec/flowersec-go/carrier"
)

const capabilityDigestLabel = "flowersec-v2-runtime-capability\x00"

var capabilityRegistryToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,127}$`)

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
	for _, kind := range []carrier.Kind{carrier.KindQUIC, carrier.KindWebSocket, carrier.KindWebTransport} {
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
		[]string{string(left.Carrier), string(left.NetworkMode), string(left.SessionRole), string(left.Path)},
		[]string{string(right.Carrier), string(right.NetworkMode), string(right.SessionRole), string(right.Path)},
	) < 0
}
