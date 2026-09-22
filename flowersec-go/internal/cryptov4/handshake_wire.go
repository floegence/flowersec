package cryptov4

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"sync"

	"github.com/floegence/flowersec/flowersec-go/v5/internal/protocolv4"
)

type cryptoDomainPart struct {
	Name, Encoding string
	Length         int
	Const          *uint64
	ConstRef       string `json:"const_ref"`
	Schema         string `json:"schema_ref"`
	Projection     string
	Enum           []uint64
}
type cryptoDomain struct {
	Name  string
	Label string                             `json:"label_bytes"`
	Input struct{ Parts []cryptoDomainPart } `json:"input_schema"`
	label []byte
}
type cryptoMapField struct {
	Name, Type string
	Length     int
	Bitmask    *uint64
	Enum       map[string]uint64
}
type cryptoMap struct{ Fields map[string]cryptoMapField }
type handshakeWireRegistry struct {
	domains   map[string]cryptoDomain
	maps      map[string]cryptoMap
	constants map[string]string
	bounds    map[string]int
}

var handshakeWire = sync.OnceValues(func() (*handshakeWireRegistry, error) {
	var domains []cryptoDomain
	r := &handshakeWireRegistry{domains: map[string]cryptoDomain{}, maps: map[string]cryptoMap{}, constants: map[string]string{}, bounds: map[string]int{}}
	if json.Unmarshal([]byte(protocolv4.DomainRegistryJSON), &domains) != nil || json.Unmarshal([]byte(protocolv4.ReadyRegistryJSON), &r.maps) != nil {
		return nil, ErrConfiguration
	}
	for _, d := range domains {
		var err error
		d.label, err = hex.DecodeString(d.Label)
		if err != nil {
			return nil, ErrConfiguration
		}
		r.domains[d.Name] = d
	}
	var syntax struct {
		Registries map[string]json.RawMessage `json:"field_registries"`
		Maps       map[string]struct {
			Maximum int `json:"max_encoded_bytes"`
		} `json:"frame_maps"`
	}
	if json.Unmarshal([]byte(protocolv4.CBORSyntaxRegistryJSON), &syntax) != nil {
		return nil, ErrConfiguration
	}
	for name, raw := range syntax.Registries {
		var value string
		if json.Unmarshal(raw, &value) == nil {
			r.constants[name] = value
		}
	}
	for name, definition := range syntax.Maps {
		r.bounds[name] = definition.Maximum
	}
	return r, nil
})

// Original map bytes have already passed the admission decoder. This function
// preserves them; it does not parse, normalize or reconstruct signed inputs.
func cryptoInput(name string, values map[string][]byte, numbers map[string]uint64) ([]byte, error) {
	r, err := handshakeWire()
	if err != nil {
		return nil, err
	}
	d, ok := r.domains[name]
	if !ok {
		return nil, ErrConfiguration
	}
	// Validate and measure the complete input before allocating. In particular,
	// rekey transcript inputs may hold two full frame views; append growth must
	// not create an unaccounted succession of payload-sized backing arrays.
	_, size, err := encodeCryptoInput(r, d, values, numbers, nil)
	if err != nil {
		return nil, err
	}
	out, written, err := encodeCryptoInput(r, d, values, numbers, make([]byte, 0, size))
	if err != nil || written != size {
		clear(out)
		return nil, ErrConfiguration
	}
	return out, nil
}

type cryptoInputWriter struct {
	output []byte // nil measures; a nonnil slice is a fixed-capacity destination.
	size   int
}

func (w *cryptoInputWriter) write(input []byte) error {
	if len(input) > math.MaxInt-w.size {
		return ErrConfiguration
	}
	if w.output != nil {
		if len(input) > cap(w.output)-len(w.output) {
			return ErrConfiguration
		}
		w.output = append(w.output, input...)
	}
	w.size += len(input)
	return nil
}

func (w *cryptoInputWriter) integer(n uint64, width int) error {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], n)
	return w.write(encoded[len(encoded)-width:])
}

// Both passes use the same schema checks and byte order. Inputs are original
// SDK-owned views and remain immutable through this synchronous operation.
func encodeCryptoInput(r *handshakeWireRegistry, d cryptoDomain, values map[string][]byte, numbers map[string]uint64, output []byte) ([]byte, int, error) {
	w := cryptoInputWriter{output: output}
	if err := w.write(d.label); err != nil {
		return nil, 0, err
	}
	for _, part := range d.Input.Parts {
		switch part.Encoding {
		case "raw", "lp-bytes", "lp-map", "lp-ascii":
			value, ok := values[part.Name]
			if part.ConstRef != "" {
				constant, exists := r.constants[part.ConstRef]
				ok = exists
				value = []byte(constant)
			}
			if !ok || part.Length > 0 && len(value) != part.Length || uint64(len(value)) > math.MaxUint32 {
				return nil, 0, ErrConfiguration
			}
			projectionOK := part.Projection == "full" || d.Name == "rekey_confirm_mac" && part.Projection == "without_mac"
			if part.Encoding == "lp-map" && (!projectionOK || len(value) == 0 || r.bounds[part.Schema] > 0 && len(value) > r.bounds[part.Schema]) {
				return nil, 0, ErrConfiguration
			}
			if part.Encoding == "lp-ascii" {
				for _, b := range value {
					if b >= 128 {
						return nil, 0, ErrConfiguration
					}
				}
			}
			if part.Encoding != "raw" {
				if err := w.integer(uint64(len(value)), 4); err != nil {
					return nil, 0, err
				}
			}
			if err := w.write(value); err != nil {
				return nil, 0, err
			}
		case "u8", "u32", "u64":
			n, ok := numbers[part.Name]
			if part.Const != nil {
				n, ok = *part.Const, true
			}
			if !ok || len(part.Enum) > 0 && !slices.Contains(part.Enum, n) {
				return nil, 0, ErrConfiguration
			}
			width := 8
			switch part.Encoding {
			case "u8":
				if n > math.MaxUint8 {
					return nil, 0, ErrConfiguration
				}
				width = 1
			case "u32":
				if n > math.MaxUint32 {
					return nil, 0, ErrConfiguration
				}
				width = 4
			}
			if err := w.integer(n, width); err != nil {
				return nil, 0, err
			}
		default:
			return nil, 0, ErrConfiguration
		}
	}
	return w.output, w.size, nil
}

func appendCBORHead(out []byte, major byte, n uint64) []byte {
	if n < 24 {
		return append(out, major<<5|byte(n))
	}
	switch {
	case n <= math.MaxUint8:
		return append(out, major<<5|24, byte(n))
	case n <= math.MaxUint16:
		out = append(out, major<<5|25)
		return binary.BigEndian.AppendUint16(out, uint16(n))
	case n <= math.MaxUint32:
		out = append(out, major<<5|26)
		return binary.BigEndian.AppendUint32(out, uint32(n))
	default:
		out = append(out, major<<5|27)
		return binary.BigEndian.AppendUint64(out, n)
	}
}
func mapFieldOrder(def cryptoMap) ([]uint64, error) {
	ids := make([]uint64, 0, len(def.Fields))
	for name := range def.Fields {
		id, err := strconv.ParseUint(name, 10, 16)
		if err != nil {
			return nil, ErrConfiguration
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}
func encodeReadyMap(name string, values map[string][]byte, numbers map[string]uint64) ([]byte, error) {
	r, err := handshakeWire()
	if err != nil {
		return nil, err
	}
	def, ok := r.maps[name]
	if !ok {
		return nil, ErrConfiguration
	}
	ids, err := mapFieldOrder(def)
	if err != nil {
		return nil, err
	}
	out := appendCBORHead(nil, 5, uint64(len(ids)))
	for _, id := range ids {
		f := def.Fields[strconv.FormatUint(id, 10)]
		out = appendCBORHead(out, 0, id)
		switch f.Type {
		case "bytes", "text":
			value, ok := values[f.Name]
			if !ok || f.Length > 0 && len(value) != f.Length {
				return nil, ErrConfiguration
			}
			if f.Type == "text" {
				if _, err := protocolv4.Profile(string(value)); err != nil {
					return nil, err
				}
				out = appendCBORHead(out, 3, uint64(len(value)))
			} else {
				out = appendCBORHead(out, 2, uint64(len(value)))
			}
			out = append(out, value...)
		case "uint8", "uint64":
			n, ok := numbers[f.Name]
			if !ok || f.Type == "uint8" && n > math.MaxUint8 || f.Bitmask != nil && n & ^*f.Bitmask != 0 {
				return nil, ErrConfiguration
			}
			if len(f.Enum) > 0 {
				found := false
				for _, v := range f.Enum {
					found = found || n == v
				}
				if !found {
					return nil, ErrConfiguration
				}
			}
			out = appendCBORHead(out, 0, n)
		default:
			return nil, ErrConfiguration
		}
	}
	return out, nil
}
func decodeReady(input []byte) (proof [64]byte, mac [32]byte, err error) {
	r, err := handshakeWire()
	if err != nil {
		return proof, mac, err
	}
	def := r.maps["READY"]
	ids, err := mapFieldOrder(def)
	if err != nil {
		return proof, mac, err
	}
	take := func(prefix []byte) bool {
		if !bytes.HasPrefix(input, prefix) {
			return false
		}
		input = input[len(prefix):]
		return true
	}
	if !take(appendCBORHead(nil, 5, uint64(len(ids)))) {
		return proof, mac, ErrHandshake
	}
	for _, id := range ids {
		f := def.Fields[strconv.FormatUint(id, 10)]
		prefix := appendCBORHead(nil, 0, id)
		prefix = appendCBORHead(prefix, 2, uint64(f.Length))
		if !take(prefix) || len(input) < f.Length {
			return proof, mac, ErrHandshake
		}
		switch f.Name {
		case "identity_proof":
			if f.Length != len(proof) {
				return proof, mac, ErrConfiguration
			}
			copy(proof[:], input[:f.Length])
		case "confirmation_mac":
			if f.Length != len(mac) {
				return proof, mac, ErrConfiguration
			}
			copy(mac[:], input[:f.Length])
		default:
			return proof, mac, ErrConfiguration
		}
		input = input[f.Length:]
	}
	if len(input) != 0 {
		return proof, mac, ErrHandshake
	}
	return proof, mac, nil
}
