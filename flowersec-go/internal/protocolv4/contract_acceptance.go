package protocolv4

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
)

const (
	ContractExact uint8 = iota
	ContractBounded
)

type ContractRange struct {
	Field        string
	Lower, Upper uint64
}

// ContractAcceptance is immutable local policy. The closed four-field schema
// fits within the per-method 256-byte allowance and retains no contract body.
type ContractAcceptance struct {
	Mode   uint8
	Count  uint8
	Ranges [4]ContractRange
}

var ErrContractPolicyRejected = CBORFailure("contract_policy_rejected")

func BoundedContractAcceptance(ranges ...ContractRange) (ContractAcceptance, error) {
	if len(ranges) == 0 || len(ranges) > 4 {
		return ContractAcceptance{}, ErrContractPolicyRejected
	}
	p := ContractAcceptance{Mode: ContractBounded, Count: uint8(len(ranges))}
	copy(p.Ranges[:], ranges)
	return p, p.Validate()
}

func contractRangeField(name string) (uint64, uint64, uint64, bool) {
	switch name {
	case "history_retention_ms":
		return 14, 1, math.MaxUint64, true
	case "result_retention_ms":
		return 15, 1, math.MaxUint64, true
	case "min_response_limit_bytes":
		return 9, 0, 1 << 20, true
	case "max_response_bytes":
		return 10, 0, 1 << 20, true
	}
	return 0, 0, 0, false
}

func (p ContractAcceptance) Validate() error {
	if p.Mode > ContractBounded || p.Mode == ContractExact && p.Count != 0 || p.Mode == ContractBounded && (p.Count == 0 || p.Count > 4) {
		return ErrContractPolicyRejected
	}
	for j, interval := range p.Ranges {
		if j >= int(p.Count) {
			if interval != (ContractRange{}) {
				return ErrContractPolicyRejected
			}
			continue
		}
		_, min, max, ok := contractRangeField(interval.Field)
		if !ok || interval.Lower > interval.Upper || interval.Lower < min || interval.Upper > max {
			return ErrContractPolicyRejected
		}
		for k := 0; k < j; k++ {
			if p.Ranges[k].Field == interval.Field {
				return ErrContractPolicyRejected
			}
		}
	}
	return nil
}

// AcceptanceIdentity checks the actual canonical variant and produces a
// bounded comparison of every field the application did not authorize changing.
// It does not infer compatibility from a partial Policy or increasing numbers.
func (c *ServiceContract) AcceptanceIdentity(p ContractAcceptance) ([32]byte, error) {
	if err := p.Validate(); err != nil {
		return [32]byte{}, err
	}
	if c == nil || c.codec == nil {
		return [32]byte{}, CBORFailure("document_released")
	}
	c.codec.mu.Lock()
	defer c.codec.mu.Unlock()
	if c.codec.current != c {
		return [32]byte{}, CBORFailure("document_released")
	}
	if p.Mode == ContractExact {
		return c.digest, nil
	}
	root := c.document.Root()
	shape, _ := root.Field(2).Uint()
	var permitted [29]bool
	for _, interval := range p.Ranges[:p.Count] {
		id, _, _, _ := contractRangeField(interval.Field)
		n, present := root.Field(id).Uint()
		if !present || (id == 9 || id == 10) && shape == 2 || n < interval.Lower || n > interval.Upper {
			return [32]byte{}, ErrContractPolicyRejected
		}
		permitted[id] = true
	}
	h := sha256.New()
	var length [8]byte
	for id := uint64(0); id < 29; id++ {
		if permitted[id] {
			continue
		}
		encoded := root.Field(id).Encoded()
		binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(encoded)
	}
	var result [32]byte
	h.Sum(result[:0])
	return result, nil
}
