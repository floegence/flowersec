package protocolv4

import (
	"sync"
	"unsafe"
)

// ContractQueryTarget names one explicit trusted service method. Known means
// that the sender owns the complete original contract throughout this query;
// it is never established by these received digest bytes alone.
type ContractQueryTarget struct {
	Namespace           string
	Type                uint32
	Wanted, Known       [32]byte
	HasWanted, HasKnown bool
}

// ContractQueryTargets is a detached fixed-size request projection. It proves
// canonical byte structure and explicit target membership only, not caller
// authorization, a source identity, a known-body lease or admission rights.
type ContractQueryTargets struct {
	count   uint8
	targets [8]ContractQueryTarget
}

func (q ContractQueryTargets) Count() int { return int(q.count) }
func (q ContractQueryTargets) Target(index int) (ContractQueryTarget, error) {
	if index < 0 || index >= int(q.count) {
		return ContractQueryTarget{}, CBORFailure("query_target_index")
	}
	return q.targets[index], nil
}
func (q ContractQueryTargets) ResponseBytes() uint32 { return uint32(q.count) * 9216 }

// ContractQueryCodec holds only bounded SDK input/encoding scratch. Its owner
// must reserve the declared backing before construction and serialize actual
// use with original query ownership. It starts no task and runs no user codec.
type ContractQueryCodec struct {
	mu      sync.Mutex
	decoder *Decoder
	scratch [2048]byte
}

func ContractQueryCodecBackingBytes() (uint64, error) {
	cost, err := decoderBackingBytes(2048, 80, 128)
	return cost + uint64(unsafe.Sizeof(ContractQueryCodec{})) + uint64(unsafe.Sizeof(ContractQueryTargets{})) + 8*128, err
}
func NewContractQueryCodec() (*ContractQueryCodec, error) {
	d, err := newDecoder(2048, 80, 128)
	if err != nil {
		return nil, err
	}
	return &ContractQueryCodec{decoder: d}, nil
}
func (c *ContractQueryCodec) DecodeTargets(wire []byte) (ContractQueryTargets, error) {
	if c == nil {
		return ContractQueryTargets{}, CBORFailure("configuration_capacity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.decodeTargetsLocked(wire)
}
func (c *ContractQueryCodec) decodeTargetsLocked(wire []byte) (ContractQueryTargets, error) {
	doc, err := c.decoder.DecodeMap(wire, "ContractTargets", DecodeContext{})
	if err != nil {
		return ContractQueryTargets{}, err
	}
	defer doc.Release()
	array := doc.Root().Named("ContractTargets", "targets")
	if array.Len() < 1 || array.Len() > 8 {
		return ContractQueryTargets{}, CBORFailure("query_target_count")
	}
	out := ContractQueryTargets{count: uint8(array.Len())}
	for i := 0; i < array.Len(); i++ {
		item := array.Index(i)
		target := &out.targets[i]
		target.Namespace, _ = item.Named("ContractTarget", "service_namespace").Text()
		typ, _ := item.Named("ContractTarget", "method_type_id").Uint()
		target.Type = uint32(typ)
		if digest, ok := item.Named("ContractTarget", "wanted_contract_digest").ByteString(); ok {
			target.HasWanted = true
			copy(target.Wanted[:], digest)
		}
		if digest, ok := item.Named("ContractTarget", "known_contract_digest").ByteString(); ok {
			target.HasKnown = true
			copy(target.Known[:], digest)
		}
	}
	return out, nil
}

// CheckKnown requires actual still-owned immutable canonical bodies for every
// known selector. The original query owner must keep those exact bodies alive
// until completion; a successful check is not a replacement ownership token.
func (q ContractQueryTargets) CheckKnown(known []*ServiceContract) error {
	if q.count == 0 || len(known) != int(q.count) {
		return CBORFailure("query_known_count")
	}
	for i, contract := range known {
		target := q.targets[i]
		if !target.HasKnown {
			if contract != nil {
				return CBORFailure("query_unrequested_known")
			}
			continue
		}
		if contract == nil {
			return CBORFailure("query_contract_body")
		}
		policy, err := contract.Policy()
		if err != nil {
			return err
		}
		if policy.Namespace != target.Namespace || policy.Type != target.Type {
			return CBORFailure("query_target_mismatch")
		}
		if policy.Digest != target.Known {
			return CBORFailure("query_known_mismatch")
		}
		if target.HasWanted && policy.Digest != target.Wanted {
			return CBORFailure("query_wanted_mismatch")
		}
	}
	return nil
}

// EncodeTargets validates the local fixed target list and original known bodies
// before returning canonical bytes in caller-owned admitted storage. Digests
// and names are captured by value; fields/IDs use the same shared registry.
func (c *ContractQueryCodec) EncodeTargets(dst []byte, targets []ContractQueryTarget, known []*ServiceContract) (int, ContractQueryTargets, error) {
	if c == nil || len(targets) < 1 || len(targets) > 8 {
		return 0, ContractQueryTargets{}, CBORFailure("query_target_count")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(c.scratch[:])
	offset, err := cborHead(c.scratch[:], 4, uint64(len(targets)))
	if err != nil {
		return 0, ContractQueryTargets{}, err
	}
	for _, target := range targets {
		fields := [4]Field{{Name: "service_namespace", Kind: TextString, Text: target.Namespace}, {Name: "method_type_id", Number: uint64(target.Type)}}
		count := 2
		if target.HasWanted {
			fields[count] = Field{Name: "wanted_contract_digest", Kind: ByteString, Bytes: target.Wanted[:]}
			count++
		}
		if target.HasKnown {
			fields[count] = Field{Name: "known_contract_digest", Kind: ByteString, Bytes: target.Known[:]}
			count++
		}
		wire, err := EncodeMap(c.scratch[offset:], "ContractTarget", fields[:count])
		if err != nil {
			return 0, ContractQueryTargets{}, err
		}
		offset += len(wire)
	}
	wire, err := EncodeMap(dst, "ContractTargets", []Field{{Name: "targets", Kind: EncodedArray, Bytes: c.scratch[:offset]}})
	if err != nil {
		return 0, ContractQueryTargets{}, err
	}
	result, err := c.decodeTargetsLocked(wire)
	if err == nil {
		err = result.CheckKnown(known)
	}
	if err != nil {
		clear(wire)
		return 0, ContractQueryTargets{}, err
	}
	return len(wire), result, nil
}

// AdmissionOfferBounds is an exact contract-bound window. Parsing does not
// establish that trusted time is inside it, install an advertisement, reserve
// resources or authorize execution. Overlapping offers remain distinct.
type AdmissionOfferBounds struct {
	Digest                  [32]byte
	NotBeforeMS, NotAfterMS uint64
}

func AdmissionOfferCodecBackingBytes() (uint64, error) { return decoderBackingBytes(256, 7, 0) }
func NewAdmissionOfferDecoder() (*Decoder, error)      { return newDecoder(256, 7, 0) }
func (c *ServiceContract) CheckOffer(d *Decoder, wire []byte, maxWindowMS uint64) (AdmissionOfferBounds, error) {
	if d == nil || maxWindowMS == 0 {
		return AdmissionOfferBounds{}, CBORFailure("offer_window")
	}
	policy, err := c.Policy()
	if err != nil {
		return AdmissionOfferBounds{}, err
	}
	if policy.Semantics != 1 {
		return AdmissionOfferBounds{}, CBORFailure("offer_presence")
	}
	doc, err := d.DecodeMap(wire, "AdmissionOffer", DecodeContext{})
	if err != nil {
		return AdmissionOfferBounds{}, err
	}
	defer doc.Release()
	root := doc.Root()
	var offer AdmissionOfferBounds
	hash, _ := root.Named("AdmissionOffer", "service_contract_digest").ByteString()
	copy(offer.Digest[:], hash)
	offer.NotBeforeMS, _ = root.Named("AdmissionOffer", "not_before_ms").Uint()
	offer.NotAfterMS, _ = root.Named("AdmissionOffer", "not_after_ms").Uint()
	if offer.Digest != policy.Digest {
		return AdmissionOfferBounds{}, CBORFailure("offer_contract_mismatch")
	}
	if offer.NotBeforeMS >= offer.NotAfterMS || offer.NotAfterMS-offer.NotBeforeMS > maxWindowMS {
		return AdmissionOfferBounds{}, CBORFailure("offer_window")
	}
	return offer, nil
}
