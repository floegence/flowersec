package protocolv4

import (
	"sync"
	"unsafe"
)

// ContractSnapshotInfo is a detached validation result, not installation or
// authorization. Only available_full writes a canonical body to its caller's
// already admitted destination. available_unchanged uses the original known
// body which the query owner must retain; denied/unavailable carry neither.
type ContractSnapshotInfo struct {
	Status        string
	ContractBytes uint16
	Policy        ServiceContractPolicy
	HasOffer      bool
	Offer         AdmissionOfferBounds
}
type ContractSnapshotSet struct {
	count uint8
	items [8]ContractSnapshotInfo
}

func (s ContractSnapshotSet) Count() int { return int(s.count) }
func (s ContractSnapshotSet) Item(index int) (ContractSnapshotInfo, error) {
	if index < 0 || index >= int(s.count) {
		return ContractSnapshotInfo{}, CBORFailure("query_target_index")
	}
	return s.items[index], nil
}

// ContractSnapshotCodec owns one finite envelope and one reused full contract
// arena. The outer envelope is never exposed. No result/body is handed off
// before ALL nested bodies, exact original targets, selectors and Offers pass.
// Its separately reserved workspace can be shared by the fixed query service;
// an operation may not retain it while waiting for a callback or new resources.
type ContractSnapshotCodec struct {
	ContractSnapshotEncoder
	envelope *Decoder
	contract *ServiceContractCodec
}

// ContractSnapshotEncoder uses only the finite canonical output workspace.
// A server encoding retained registered bodies needs no response envelope or
// nested contract decode arena. The full client codec embeds this same encoder.
type ContractSnapshotEncoder struct {
	mu       sync.Mutex
	offer    *Decoder
	statuses [4]uint64
}

func ContractSnapshotEncoderBackingBytes() (uint64, error) {
	offer, err := AdmissionOfferCodecBackingBytes()
	return offer + uint64(unsafe.Sizeof(ContractSnapshotEncoder{})) + ContractSnapshotWriterBackingBytes(), err
}

func NewContractSnapshotEncoder() (*ContractSnapshotEncoder, error) {
	c := &ContractSnapshotEncoder{}
	if err := c.initialize(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *ContractSnapshotEncoder) initialize() (err error) {
	c.offer, err = NewAdmissionOfferDecoder()
	if err != nil {
		return err
	}
	for i, label := range [...]string{"available_full", "available_unchanged", "denied", "unavailable"} {
		c.statuses[i], err = EnumValue("ContractSnapshot", "status", label)
		if err != nil {
			return err
		}
	}
	return nil
}

func ContractSnapshotCodecBackingBytes() (uint64, error) {
	outer, err := decoderBackingBytes(73728, 100, 0)
	if err != nil {
		return 0, err
	}
	contract, err := ServiceContractBackingBytes(768)
	if err != nil {
		return 0, err
	}
	offer, err := AdmissionOfferCodecBackingBytes()
	return outer + contract + offer + uint64(unsafe.Sizeof(ContractSnapshotCodec{})) + uint64(unsafe.Sizeof(ContractSnapshotSet{})) + 8*128 + ContractSnapshotWriterBackingBytes(), err
}
func NewContractSnapshotCodec() (*ContractSnapshotCodec, error) {
	c := &ContractSnapshotCodec{}
	var err error
	c.envelope, err = newDecoder(73728, 100, 0)
	if err != nil {
		return nil, err
	}
	c.envelope.snapshotEnvelope = true
	c.contract, err = NewServiceContractCodec(768)
	if err != nil {
		return nil, err
	}
	if err = c.ContractSnapshotEncoder.initialize(); err != nil {
		return nil, err
	}
	return c, nil
}
func queryBuffersOverlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	x, y := uintptr(unsafe.Pointer(&a[0])), uintptr(unsafe.Pointer(&b[0]))
	if x <= y {
		return y-x < uintptr(len(a))
	}
	return x-y < uintptr(len(b))
}

func checkQueryOutputs(wire []byte, known []*ServiceContract, outputs [][]byte) error {
	for i, dst := range outputs {
		if queryBuffersOverlap(wire, dst) {
			return CBORFailure("query_output_alias")
		}
		for _, previous := range outputs[:i] {
			if queryBuffersOverlap(previous, dst) {
				return CBORFailure("query_output_alias")
			}
		}
		for _, contract := range known {
			if contract == nil {
				continue
			}
			contract.codec.mu.Lock()
			live := contract.codec.current == contract
			alias := live && queryBuffersOverlap(contract.document.Bytes(), dst)
			contract.codec.mu.Unlock()
			if !live {
				return CBORFailure("document_released")
			}
			if alias {
				return CBORFailure("query_output_alias")
			}
		}
	}
	return nil
}

// Decode validates against the original request and actual known-body owners.
// Destinations must be distinct caller-owned buffers; insufficient capacity is
// a local error with zero partial body publication. Reply bytes and known-body
// storage are not mutable destinations. Windows are trusted per-method policy
// bounds, not declarations extracted from the peer's Offer.
func (c *ContractSnapshotCodec) Decode(request ContractQueryTargets, wire []byte, known []*ServiceContract, windows []uint64, destinations [][]byte) (ContractSnapshotSet, error) {
	if c == nil || request.count == 0 {
		return ContractSnapshotSet{}, CBORFailure("configuration_capacity")
	}
	if len(wire) > int(request.ResponseBytes()) {
		return ContractSnapshotSet{}, CBORFailure("query_response_size")
	}
	count := request.Count()
	if len(windows) != count {
		return ContractSnapshotSet{}, CBORFailure("query_policy_count")
	}
	if len(destinations) != count {
		return ContractSnapshotSet{}, CBORFailure("query_output_count")
	}
	if err := request.CheckKnown(known); err != nil {
		return ContractSnapshotSet{}, err
	}
	if err := checkQueryOutputs(wire, known, destinations); err != nil {
		return ContractSnapshotSet{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	doc, err := c.envelope.DecodeMap(wire, "ContractSnapshots", DecodeContext{})
	if err != nil {
		return ContractSnapshotSet{}, err
	}
	defer doc.Release()
	items := doc.Root().Named("ContractSnapshots", "items")
	if items.Len() != count {
		return ContractSnapshotSet{}, CBORFailure("query_response_count")
	}
	result := ContractSnapshotSet{count: request.count}
	var bodies [8][]byte
	for i := 0; i < count; i++ {
		item := items.Index(i)
		status, _ := item.Named("ContractSnapshot", "status").Uint()
		info := &result.items[i]
		switch status {
		case c.statuses[0]:
			info.Status = "available_full"
			body, _ := item.Named("ContractSnapshot", "contract").ByteString()
			if len(body) > len(destinations[i]) {
				return ContractSnapshotSet{}, CBORFailure("encoder_capacity")
			}
			contract, err := c.contract.Decode(body)
			if err != nil {
				return ContractSnapshotSet{}, err
			}
			policy, err := contract.Policy()
			if err == nil {
				err = c.validateAvailable(request.targets[i], item, contract, policy, windows[i], info)
			}
			contract.Release()
			if err != nil {
				return ContractSnapshotSet{}, err
			}
			bodies[i] = body
			info.ContractBytes = uint16(len(body))
		case c.statuses[1]:
			info.Status = "available_unchanged"
			if !request.targets[i].HasKnown || known[i] == nil {
				return ContractSnapshotSet{}, CBORFailure("query_unchanged_without_known")
			}
			digest, _ := item.Named("ContractSnapshot", "contract_digest").ByteString()
			if len(digest) != 32 || [32]byte(digest) != request.targets[i].Known {
				return ContractSnapshotSet{}, CBORFailure("query_unchanged_mismatch")
			}
			policy, err := known[i].Policy()
			if err != nil {
				return ContractSnapshotSet{}, err
			}
			if err = c.validateAvailable(request.targets[i], item, known[i], policy, windows[i], info); err != nil {
				return ContractSnapshotSet{}, err
			}
		case c.statuses[2]:
			info.Status = "denied"
		case c.statuses[3]:
			info.Status = "unavailable"
		default:
			return ContractSnapshotSet{}, CBORFailure("enum_value")
		}
	}
	for i, body := range bodies[:count] {
		copy(destinations[i], body)
	}
	return result, nil
}
func (c *ContractSnapshotEncoder) validateAvailable(target ContractQueryTarget, item Value, contract *ServiceContract, policy ServiceContractPolicy, window uint64, info *ContractSnapshotInfo) error {
	if policy.Namespace != target.Namespace || policy.Type != target.Type {
		return CBORFailure("query_target_mismatch")
	}
	if target.HasWanted && target.Wanted != policy.Digest {
		return CBORFailure("query_wanted_mismatch")
	}
	offer, present := item.Named("ContractSnapshot", "offer").ByteString()
	if present != (policy.Semantics == 1) {
		return CBORFailure("query_offer_presence")
	}
	if present {
		bounds, err := contract.CheckOffer(c.offer, offer, window)
		if err != nil {
			return err
		}
		info.Offer, info.HasOffer = bounds, true
	}
	info.Policy = policy
	return nil
}

// ContractSnapshotChoice is selected by the original trusted registry after
// current per-target authorization. Codec validation cannot establish that
// authority. Contract is a real immutable body held through encoding; Offer
// bytes belong to its original bounded registered window, never a merged range.
type ContractSnapshotChoice struct {
	Status           string
	Contract         *ServiceContract
	Offer            []byte
	MaxOfferWindowMS uint64
}

// Encode writes the sole canonical response into its already admitted complete
// output. It checks the same exact target/selector/variant/Offer relations as
// Decode. The server does not claim to prove the peer owns a known body; an
// unchanged response requires exact equality with that original known selector.
func (c *ContractSnapshotEncoder) Encode(dst []byte, request ContractQueryTargets, choices []ContractSnapshotChoice) (written int, err error) {
	if c == nil || request.Count() < 1 || request.Count() > 8 || len(choices) != request.Count() {
		return 0, CBORFailure("query_response_count")
	}
	dst = dst[:min(len(dst), int(request.ResponseBytes()))]
	for _, choice := range choices {
		if queryBuffersOverlap(dst, choice.Offer) {
			return 0, CBORFailure("query_output_alias")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	writer, err := c.newWriterLocked(request, choices)
	if err != nil {
		return 0, err
	}
	defer writer.Close()
	defer func() {
		if err != nil {
			clear(dst)
			written = 0
		}
	}()
	if len(dst) < writer.Size() {
		return 0, CBORFailure("encoder_capacity")
	}
	for {
		n, done, e := writer.Next(dst[written:])
		if e != nil {
			return 0, e
		}
		written += n
		if done {
			return written, nil
		}
	}
}

func (c *ContractSnapshotEncoder) validateChoices(request ContractQueryTargets, choices []ContractSnapshotChoice, codes *[8]uint64, policies *[8]ServiceContractPolicy) error {
	for i, choice := range choices {
		index := -1
		for at, label := range [...]string{"available_full", "available_unchanged", "denied", "unavailable"} {
			if choice.Status == label {
				index = at
				break
			}
		}
		if index < 0 {
			return CBORFailure("enum_value")
		}
		codes[i] = c.statuses[index]
		if index >= 2 {
			if choice.Contract != nil || len(choice.Offer) != 0 {
				return CBORFailure("query_unavailable_body")
			}
			continue
		}
		if choice.Contract == nil {
			return CBORFailure("query_contract_body")
		}
		policy, e := choice.Contract.Policy()
		if e != nil {
			return e
		}
		target := request.targets[i]
		if policy.Namespace != target.Namespace || policy.Type != target.Type {
			return CBORFailure("query_target_mismatch")
		}
		if target.HasWanted && target.Wanted != policy.Digest {
			return CBORFailure("query_wanted_mismatch")
		}
		if index == 1 && (!target.HasKnown || target.Known != policy.Digest) {
			return CBORFailure("query_unchanged_mismatch")
		}
		if (len(choice.Offer) > 0) != (policy.Semantics == 1) {
			return CBORFailure("query_offer_presence")
		}
		if policy.Semantics == 1 {
			if _, e = choice.Contract.CheckOffer(c.offer, choice.Offer, choice.MaxOfferWindowMS); e != nil {
				return e
			}
		}
		policies[i] = policy
	}
	return nil
}
