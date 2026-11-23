package protocolv4

import (
	"hash"
	"math"
	"sync"
	"unsafe"
)

// ContractSnapshotReader shares one private borrowed-input arena across the
// Session's completed outgoing responses. Waiting responses retain their
// original Q2 vectors. The protected root worker calls Step once per turn.
// Neither the wire nor destinations may change while a read owns them.
type ContractSnapshotReader struct {
	mu             sync.Mutex
	validator      ContractSnapshotEncoder
	envelope, body *Decoder
	contractCodec  ServiceContractCodec
	cursor         contractDecodeCursor
	current        *ContractSnapshotRead
}

type ContractSnapshotRead struct {
	reader          *ContractSnapshotReader
	request         ContractQueryTargets
	known           [8]*ServiceContract
	windows         [8]uint64
	outputs, bodies [8][]byte
	result          ContractSnapshotSet
	envelope, body  *Document
	hash            hash.Hash
	index, offset   int
	phase           uint8
	done, closed    bool
	failure         error
}

func ContractSnapshotReaderBackingBytes(hashRuntimeBytes uint64) (uint64, error) {
	if hashRuntimeBytes == 0 {
		return 0, CBORFailure("configuration_capacity")
	}
	// Input belongs to the original response vector. Both finite arenas and
	// the single reusable traversal plan remain charged to this shared reader.
	outer, err := decoderBackingBytes(73728, 100, 0)
	if err != nil {
		return 0, err
	}
	body, err := decoderBackingBytes(8192, 768, 128)
	if err != nil {
		return 0, err
	}
	offer, err := AdmissionOfferCodecBackingBytes()
	if err != nil {
		return 0, err
	}
	total := outer - 73728 + body - 8192 + offer + uint64(unsafe.Sizeof(ContractSnapshotReader{})) + uint64(unsafe.Sizeof(ContractSnapshotRead{})) + uint64(unsafe.Sizeof(ServiceContract{})) + 8*128
	if hashRuntimeBytes > math.MaxUint64-total {
		return 0, CBORFailure("configuration_capacity")
	}
	return total + hashRuntimeBytes, nil
}

func NewContractSnapshotReader() (*ContractSnapshotReader, error) {
	c := &ContractSnapshotReader{}
	var err error
	c.envelope, err = borrowedContractDecoder(73728, 100, 0)
	if err != nil {
		return nil, err
	}
	c.envelope.snapshotEnvelope = true
	c.body, err = borrowedContractDecoder(8192, 768, 128)
	if err != nil {
		return nil, err
	}
	c.contractCodec.decoder = c.body
	if err = c.validator.initialize(); err != nil {
		return nil, err
	}
	// Registry initialization is construction work, before any fixed-worker turn.
	if _, err = runtimeRules(); err != nil {
		return nil, err
	}
	if _, err = runtimeSignedMaps(); err != nil {
		return nil, err
	}
	return c, nil
}

// Begin borrows preadmitted output storage; nothing in it is publishable until
// Result succeeds. In particular a partially copied candidate is not a result.
func (c *ContractSnapshotReader) Begin(request ContractQueryTargets, wire []byte, known []*ServiceContract, windows []uint64, outputs [][]byte) (*ContractSnapshotRead, error) {
	if c == nil || request.Count() < 1 || request.Count() > 8 {
		return nil, CBORFailure("configuration_capacity")
	}
	if len(wire) > int(request.ResponseBytes()) {
		return nil, CBORFailure("query_response_size")
	}
	if len(windows) != request.Count() {
		return nil, CBORFailure("query_policy_count")
	}
	if len(outputs) != request.Count() {
		return nil, CBORFailure("query_output_count")
	}
	if err := request.CheckKnown(known); err != nil {
		return nil, err
	}
	if err := checkQueryOutputs(wire, known, outputs); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return nil, CBORFailure("decoder_busy")
	}
	if err := c.cursor.begin(c.envelope, wire, "ContractSnapshots"); err != nil {
		return nil, err
	}
	r := &ContractSnapshotRead{reader: c, request: request, result: ContractSnapshotSet{count: request.count}}
	copy(r.known[:], known)
	copy(r.windows[:], windows)
	copy(r.outputs[:], outputs)
	c.current = r
	return r, nil
}

// Step performs one bounded structure/rule action or at most 4096 bytes of
// hashing/copying. A complete validation pass precedes every output copy.
func (r *ContractSnapshotRead) Step() (bool, error) {
	if r == nil || r.reader == nil {
		return false, CBORFailure("document_released")
	}
	c := r.reader
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != r || r.closed {
		return false, CBORFailure("document_released")
	}
	if r.done {
		return true, r.failure
	}
	err := r.stepLocked()
	if err != nil {
		r.failure = err
		r.done = true
		r.releaseInputLocked()
	}
	return r.done, err
}

func (r *ContractSnapshotRead) stepLocked() error {
	c := r.reader
	switch r.phase {
	case 0:
		done, err := c.cursor.step()
		if err != nil {
			return err
		}
		if done {
			r.envelope = c.cursor.take()
			if r.envelope.Root().Named("ContractSnapshots", "items").Len() != r.request.Count() {
				return CBORFailure("query_response_count")
			}
			r.phase = 1
		}
	case 1:
		if r.index == r.request.Count() {
			r.index, r.offset, r.phase = 0, 0, 5
			return nil
		}
		item := r.envelope.Root().Named("ContractSnapshots", "items").Index(r.index)
		status, _ := item.Named("ContractSnapshot", "status").Uint()
		info := &r.result.items[r.index]
		switch status {
		case c.validator.statuses[0]:
			info.Status = "available_full"
			body, _ := item.Named("ContractSnapshot", "contract").ByteString()
			if len(body) > len(r.outputs[r.index]) {
				return CBORFailure("encoder_capacity")
			}
			r.bodies[r.index] = body
			info.ContractBytes = uint16(len(body))
			if err := c.cursor.begin(c.body, body, "ServiceContract"); err != nil {
				return err
			}
			r.phase = 2
		case c.validator.statuses[1]:
			info.Status = "available_unchanged"
			target, known := r.request.targets[r.index], r.known[r.index]
			if !target.HasKnown || known == nil {
				return CBORFailure("query_unchanged_without_known")
			}
			digest, _ := item.Named("ContractSnapshot", "contract_digest").ByteString()
			if len(digest) != 32 || [32]byte(digest) != target.Known {
				return CBORFailure("query_unchanged_mismatch")
			}
			if err := r.availableLocked(known); err != nil {
				return err
			}
			r.index++
		case c.validator.statuses[2]:
			info.Status = "denied"
			r.index++
		case c.validator.statuses[3]:
			info.Status = "unavailable"
			r.index++
		default:
			return CBORFailure("enum_value")
		}
	case 2:
		done, err := c.cursor.step()
		if err != nil {
			return err
		}
		if done {
			r.body = c.cursor.take()
			r.hash, err = newFullMapHash("service_contract_digest", "ServiceContract", len(r.bodies[r.index]))
			if err != nil {
				return err
			}
			r.offset, r.phase = 0, 3
		}
	case 3:
		body := r.bodies[r.index]
		end := min(r.offset+4096, len(body))
		_, _ = r.hash.Write(body[r.offset:end])
		r.offset = end
		if end == len(body) {
			r.phase = 4
		}
	case 4:
		contract := &ServiceContract{codec: &c.contractCodec, document: r.body}
		r.hash.Sum(contract.digest[:0])
		r.hash = nil
		c.contractCodec.current = contract
		err := r.availableLocked(contract)
		contract.Release()
		r.body = nil
		if err != nil {
			return err
		}
		r.index++
		r.phase = 1
	case 5:
		if r.index == r.request.Count() {
			r.done = true
			r.releaseInputLocked()
			return nil
		}
		body := r.bodies[r.index]
		end := min(r.offset+4096, len(body))
		copy(r.outputs[r.index][r.offset:end], body[r.offset:end])
		r.offset = end
		if end == len(body) {
			r.index++
			r.offset = 0
		}
	}
	return nil
}
func (r *ContractSnapshotRead) availableLocked(contract *ServiceContract) error {
	policy, err := contract.Policy()
	if err != nil {
		return err
	}
	item := r.envelope.Root().Named("ContractSnapshots", "items").Index(r.index)
	return r.reader.validator.validateAvailable(r.request.targets[r.index], item, contract, policy, r.windows[r.index], &r.result.items[r.index])
}
func (r *ContractSnapshotRead) releaseInputLocked() {
	r.reader.cursor.close()
	if r.body != nil {
		r.body.Release()
		r.body = nil
	}
	if r.envelope != nil {
		r.envelope.Release()
		r.envelope = nil
	}
	r.hash = nil
	r.known = [8]*ServiceContract{}
	r.bodies = [8][]byte{}
}
func (r *ContractSnapshotRead) Result() (ContractSnapshotSet, error) {
	if r == nil || r.reader == nil {
		return ContractSnapshotSet{}, CBORFailure("document_released")
	}
	c := r.reader
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != r || r.closed {
		return ContractSnapshotSet{}, CBORFailure("document_released")
	}
	if r.failure != nil {
		return ContractSnapshotSet{}, r.failure
	}
	if !r.done {
		return ContractSnapshotSet{}, CBORFailure("decoder_incomplete")
	}
	return r.result, nil
}
func (r *ContractSnapshotRead) Close() {
	if r == nil || r.reader == nil {
		return
	}
	c := r.reader
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != r {
		return
	}
	r.releaseInputLocked()
	r.outputs = [8][]byte{}
	r.result = ContractSnapshotSet{}
	r.closed = true
	c.current = nil
}
