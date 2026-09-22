package protocolv4

import (
	"sync"
	"unsafe"
)

type snapshotWriteItem struct {
	metadata            [512]byte
	prefix, bytes, body int
	contract            *ServiceContract
}

// ContractSnapshotWriter owns only a finite cursor and canonical map envelopes.
// Original immutable bodies are borrowed from the query owner, which must keep
// them alive until Close or completed encoding. Next copies at most 4 KiB and
// exposes no source alias. No shared codec workspace is held across steps.
// Only complete encoding may be published as a fixed query response.
type ContractSnapshotWriter struct {
	mu                         sync.Mutex
	items                      [8]snapshotWriteItem
	outer                      [32]byte
	outerBytes, outerAt        int
	count, item, phase, offset int
	total, written             int
	closed, failed             bool
}

func ContractSnapshotWriterBackingBytes() uint64 {
	return uint64(unsafe.Sizeof(ContractSnapshotWriter{}))
}
func (c *ContractSnapshotEncoder) NewWriter(request ContractQueryTargets, choices []ContractSnapshotChoice) (*ContractSnapshotWriter, error) {
	if c == nil {
		return nil, CBORFailure("configuration_capacity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.newWriterLocked(request, choices)
}
func (c *ContractSnapshotEncoder) newWriterLocked(request ContractQueryTargets, choices []ContractSnapshotChoice) (*ContractSnapshotWriter, error) {
	if c.offer == nil {
		return nil, CBORFailure("configuration_capacity")
	}
	if request.Count() < 1 || request.Count() > 8 || len(choices) != request.Count() {
		return nil, CBORFailure("query_response_count")
	}
	var codes [8]uint64
	var policies [8]ServiceContractPolicy
	if err := c.validateChoices(request, choices, &codes, &policies); err != nil {
		return nil, err
	}
	w := &ContractSnapshotWriter{count: len(choices)}
	id, err := FieldID("ContractSnapshots", "items")
	if err != nil {
		return nil, err
	}
	for _, head := range [][2]uint64{{5, 1}, {0, id}, {4, uint64(len(choices))}} {
		n, e := cborHead(w.outer[w.outerBytes:], byte(head[0]), head[1])
		if e != nil {
			return nil, e
		}
		w.outerBytes += n
	}
	w.total = w.outerBytes
	for i, choice := range choices {
		fields := [4]Field{{Name: "target_index", Number: uint64(i)}, {Name: "status", Number: codes[i]}}
		count := 2
		item := &w.items[i]
		switch choice.Status {
		case "available_full":
			item.contract = choice.Contract
			item.body, err = choice.Contract.CanonicalSize()
			if err != nil {
				return nil, err
			}
			fields[count] = Field{Name: "contract", Kind: ByteString}
			count++
		case "available_unchanged":
			fields[count] = Field{Name: "contract_digest", Kind: ByteString, Bytes: policies[i].Digest[:]}
			count++
		}
		if len(choice.Offer) > 0 {
			fields[count] = Field{Name: "offer", Kind: ByteString, Bytes: choice.Offer}
			count++
		}
		if item.contract != nil {
			prefix, suffix, e := encodeMapByteStringEnvelope(item.metadata[:], "ContractSnapshot", fields[:count], "contract", item.body)
			if e != nil {
				return nil, e
			}
			item.prefix, item.bytes = len(prefix), len(prefix)+len(suffix)
		} else {
			bytes, e := EncodeMap(item.metadata[:], "ContractSnapshot", fields[:count])
			if e != nil {
				return nil, e
			}
			item.prefix, item.bytes = len(bytes), len(bytes)
		}
		w.total += item.bytes + item.body
	}
	if w.total > int(request.ResponseBytes()) {
		return nil, CBORFailure("query_response_size")
	}
	return w, nil
}
func (w *ContractSnapshotWriter) Size() int {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total
}

// Next fills only the caller's admitted destination, capped at 4096 bytes even
// if it is larger. Empty/non-final destinations and released source bodies fail
// without publishing a response. An errored writer cannot resume.
func (w *ContractSnapshotWriter) Next(dst []byte) (written int, done bool, err error) {
	if w == nil {
		return 0, false, CBORFailure("encoder_closed")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.failed {
		return 0, false, CBORFailure("encoder_closed")
	}
	if w.written == w.total {
		return 0, true, nil
	}
	if len(dst) == 0 {
		return 0, false, CBORFailure("encoder_capacity")
	}
	dst = dst[:min(len(dst), 4096)]
	defer func() {
		if err != nil {
			w.failed = true
			clear(dst[:written])
			written = 0
			return
		}
		w.written += written
		done = w.written == w.total
		if done {
			for i := range w.items {
				w.items[i].contract = nil
			}
		}
	}()
	for written < len(dst) {
		if w.outerAt < w.outerBytes {
			n := copy(dst[written:], w.outer[w.outerAt:w.outerBytes])
			w.outerAt += n
			written += n
			continue
		}
		if w.item == w.count {
			break
		}
		item := &w.items[w.item]
		switch w.phase {
		case 0:
			n := copy(dst[written:], item.metadata[w.offset:item.prefix])
			written += n
			w.offset += n
			if w.offset == item.prefix {
				w.phase = 1
				w.offset = 0
			}
		case 1:
			if w.offset == item.body {
				w.phase = 2
				w.offset = item.prefix
				continue
			}
			count := min(len(dst)-written, item.body-w.offset)
			n, e := item.contract.CopyCanonicalRange(dst[written:written+count], w.offset)
			if e != nil {
				return written, false, e
			}
			if n != count {
				return written, false, CBORFailure("encoder_capacity")
			}
			written += n
			w.offset += n
		case 2:
			n := copy(dst[written:], item.metadata[w.offset:item.bytes])
			written += n
			w.offset += n
			if w.offset == item.bytes {
				w.item++
				w.phase = 0
				w.offset = 0
			}
		}
	}
	return written, false, nil
}
func (w *ContractSnapshotWriter) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	clear(w.items[:])
	clear(w.outer[:])
}
