package protocolv4

// EncodeBarrier uses the generated entry schema. Entries hold immutable ticket
// frontiers; Epoch is an owner-side association and is not a second wire field.
func EncodeBarrier(dst []byte, entries []RecordHeader) ([]byte, error) {
	maximum, err := FieldItemLimit("REKEY_INIT", "client_barrier")
	if err != nil {
		return nil, err
	}
	if len(entries) > maximum {
		return nil, CBORFailure("array_limit")
	}
	offset, err := cborHead(dst, 4, uint64(len(entries)))
	if err != nil {
		return nil, err
	}
	for i, entry := range entries {
		if entry.Scope == 0 || entry.Scope >= uint64(1)<<63 || i > 0 && entry.Scope <= entries[i-1].Scope {
			return nil, CBORFailure("scope_order")
		}
		wire, err := EncodeMap(dst[offset:], "RekeyBarrierEntry", []Field{{Name: "scope_id", Number: entry.Scope}, {Name: "next_sequence", Number: entry.Sequence}})
		if err != nil {
			return nil, err
		}
		offset += len(wire)
	}
	return dst[:offset:offset], nil
}

// CopyBarrier transfers the actual authenticated phase's entries in one arena
// walk. It does not authenticate the phase MAC or admit the rekey transaction.
func (f *Frame) CopyBarrier(dst []RecordHeader) (int, error) {
	field := "client_barrier"
	if f.Schema == "REKEY_REPLY" {
		field = "server_barrier"
	} else if f.Schema != "REKEY_INIT" {
		return 0, CBORFailure("frame_variant")
	}
	v := f.Field(field)
	if !v.valid() {
		return 0, CBORFailure("missing_field")
	}
	d := f.Document.decoder
	node := d.nodes[v.index]
	if node.major != 4 || node.n > uint64(len(dst)) {
		return 0, CBORFailure("array_limit")
	}
	i := 0
	for child := node.first; child >= 0; child = d.nodes[child].next {
		entry := Value{f.Document, child}
		scope, ok := entry.Named("RekeyBarrierEntry", "scope_id").Uint()
		sequence, yes := entry.Named("RekeyBarrierEntry", "next_sequence").Uint()
		if !ok || !yes {
			return 0, CBORFailure("field_type")
		}
		dst[i] = RecordHeader{Epoch: f.Header.Epoch, Scope: scope, Sequence: sequence}
		i++
	}
	return i, nil
}
