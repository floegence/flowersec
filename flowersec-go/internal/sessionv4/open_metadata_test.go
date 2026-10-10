package sessionv4

import (
	"bytes"
	"context"
	"testing"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

func TestOpenMetadataArenaPreservesFirstFitFragmentationAndExactCapacity(t *testing.T) {
	const capacity = 4*openMetadataPageBytes + 17
	m, err := newOpenMetadataArena(capacity)
	if err != nil {
		t.Fatal(err)
	}
	for _, page := range m.pages {
		if page != nil {
			t.Fatal("idle arena allocated a data page")
		}
	}
	var starts [4]int
	sizes := [4]int{256, 256, 256, 273}
	for i, size := range sizes {
		start, ok := m.reserve("k", bytes.Repeat([]byte{byte(i + 1)}, size-1))
		if !ok || start != i*256 {
			t.Fatal("first-fit allocation changed its absolute position", i, start, ok)
		}
		starts[i] = start
	}
	if _, ok := m.reserve("x", nil); ok {
		t.Fatal("full logical arena admitted another byte")
	}
	last := make([]byte, sizes[3])
	if n := m.copyRange(last, starts[3], capacity); n != len(last) || last[0] != 'k' || !bytes.Equal(last[1:], bytes.Repeat([]byte{4}, len(last)-1)) {
		t.Fatal("last partial page lost the exact arena end")
	}
	m.release(starts[0], sizes[0])
	m.release(starts[2], sizes[2])
	if _, ok := m.reserve("k", make([]byte, 256)); ok {
		t.Fatal("separate free ranges were compacted into one allocation")
	}
	if start, ok := m.reserve("r", make([]byte, 255)); !ok || start != 0 {
		t.Fatal("reused range was rounded to a different page", start, ok)
	}
	m.release(starts[1], sizes[1])
	if start, ok := m.reserve("r", make([]byte, 511)); !ok || start != 256 {
		t.Fatal("adjacent free bytes did not form their original contiguous range", start, ok)
	}
	if _, ok := m.reserve("x", nil); ok {
		t.Fatal("full restored arena exceeded its exact logical capacity")
	}
	pages := append([]*[openMetadataPageBytes]byte(nil), m.pages...)
	m.release(0, 256)
	m.release(256, 512)
	m.release(768, 273)
	for i, page := range pages {
		if m.pages[i] != nil || !bytes.Equal(page[:], make([]byte, len(page))) {
			t.Fatal("actual range exit retained data or an empty page", i)
		}
	}
	if start, ok := m.reserve("k", make([]byte, capacity-1)); !ok || start != 0 {
		t.Fatal("releasing all ranges reduced the original capacity", start, ok)
	}
	m.clear()
	for _, word := range m.used {
		if word != 0 {
			t.Fatal("cleared arena retained an occupied position")
		}
	}
}

func TestOpenMetadataArenaCopiesAcrossPagesWithoutReleasingNeighbours(t *testing.T) {
	m, err := newOpenMetadataArena(4224)
	if err != nil {
		t.Fatal(err)
	}
	prefix, ok := m.reserve("p", bytes.Repeat([]byte{0x55}, 254))
	if !ok || prefix != 0 {
		t.Fatal(prefix, ok)
	}
	const kind = "example/raw"
	metadata := bytes.Repeat([]byte{0xff, 0x00, 0x81}, 200)
	start, ok := m.reserve(kind, metadata)
	if !ok || start != 255 {
		t.Fatal("cross-page metadata was rounded or refused", start, ok)
	}
	size := len(kind) + len(metadata)
	snapshot := make([]byte, size)
	if n := m.copyRange(snapshot, start, start+size); n != size || string(snapshot[:len(kind)]) != kind || !bytes.Equal(snapshot[len(kind):], metadata) {
		t.Fatal("opaque original OPEN fields changed across page boundaries")
	}
	if !m.equals(start, start+len(kind), kind) || m.equals(start, start+len(kind), "example/RAW") || m.equals(start, start+len(kind), "example/rawx") {
		t.Fatal("kind selection ignored original bytes or their exact length")
	}
	short := make([]byte, 17)
	if n := m.copyRange(short, start+len(kind), start+size); n != len(short) || !bytes.Equal(short, metadata[:len(short)]) {
		t.Fatal("bounded metadata copy crossed its destination capacity")
	}
	shared := m.pages[0]
	m.release(prefix, 255)
	if m.pages[0] != shared || shared[255] != kind[0] || !bytes.Equal(shared[:255], make([]byte, 255)) {
		t.Fatal("one range exit released or retained its neighbour's shared page")
	}
	clear(metadata)
	if !bytes.Equal(snapshot[len(kind):], bytes.Repeat([]byte{0xff, 0x00, 0x81}, 200)) {
		t.Fatal("arena copy borrowed the original input")
	}
	m.release(start, size)
	for _, page := range m.pages {
		if page != nil {
			t.Fatal("last range exit retained an empty page")
		}
	}
	if !bytes.Equal(shared[:], make([]byte, len(shared))) {
		t.Fatal("retired shared page retained its original bytes")
	}
	if string(snapshot[:len(kind)]) != kind {
		t.Fatal("range exit cleared the caller's independent snapshot")
	}
}

func TestOpenMetadataPagedHoldPreparationAndOutcomeTransfer(t *testing.T) {
	client := newOpenEndpoint(t, protocolv4.ClientToServer, 2, 2, 1)
	server := newOpenEndpoint(t, protocolv4.ServerToClient, 2, 2, 1)
	const kind = "example/raw"
	hold := func(metadata []byte) OpenHandle {
		provider := new(bytes.Buffer)
		_, result, err := client.admission.OpenLocal(context.Background(), BusinessStream, kind, metadata, &CarrierAssociation{}, client.reservation(provider, 8), streamTestDeadline(t, client.engine))
		if err != nil || !result.Submitted || !result.Complete {
			t.Fatal("public OPEN failed before the original metadata holder", result, err)
		}
		record, err := server.receiver.ReceiveOpen(context.Background(), provider.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		peer, err := server.admission.Hold(record, &CarrierAssociation{}, streamTestDeadline(t, server.engine))
		record.Release()
		if err != nil {
			t.Fatal(err)
		}
		return peer
	}
	first := hold(bytes.Repeat([]byte{0x55}, 255-len(kind)))
	original := bytes.Repeat([]byte{0xff, 0x00, 0x81}, 200)
	second := hold(original)
	p, err := server.admission.PreparePeerOpen(second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Release)
	kindCopy, metadataCopy, limit, err := p.CopyRequest(make([]byte, len(kind)+len(original)))
	if err != nil || string(kindCopy) != kind || !bytes.Equal(metadataCopy, original) || limit != 8 {
		t.Fatal("public preparation changed original cross-page OPEN bytes", err)
	}
	a := server.admission
	a.mu.Lock()
	s, err := a.slot(second)
	if err != nil || s.metadataStart != 255 {
		a.mu.Unlock()
		t.Fatal("pending OPEN changed the original first-fit byte position", err)
	}
	target := s.preparationTarget - 1
	shared := a.metadata.pages[0]
	a.mu.Unlock()
	if _, err := a.Decide(context.Background(), second, BusinessStream, "metadata_invalid", StreamReservation{}, server.maintenance); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	s, err = a.slot(second)
	retained := err == nil && a.find(second.scope) == target && s.preparationActive && s.metadataSize == len(kind)+len(original) && a.metadata.equals(s.metadataStart, s.metadataStart+s.kindSize, kind)
	a.mu.Unlock()
	if !retained || string(kindCopy) != kind || !bytes.Equal(metadataCopy, original) {
		t.Fatal("outcome transfer released the original preparation's pages or snapshot")
	}
	p.Release()
	a.mu.Lock()
	sharedRetained := a.metadata.pages[0] == shared && a.metadata.equals(0, len(kind), kind) && shared[255] == 0
	for _, page := range a.metadata.pages[1:] {
		sharedRetained = sharedRetained && page == nil
	}
	a.mu.Unlock()
	if !sharedRetained || !bytes.Equal(kindCopy, make([]byte, len(kindCopy))) || !bytes.Equal(metadataCopy, make([]byte, len(metadataCopy))) {
		t.Fatal("actual preparation exit retained its range or reclaimed the other pending OPEN")
	}
	storage := make([]byte, 255)
	firstKind, firstMetadata, _, err := a.CopyRequest(first, storage)
	if err != nil || string(firstKind) != kind || !bytes.Equal(firstMetadata, bytes.Repeat([]byte{0x55}, 255-len(kind))) {
		t.Fatal("shared-page release changed the neighbouring public OPEN", err)
	}
	a.Close()
	for _, page := range a.metadata.pages {
		if page != nil {
			t.Fatal("Close retained pages without an actual preparation tail")
		}
	}
	if !bytes.Equal(shared[:], make([]byte, len(shared))) {
		t.Fatal("Close dropped a page before clearing the original metadata")
	}
}
