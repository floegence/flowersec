package ledgerv4

import (
	"context"
	"math"

	"github.com/floegence/flowersec/flowersec-go/v6/internal/protocolv4"
)

// TopUpTerminalEvidence is the authenticated control result's original receipt
// owner. It must validate the complete server tombstone (including unknown vs
// known fields), current source permission and exact request/response binding.
// Local expiry, transport failure and a source call error cannot implement this
// evidence. The finite local check is repeated at the durable boundary; it does
// no I/O or application callbacks and remains held through the provider return.
type TopUpTerminalEvidence interface {
	CheckTopUpTerminal(SQLiteIdentity, protocolv4.TopUpRequestFacts, TopUpServerSnapshot) error
}

// ConfirmTerminal records authoritative history without changing the local
// installed frontier or parsing/acquiring material. Only a retired server
// sequence releases the local sequence; an unretired terminal keeps it occupied.
// A permanently fenced source stays unusable even after that sequence retires.
func (j *SQLiteTopUpJournal) ConfirmTerminal(ctx context.Context, request protocolv4.TopUpRequestFacts, terminal TopUpServerSnapshot, evidence TopUpTerminalEvidence) error {
	if evidence == nil || terminal.Request != request || !validTopUpTerminal(terminal) {
		return ErrConfiguration
	}
	if err := j.store.begin(ctx); err != nil {
		return err
	}
	defer j.store.end()
	var data [2048]byte
	n, err := encodeTopUpTerminal(data[:], terminal)
	if err != nil {
		return err
	}
	defer clear(data[:])
	guard := func() error {
		if err := j.check(); err != nil {
			return err
		}
		return evidence.CheckTopUpTerminal(j.store.identity, request, terminal)
	}
	return j.store.writeTransaction(ctx, guard, func() error {
		old, err := j.readRecovery()
		if err != nil {
			return err
		}
		if old.PermanentFenceGeneration != 0 || old.Request != request || old.BindingGeneration != j.config.BindingGeneration || terminal.BindingGeneration > old.BindingGeneration || old.State != TopUpJournalPending && old.State != TopUpJournalInstalled && old.State != TopUpJournalTerminal {
			return ErrConflict
		}
		if terminal.HighestArtifact < old.ArtifactFrontier || old.Response.Count > 0 && old.Response != terminal.Response {
			return ErrConflict
		}
		if old.State == TopUpJournalTerminal {
			prior := old.Terminal
			if terminal.RetiredSequence < prior.RetiredSequence || terminal.HighestArtifact != prior.HighestArtifact || terminal.RetiredArtifact < prior.RetiredArtifact || terminal.Response != prior.Response || prior.Permanent && !terminal.Permanent || terminal.Terminal != prior.Terminal && !terminal.Permanent {
				return ErrConflict
			}
		}
		return j.store.exec("UPDATE manifest SET state=4,terminal=?1,retired_sequence=?2,identity=x'',key_reference=x'' WHERE id=1", named(1, data[:n]), named(2, sqliteUint(terminal.RetiredSequence)))
	})
}
func validTopUpTerminal(s TopUpServerSnapshot) bool {
	r := s.Request
	if !validBusinessIdentifier(r.Tenant) || r.Source == ([16]byte{}) || r.Generation == 0 || r.DeadlineMS == 0 || r.DesiredCount < 1 || r.DesiredCount > 4 || r.MaxItemBytes < 1 || r.MaxItemBytes > 65536 || r.Digest == ([32]byte{}) {
		return false
	}
	if s.State != TopUpServerTerminal && s.State != TopUpServerRetired || s.Terminal == "" || r.Sequence() == 0 || r.Sequence() == math.MaxUint64 || s.NextSequence != r.Sequence()+1 || s.BindingGeneration < r.Generation || s.RetiredArtifact > s.HighestArtifact {
		return false
	}
	if _, ok := protocolv4.TopUpErrorProjection(s.Terminal, protocolv4.V4TopUpWriteActionTerminal); !ok {
		return false
	}
	if s.State == TopUpServerRetired {
		if s.RetiredSequence != r.Sequence() {
			return false
		}
	} else if s.RetiredSequence+1 != r.Sequence() || s.Permanent {
		return false
	}
	if s.Response.Count == 0 && s.Response != (protocolv4.TopUpResponseFacts{}) {
		return false
	}
	if s.Response.Count > 0 {
		f := s.Response
		if f.Count != r.DesiredCount || f.Count > 4 || f.Operation != r.Operation || f.Source != r.Source || f.Tenant != r.Tenant || f.Generation != r.Generation || f.Highest != s.HighestArtifact || f.Digest == ([32]byte{}) || f.Entries[f.Count-1].Sequence != f.Highest {
			return false
		}
		if !f.Gap && f.RetiredThrough != 0 || f.Gap && (f.RetiredThrough == math.MaxUint64 || f.Entries[0].Sequence != f.RetiredThrough+1) {
			return false
		}
		for _, unused := range f.Entries[f.Count:] {
			if unused != (protocolv4.TopUpEntryFacts{}) {
				return false
			}
		}
		for i, item := range f.Entries[:f.Count] {
			if item.Generation != r.Generation || item.Identity != r.Identity || item.Sequence == 0 || i > 0 && (f.Entries[i-1].Sequence == math.MaxUint64 || item.Sequence != f.Entries[i-1].Sequence+1) {
				return false
			}
		}
		if s.Terminal != protocolv4.V4TopUpErrorCodeSourceResetRequired {
			return false
		}
	}
	return true
}

// CheckTopUpTerminalFacts validates detached history for a control adapter.
// It grants no receipt authority; ConfirmTerminal still requires independently
// authenticated evidence and checks the client's exact original journal facts.
func CheckTopUpTerminalFacts(s TopUpServerSnapshot) error {
	if !validTopUpTerminal(s) {
		return ErrConfiguration
	}
	return nil
}
func encodeTopUpTerminal(dst []byte, s TopUpServerSnapshot) (int, error) {
	if !validTopUpTerminal(s) {
		return 0, ErrStorageFormat
	}
	w := admissionWriter{dst: dst}
	permanent := uint64(0)
	if s.Permanent {
		permanent = 1
	}
	for _, value := range []uint64{uint64(s.State), s.BindingGeneration, s.NextSequence, s.RetiredSequence, s.HighestArtifact, s.RetiredArtifact, permanent} {
		w.uint(value)
	}
	w.text(string(s.Terminal))
	var response [1024]byte
	n := 0
	var err error
	if s.Response.Count > 0 {
		n, err = encodeTopUpResponse(response[:], s.Response)
		if err != nil {
			return 0, err
		}
	}
	w.uint(uint64(n))
	w.bytes(response[:n])
	clear(response[:])
	return w.n, w.err
}
func decodeTopUpTerminal(wire []byte, request protocolv4.TopUpRequestFacts) (s TopUpServerSnapshot, err error) {
	r := topUpReader{data: wire}
	state := r.uint()
	if state > uint64(TopUpServerRetired) {
		return s, ErrStorageFormat
	}
	s.State = TopUpServerState(state)
	for _, value := range []*uint64{&s.BindingGeneration, &s.NextSequence, &s.RetiredSequence, &s.HighestArtifact, &s.RetiredArtifact} {
		*value = r.uint()
	}
	permanent := r.uint()
	if permanent > 1 {
		return s, ErrStorageFormat
	}
	s.Permanent = permanent == 1
	s.Terminal = protocolv4.V4TopUpErrorCode(r.text())
	s.Request = request
	n := r.uint()
	if n > 1024 {
		return s, ErrStorageFormat
	}
	if n > 0 {
		s.Response, err = decodeTopUpResponse(r.take(int(n)))
		if err != nil {
			return s, err
		}
	}
	if err = r.done(); err != nil {
		return s, err
	}
	if !validTopUpTerminal(s) {
		return s, ErrStorageFormat
	}
	return s, nil
}

// TopUpPermanentFenceReceipt deliberately contains no operation, response,
// artifact or expiry fields. A source-level fence can cover a local pending
// intent that never reached the server; missing server facts remain unknown.
type TopUpPermanentFenceReceipt struct {
	Tenant     string
	Source     [16]byte
	Generation uint64
}

type TopUpPermanentFenceEvidence interface {
	CheckTopUpPermanentFence(SQLiteIdentity, TopUpPermanentFenceReceipt) error
}

// ConfirmPermanentFence requires independent authority confirmation that this
// entire incarnation can never append again. It preserves installed/acked
// history, seals future Begin, and retires unresolved local IDs without
// inventing a server response, material frontier, or per-operation tombstone.
func (j *SQLiteTopUpJournal) ConfirmPermanentFence(ctx context.Context, receipt TopUpPermanentFenceReceipt, evidence TopUpPermanentFenceEvidence) error {
	if evidence == nil || receipt.Tenant != j.config.Tenant || receipt.Source != j.config.Source || receipt.Generation == 0 || receipt.Generation > j.config.BindingGeneration {
		return ErrConfiguration
	}
	if err := j.store.begin(ctx); err != nil {
		return err
	}
	defer j.store.end()
	guard := func() error {
		if err := j.check(); err != nil {
			return err
		}
		return evidence.CheckTopUpPermanentFence(j.store.identity, receipt)
	}
	return j.store.writeTransaction(ctx, guard, func() error {
		old, err := j.readRecovery()
		if err != nil {
			return err
		}
		if old.BindingGeneration != j.config.BindingGeneration || receipt.Generation < old.PermanentFenceGeneration || old.Request.Generation > receipt.Generation {
			return ErrFenced
		}
		state, retired := old.State, old.RetiredSequence
		if state == TopUpJournalPending || state == TopUpJournalInstalled || state == TopUpJournalTerminal {
			state = TopUpJournalTerminal
			retired = old.Request.Sequence()
		}
		return j.store.exec("UPDATE manifest SET state=?1,retired_sequence=?2,permanent_fence=?3,identity=x'',key_reference=x'' WHERE id=1", named(1, int64(state)), named(2, sqliteUint(retired)), named(3, sqliteUint(receipt.Generation)))
	})
}
