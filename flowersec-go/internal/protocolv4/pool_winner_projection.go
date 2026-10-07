package protocolv4

import "unicode/utf8"

// EncodePoolWinnerControlProjection writes the registered control protocol's
// canonical public selection, shared with the TypeScript authority. Local
// ledger records keep their own encoding. This projection grants no admission,
// signing or replay capability; only the original continuation may match it.
func EncodePoolWinnerControlProjection(dst []byte, f AdmissionFields) (int, error) {
	if f.Source != "preauthorized_pool" || f.CandidateSet == ([32]byte{}) || f.IssuedAt >= f.ActivationEnd || f.IssuedAt >= f.SessionEnd {
		return 0, CBORFailure("credential_binding")
	}
	for _, value := range []string{f.Tenant, f.WinnerAuthority, f.Audience} {
		if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
			return 0, CBORFailure("credential_binding")
		}
	}
	sink := mapEncodingSink{dst: dst}
	if err := sink.head(4, 18); err != nil {
		return 0, err
	}
	for _, value := range []string{"flowersec/parent-winner/1", f.Source, f.Tenant, f.WinnerAuthority, f.Audience} {
		if err := sink.field(&Field{Kind: TextString, Text: value}); err != nil {
			return 0, err
		}
	}
	for _, value := range [][]byte{f.Issuer[:], f.Lease[:], f.Artifact[:], f.Proof[:], f.CandidateSet[:], f.Candidate[:], f.Route[:], f.Attempt[:], f.ClientIdentity[:], f.ServerIdentity[:]} {
		if err := sink.field(&Field{Kind: ByteString, Bytes: value}); err != nil {
			return 0, err
		}
	}
	for _, value := range []uint64{f.IssuedAt, f.ActivationEnd, f.SessionEnd} {
		if err := sink.head(0, value); err != nil {
			return 0, err
		}
	}
	return sink.offset, nil
}
