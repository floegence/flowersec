package protocolv4

// MatchOriginal binds the authenticated hello to the complete original signed
// Session parameters, attempt, and candidate route. Detached public values do
// not introduce authority; this compares facts retained by the original bind.
func (h *HelloBinding) MatchOriginal(session ArtifactSessionParameters, attempt [16]byte, winner PoolMember) error {
	if h == nil || !session.Contract.Valid() || h.session != session || h.artifact != session.ArtifactDigest || h.profile != session.Profile || h.attempt != attempt || h.winner != winner {
		return CBORFailure("hello_artifact_binding")
	}
	return nil
}
