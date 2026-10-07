//! One public parent selection shared by direct admission and both relay legs.
//! Local carrier bindings, admission authority IDs and Noise material belong
//! only to their original local owners and never change this shared fact.
use super::*;

pub(crate) struct ParentWinnerSelection<'a> {
    pub(crate) source: ActivationSource,
    pub(crate) tenant: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) server_authority: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) artifact: [u8; 32],
    pub(crate) activation: [u8; 32],
    pub(crate) proof: &'a [u8],
    pub(crate) candidate: [u8; 16],
    pub(crate) route: [u8; 32],
    pub(crate) attempt: [u8; 16],
    pub(crate) identities: [[u8; 32]; 2],
    pub(crate) parent_initiation_end: u64,
    pub(crate) parent_session_end: u64,
}
impl ParentWinnerSelection<'_> {
    pub(crate) fn encode(&self, maximum: usize) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(maximum)
            .map_err(|_| fail(PoolStoreFailure::Capacity))?;
        codec::encode_head(&mut output, 4, 15);
        text(
            &mut output,
            match self.source {
                ActivationSource::PreauthorizedPool => "flowersec/rust-parent-pool-selection/1",
                ActivationSource::LiveAuthority => "flowersec/rust-parent-live-selection/1",
            },
        );
        for value in [
            self.tenant,
            self.authority,
            self.server_authority,
            self.audience,
        ] {
            text(&mut output, value);
        }
        for value in [
            &self.artifact[..],
            &self.activation,
            self.proof,
            &self.candidate,
            &self.route,
            &self.attempt,
            &self.identities[0],
            &self.identities[1],
        ] {
            data(&mut output, value);
        }
        head(&mut output, self.parent_initiation_end);
        head(&mut output, self.parent_session_end);
        if output.len() > maximum {
            return Err(fail(PoolStoreFailure::Capacity));
        }
        Ok(output)
    }
}
