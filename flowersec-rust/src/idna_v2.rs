//! Frozen Unicode 15.1 host normalization for Flowersec v2 artifacts and policies.

/// Unicode version used by the Flowersec v2 IDNA contract.
#[cfg(test)]
pub const UNICODE_VERSION: &str = "15.1.0";

/// Stable failure returned when a host is not valid under the v2 IDNA contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdnaHostErrorV2 {
    /// The host failed Unicode 15.1 UTS #46 non-transitional processing.
    #[error("invalid Unicode 15.1 IDNA host")]
    InvalidHost,
}

/// Returns a lowercase A-label host using the frozen Flowersec v2 IDNA profile.
///
/// The direct dependency pins `idna_mapping` 1.0.0, whose committed table is
/// Unicode 15.1 UTS #46. This rejects code points introduced after Unicode 15.1
/// even when the host runtime carries newer Unicode data. Strict processing
/// enables STD3, Bidi, ContextJ, hyphen, A-label round-trip, and DNS length checks.
pub fn lookup_ascii(host: &str) -> Result<String, IdnaHostErrorV2> {
    if host.is_empty() || host.ends_with('.') {
        return Err(IdnaHostErrorV2::InvalidHost);
    }

    let ascii = idna::domain_to_ascii_strict(host).map_err(|_| IdnaHostErrorV2::InvalidHost)?;
    if ascii.is_empty()
        || ascii.ends_with('.')
        || !ascii.is_ascii()
        || ascii.len() > 253
        || ascii
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(IdnaHostErrorV2::InvalidHost);
    }
    Ok(ascii.to_ascii_lowercase())
}
