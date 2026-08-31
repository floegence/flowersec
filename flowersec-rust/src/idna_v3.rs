//! Frozen Unicode 15.1 host normalization for Flowersec v3 artifacts and policies.

/// Unicode version used by the Flowersec v3 IDNA contract.
#[cfg(test)]
pub const UNICODE_VERSION: &str = crate::unicode151_generated::UNICODE_VERSION;

/// Stable failure returned when a host is not valid under the v3 IDNA contract.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdnaHostErrorV3 {
    /// The host failed Unicode 15.1 UTS #46 non-transitional processing.
    #[error("invalid Unicode 15.1 IDNA host")]
    InvalidHost,
}

/// Returns a lowercase A-label host using the frozen Flowersec v3 IDNA profile.
///
/// The repository-owned scalar table limits both U-label input and decoded
/// A-labels before the current IDNA implementation performs normalization,
/// Punycode, Bidi, ContextJ, hyphen, and DNS length checks.
#[cfg_attr(not(test), allow(dead_code))]
pub fn lookup_ascii(host: &str) -> Result<String, IdnaHostErrorV3> {
    if host.is_empty() || host.ends_with('.') {
        return Err(IdnaHostErrorV3::InvalidHost);
    }

    if !assigned(host) {
        return Err(IdnaHostErrorV3::InvalidHost);
    }
    let (decoded, decoded_result) = idna::domain_to_unicode(host);
    if decoded_result.is_err() || !assigned(&decoded) {
        return Err(IdnaHostErrorV3::InvalidHost);
    }

    let ascii = idna::domain_to_ascii_strict(host).map_err(|_| IdnaHostErrorV3::InvalidHost)?;
    if ascii.is_empty()
        || ascii.ends_with('.')
        || !ascii.is_ascii()
        || ascii.len() > 253
        || ascii
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(IdnaHostErrorV3::InvalidHost);
    }
    Ok(ascii.to_ascii_lowercase())
}

fn assigned(value: &str) -> bool {
    value
        .chars()
        .all(|scalar| crate::unicode151_generated::assigned(scalar as u32))
}
