use crate::generated::flowersec::{controlplane::v1 as controlplane, direct::v1 as direct};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationKv {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationContext {
    pub v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<CorrelationKv>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeMetadataEntry {
    pub scope: String,
    pub scope_version: u16,
    pub critical: bool,
    pub payload: Map<String, Value>,
}

#[derive(Clone, PartialEq)]
pub enum ConnectArtifact {
    Tunnel {
        grant: controlplane::ChannelInitGrant,
        scoped: Vec<ScopeMetadataEntry>,
        correlation: Option<CorrelationContext>,
    },
    Direct {
        info: direct::DirectConnectInfo,
        scoped: Vec<ScopeMetadataEntry>,
        correlation: Option<CorrelationContext>,
    },
}

impl std::fmt::Debug for ConnectArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tunnel {
                grant,
                scoped,
                correlation,
            } => formatter
                .debug_struct("Tunnel")
                .field("grant", grant)
                .field("scoped", scoped)
                .field("correlation", correlation)
                .finish(),
            Self::Direct {
                info,
                scoped,
                correlation,
            } => formatter
                .debug_struct("Direct")
                .field("info", info)
                .field("scoped", scoped)
                .field("correlation", correlation)
                .finish(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact JSON exceeds the 1 MiB limit")]
    TooLarge,
    #[error("artifact JSON is invalid: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("artifact validation failed: {0}")]
    Invalid(&'static str),
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "transport", deny_unknown_fields)]
enum ArtifactWire {
    #[serde(rename = "tunnel")]
    Tunnel {
        v: u32,
        tunnel_grant: controlplane::ChannelInitGrant,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scoped: Vec<ScopeMetadataEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        correlation: Option<CorrelationContext>,
    },
    #[serde(rename = "direct")]
    Direct {
        v: u32,
        direct_info: direct::DirectConnectInfo,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        scoped: Vec<ScopeMetadataEntry>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        correlation: Option<CorrelationContext>,
    },
}

impl ConnectArtifact {
    pub fn from_json(input: &[u8]) -> Result<Self, ArtifactError> {
        if input.len() > 1024 * 1024 {
            return Err(ArtifactError::TooLarge);
        }
        let wire: ArtifactWire = serde_json::from_slice(input)?;
        let mut artifact = match wire {
            ArtifactWire::Tunnel {
                v,
                tunnel_grant,
                scoped,
                correlation,
            } => {
                if v != 1 || tunnel_grant.role != controlplane::Role::Client {
                    return Err(ArtifactError::Invalid("invalid tunnel artifact"));
                }
                Self::Tunnel {
                    grant: tunnel_grant,
                    scoped,
                    correlation,
                }
            }
            ArtifactWire::Direct {
                v,
                direct_info,
                scoped,
                correlation,
            } => {
                if v != 1 {
                    return Err(ArtifactError::Invalid("invalid direct artifact"));
                }
                Self::Direct {
                    info: direct_info,
                    scoped,
                    correlation,
                }
            }
        };
        artifact.normalize_correlation();
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, ArtifactError> {
        let wire = match self {
            Self::Tunnel {
                grant,
                scoped,
                correlation,
            } => ArtifactWire::Tunnel {
                v: 1,
                tunnel_grant: grant.clone(),
                scoped: scoped.clone(),
                correlation: correlation.clone(),
            },
            Self::Direct {
                info,
                scoped,
                correlation,
            } => ArtifactWire::Direct {
                v: 1,
                direct_info: info.clone(),
                scoped: scoped.clone(),
                correlation: correlation.clone(),
            },
        };
        Ok(serde_json::to_vec(&wire)?)
    }

    pub fn correlation(&self) -> Option<&CorrelationContext> {
        match self {
            Self::Tunnel { correlation, .. } | Self::Direct { correlation, .. } => {
                correlation.as_ref()
            }
        }
    }

    pub fn scoped(&self) -> &[ScopeMetadataEntry] {
        match self {
            Self::Tunnel { scoped, .. } | Self::Direct { scoped, .. } => scoped,
        }
    }

    fn validate(&self) -> Result<(), ArtifactError> {
        validate_scopes(self.scoped())?;
        if let Some(correlation) = self.correlation() {
            validate_correlation(correlation)?;
        }
        Ok(())
    }

    fn normalize_correlation(&mut self) {
        let correlation = match self {
            Self::Tunnel { correlation, .. } | Self::Direct { correlation, .. } => correlation,
        };
        let Some(correlation) = correlation else {
            return;
        };
        correlation.trace_id = normalize_correlation_id(correlation.trace_id.take());
        correlation.session_id = normalize_correlation_id(correlation.session_id.take());
    }
}

fn validate_scopes(scopes: &[ScopeMetadataEntry]) -> Result<(), ArtifactError> {
    if scopes.len() > 8 {
        return Err(ArtifactError::Invalid("too many scopes"));
    }
    let mut seen = HashSet::with_capacity(scopes.len());
    for entry in scopes {
        if !valid_identifier(&entry.scope, 64) || entry.scope_version == 0 {
            return Err(ArtifactError::Invalid("invalid scope"));
        }
        if !seen.insert(&entry.scope) {
            return Err(ArtifactError::Invalid("duplicate scope"));
        }
        let value = Value::Object(entry.payload.clone());
        if serde_json::to_vec(&value)?.len() > 8192 || json_depth(&value) > 8 {
            return Err(ArtifactError::Invalid("invalid scope payload"));
        }
    }
    Ok(())
}

fn validate_correlation(correlation: &CorrelationContext) -> Result<(), ArtifactError> {
    if correlation.v != 1 || correlation.tags.len() > 8 {
        return Err(ArtifactError::Invalid("invalid correlation"));
    }
    let mut seen = HashSet::with_capacity(correlation.tags.len());
    for tag in &correlation.tags {
        if !valid_identifier(&tag.key, 32) || tag.value.len() > 128 || !seen.insert(&tag.key) {
            return Err(ArtifactError::Invalid("invalid correlation tag"));
        }
    }
    Ok(())
}

fn normalize_correlation_id(value: Option<String>) -> Option<String> {
    let value = value?.trim().to_owned();
    if (8..=128).contains(&value.len()) && value.bytes().all(is_correlation_byte) {
        Some(value)
    } else {
        None
    }
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && value.len() <= max_len
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn is_correlation_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
}

fn json_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or_default(),
        Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or_default(),
        _ => 0,
    }
}
