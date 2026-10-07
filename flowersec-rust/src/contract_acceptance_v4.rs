//! Finite local contract acceptance over the original canonical bodies. This
//! gate creates no binding, grants no authority and retains no third snapshot.

use crate::codec_v4::{self, Limits, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractRangeField {
    HistoryRetentionMs,
    ResultRetentionMs,
    MinResponseLimitBytes,
    MaxResponseBytes,
}
impl ContractRangeField {
    fn id(self) -> u64 {
        match self {
            Self::HistoryRetentionMs => 14,
            Self::ResultRetentionMs => 15,
            Self::MinResponseLimitBytes => 9,
            Self::MaxResponseBytes => 10,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContractRange {
    pub field: ContractRangeField,
    pub lower: u64,
    pub upper: u64,
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ContractAcceptance {
    ranges: [Option<ContractRange>; 4],
    count: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("contract_policy_rejected")]
pub struct ContractPolicyRejected;
type Result<T> = std::result::Result<T, ContractPolicyRejected>;

impl ContractAcceptance {
    pub fn exact() -> Self {
        Self::default()
    }
    pub(crate) fn locks_digest(self) -> bool {
        self.count == 0
    }
    pub fn bounded(ranges: &[ContractRange]) -> Result<Self> {
        if ranges.is_empty() || ranges.len() > 4 {
            return Err(ContractPolicyRejected);
        }
        let mut result = Self {
            count: ranges.len() as u8,
            ..Self::default()
        };
        for (j, range) in ranges.iter().enumerate() {
            let (min, max) = if range.field.id() >= 14 {
                (1, u64::MAX)
            } else {
                (0, 1 << 20)
            };
            if range.lower > range.upper
                || range.lower < min
                || range.upper > max
                || ranges[..j].iter().any(|old| old.field == range.field)
            {
                return Err(ContractPolicyRejected);
            }
            result.ranges[j] = Some(*range);
        }
        Ok(result)
    }
    /// Input is borrowed only for this bounded check. The Environment must have
    /// admitted its shared codec registry; no peer-sized parsing arena is built.
    /// Explicit exact approval may change policy but never the method shape.
    pub fn check(
        self,
        candidate: &[u8],
        current: Option<&[u8]>,
        explicit_update: bool,
    ) -> Result<()> {
        let parse = |wire| {
            codec_v4::decode(
                wire,
                "ServiceContract",
                Limits {
                    bytes: 8192,
                    nodes: 16384,
                },
                None,
            )
            .map_err(|_| ContractPolicyRejected)
        };
        let next = parse(candidate)?;
        let old = current.map(parse).transpose()?;
        let shape = next
            .u("ServiceContract", "call_shape")
            .map_err(|_| ContractPolicyRejected)?;
        for range in self.ranges[..usize::from(self.count)].iter().flatten() {
            let id = range.field.id();
            if matches!(id, 9 | 10) && shape == 2 {
                return Err(ContractPolicyRejected);
            }
            for contract in [Some(next), old].into_iter().flatten() {
                let n = field(contract, id)?
                    .ok_or(ContractPolicyRejected)?
                    .uint()
                    .map_err(|_| ContractPolicyRejected)?;
                if n < range.lower || n > range.upper {
                    return Err(ContractPolicyRejected);
                }
            }
        }
        let Some(old) = old else {
            return Ok(());
        };
        for id in 0..29 {
            if self.count == 0 && explicit_update && !matches!(id, 0..=7 | 20..=22 | 27) {
                continue;
            }
            if self
                .ranges
                .iter()
                .flatten()
                .any(|range| range.field.id() == id)
            {
                continue;
            }
            if field(old, id)?.map(Value::raw) != field(next, id)?.map(Value::raw) {
                return Err(ContractPolicyRejected);
            }
        }
        Ok(())
    }
}

fn field(value: Value<'_>, id: u64) -> Result<Option<Value<'_>>> {
    let mut children = value.children().map_err(|_| ContractPolicyRejected)?;
    while let Some(key) = children.next() {
        let key = key
            .and_then(Value::uint)
            .map_err(|_| ContractPolicyRejected)?;
        let value = children
            .next()
            .ok_or(ContractPolicyRejected)?
            .map_err(|_| ContractPolicyRejected)?;
        if key == id {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec_v4::tests::{encode_map, hex, t, u};

    fn seed(id: &str) -> Vec<u8> {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        hex(corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["id"] == id)
            .unwrap()["hex"]
            .as_str()
            .unwrap())
    }
    fn change(raw: &[u8], id: u64, replacement: Vec<u8>) -> Vec<u8> {
        let value = codec_v4::decode(
            raw,
            "ServiceContract",
            Limits {
                bytes: 8192,
                nodes: 16384,
            },
            None,
        )
        .unwrap();
        let mut children = value.children().unwrap();
        let mut fields = Vec::new();
        while let Some(key) = children.next() {
            let key = key.unwrap().uint().unwrap();
            let old = children.next().unwrap().unwrap();
            fields.push((
                key,
                if key == id {
                    replacement.clone()
                } else {
                    old.raw().to_vec()
                },
            ));
        }
        encode_map(&fields)
    }
    #[test]
    fn complete_contract_variants_and_fixed_response_bounds() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../../testdata/transport_v4/corpus.json")).unwrap();
        for vector in corpus["vectors"].as_array().unwrap() {
            if vector["schema"] == "ServiceContract" && vector["kind"] == "cbor_fields" {
                let raw = hex(vector["hex"].as_str().unwrap());
                assert_eq!(
                    ContractAcceptance::exact().check(&raw, None, false),
                    Ok(()),
                    "{}",
                    vector["id"]
                );
            }
        }
        let raw = seed("service_unary_fixed_empty");
        let policy = ContractAcceptance::bounded(&[
            ContractRange {
                field: ContractRangeField::MinResponseLimitBytes,
                lower: 0,
                upper: 1024,
            },
            ContractRange {
                field: ContractRangeField::MaxResponseBytes,
                lower: 0,
                upper: 1024,
            },
        ])
        .unwrap();
        assert!(
            policy
                .check(&change(&raw, 10, u(1)), Some(&raw), true)
                .is_err()
        );
        let equal = change(&change(&raw, 8, u(1)), 10, u(1));
        assert!(policy.check(&equal, Some(&raw), true).is_err());
    }
    #[test]
    fn canonical_contract_acceptance() {
        assert!(std::mem::size_of::<ContractAcceptance>() <= 256);
        let raw = seed("service_unary_execution");
        let policy = ContractAcceptance::bounded(&[ContractRange {
            field: ContractRangeField::HistoryRetentionMs,
            lower: 1,
            upper: u64::MAX,
        }])
        .unwrap();
        assert_eq!(
            policy.check(&change(&raw, 14, u(123456)), Some(&raw), true),
            Ok(())
        );
        for (id, value) in [(23, u(777)), (13, u(0)), (6, t("other"))] {
            assert_eq!(
                policy.check(&change(&raw, id, value), Some(&raw), true),
                Err(ContractPolicyRejected)
            );
        }
        assert_eq!(
            policy.check(&seed("service_unary_transient"), None, false),
            Err(ContractPolicyRejected)
        );
        assert!(ContractAcceptance::bounded(&[]).is_err());
        let duplicate = ContractRange {
            field: ContractRangeField::MaxResponseBytes,
            lower: 0,
            upper: 100,
        };
        assert!(ContractAcceptance::bounded(&[duplicate, duplicate]).is_err());
        assert!(
            ContractAcceptance::bounded(&[ContractRange {
                upper: 1048577,
                ..duplicate
            }])
            .is_err()
        );
        let changed = change(&raw, 14, u(123456));
        assert!(
            ContractAcceptance::exact()
                .check(&changed, Some(&raw), false)
                .is_err()
        );
        assert!(
            ContractAcceptance::exact()
                .check(&changed, Some(&raw), true)
                .is_ok()
        );
    }
}
