//! Test-only UAX #15 implementation using the pinned data, not host Unicode.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Deserialize)]
struct Source {
    sha256: String,
}

#[derive(Deserialize)]
struct Tables {
    unicode_version: String,
    ccc: Vec<(u32, u8)>,
    decompositions: Vec<(u32, Vec<u32>)>,
    compositions: Vec<(u32, u32, u32)>,
    assigned: Vec<(u32, u32)>,
    sources: BTreeMap<String, Source>,
}

pub struct Nfc {
    classes: BTreeMap<u32, u8>,
    decomposition: BTreeMap<u32, Vec<u32>>,
    composition: BTreeMap<(u32, u32), u32>,
    assigned: Vec<(u32, u32)>,
    pub conformance_sha256: String,
}

impl Nfc {
    pub fn load(path: &str, expected_hash: &str) -> Self {
        assert_eq!(path, "testdata/unicode15_1/normalization_generated.json");
        let raw = include_bytes!("../../../testdata/unicode15_1/normalization_generated.json");
        let actual_hash: String = Sha256::digest(raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(actual_hash, expected_hash);
        let tables: Tables = serde_json::from_slice(raw).unwrap();
        assert_eq!(tables.unicode_version, "15.1.0");
        Self {
            classes: tables.ccc.into_iter().collect(),
            decomposition: tables.decompositions.into_iter().collect(),
            composition: tables
                .compositions
                .into_iter()
                .map(|(a, b, c)| ((a, b), c))
                .collect(),
            assigned: tables.assigned,
            conformance_sha256: tables.sources["NormalizationTest.txt"].sha256.clone(),
        }
    }

    pub fn assigned(&self, c: char) -> bool {
        let cp = u32::from(c);
        let index = self.assigned.partition_point(|&(_, end)| end < cp);
        self.assigned
            .get(index)
            .is_some_and(|&(start, _)| start <= cp)
    }

    fn class(&self, cp: u32) -> u8 {
        self.classes.get(&cp).copied().unwrap_or(0)
    }

    fn decompose(&self, cp: u32, output: &mut Vec<u32>) {
        // Algorithmic Hangul decomposition from UAX #15.
        if (0xac00..0xac00 + 11172).contains(&cp) {
            let index = cp - 0xac00;
            output.extend([0x1100 + index / 588, 0x1161 + index % 588 / 28]);
            if !index.is_multiple_of(28) {
                output.push(0x11a7 + index % 28);
            }
        } else if let Some(parts) = self.decomposition.get(&cp) {
            for &part in parts {
                self.decompose(part, output);
            }
        } else {
            output.push(cp);
        }
    }

    fn compose(&self, a: u32, b: u32) -> Option<u32> {
        if (0x1100..0x1100 + 19).contains(&a) && (0x1161..0x1161 + 21).contains(&b) {
            Some(0xac00 + ((a - 0x1100) * 21 + b - 0x1161) * 28)
        } else if (0xac00..0xac00 + 11172).contains(&a)
            && (a - 0xac00).is_multiple_of(28)
            && (0x11a8..0x11a7 + 28).contains(&b)
        {
            Some(a + b - 0x11a7)
        } else {
            self.composition.get(&(a, b)).copied()
        }
    }

    pub fn normalize(&self, text: &str) -> String {
        let mut scalars = Vec::new();
        for c in text.chars() {
            self.decompose(u32::from(c), &mut scalars);
        }
        // Stable sort only combining runs; equal-class blocking is preserved.
        let mut start = 0;
        while start < scalars.len() {
            if self.class(scalars[start]) == 0 {
                start += 1;
                continue;
            }
            let mut end = start + 1;
            while end < scalars.len() && self.class(scalars[end]) != 0 {
                end += 1;
            }
            scalars[start..end].sort_by_key(|&cp| self.class(cp));
            start = end;
        }
        let mut output = Vec::with_capacity(scalars.len());
        let mut starter = None;
        let mut previous_class = 0;
        for cp in scalars {
            let class = self.class(cp);
            if let Some(index) = starter
                && (previous_class == 0 || previous_class < class)
                && let Some(composed) = self.compose(output[index], cp)
            {
                output[index] = composed;
                continue;
            }
            if class == 0 {
                starter = Some(output.len());
            }
            output.push(cp);
            previous_class = class;
        }
        output
            .into_iter()
            .map(|cp| char::from_u32(cp).unwrap())
            .collect()
    }
}
