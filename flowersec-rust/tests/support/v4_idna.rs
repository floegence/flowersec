//! Test-only Unicode 15.1 UTS46/IDNA2008 reference. No host mapping tables.
use super::unicode::Nfc;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub type Error = &'static str;

struct Property {
    first: u32,
    last: u32,
    kind: String,
    mapped: Vec<char>,
}

pub struct Idna {
    nfc: Nfc,
    tables: BTreeMap<String, Vec<Property>>,
    pub conformance_sha256: String,
}

pub fn hash(raw: &[u8]) -> String {
    Sha256::digest(raw)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl Idna {
    pub fn new(registry: &str) -> Self {
        let registry: Json = serde_json::from_str(registry).unwrap();
        let unicode = &registry["unicode"];
        assert_eq!(
            unicode["idna_data"]["path"],
            "testdata/unicode15_1/idna_generated.json"
        );
        let raw = include_bytes!("../../../testdata/unicode15_1/idna_generated.json");
        assert_eq!(hash(raw), unicode["idna_data"]["sha256"]);
        let data: Json = serde_json::from_slice(raw).unwrap();
        assert_eq!(data["unicode_version"], "15.1.0");
        assert_eq!(data["uts46_revision"], 31);
        assert_eq!(data["nfc_data_sha256"], unicode["nfc_data"]["sha256"]);
        let nfc = Nfc::load(
            unicode["nfc_data"]["path"].as_str().unwrap(),
            unicode["nfc_data"]["sha256"].as_str().unwrap(),
        );
        let mut tables = BTreeMap::new();
        for name in [
            "mapping",
            "classes",
            "categories",
            "bidi",
            "ccc",
            "joining",
            "scripts",
        ] {
            let rows: Vec<Property> = data[name]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    let row = row.as_array().unwrap();
                    assert!((3..=4).contains(&row.len()));
                    Property {
                        first: u32::try_from(row[0].as_u64().unwrap()).unwrap(),
                        last: u32::try_from(row[1].as_u64().unwrap()).unwrap(),
                        kind: row[2]
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| row[2].as_u64().unwrap().to_string()),
                        mapped: row
                            .get(3)
                            .map(|r| {
                                r.as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|cp| {
                                        char::from_u32(u32::try_from(cp.as_u64().unwrap()).unwrap())
                                            .unwrap()
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                    }
                })
                .collect();
            for (index, row) in rows.iter().enumerate() {
                assert!(row.first <= row.last);
                assert!(index == 0 || rows[index - 1].last < row.first);
            }
            tables.insert(name.into(), rows);
        }
        Self {
            nfc,
            tables,
            conformance_sha256: data["sources"]["IdnaTestV2.txt"]["sha256"]
                .as_str()
                .unwrap()
                .into(),
        }
    }

    fn lookup(&self, table: &str, cp: char) -> Option<&Property> {
        let cp = u32::from(cp);
        let rows = &self.tables[table];
        let index = rows.partition_point(|r| r.last < cp);
        rows.get(index).filter(|r| r.first <= cp)
    }

    fn prop(&self, table: &str, cp: char) -> &str {
        self.lookup(table, cp)
            .map(|r| r.kind.as_str())
            .unwrap_or("")
    }

    fn context_j(&self, label: &[char], index: usize) -> bool {
        if index > 0 && self.prop("ccc", label[index - 1]) == "9" {
            return true;
        }
        if label[index] == '\u{200d}' {
            return false;
        }
        let left = label[..index]
            .iter()
            .rev()
            .find(|&&c| self.prop("joining", c) != "T");
        let right = label[index + 1..]
            .iter()
            .find(|&&c| self.prop("joining", c) != "T");
        left.is_some_and(|&c| matches!(self.prop("joining", c), "L" | "D"))
            && right.is_some_and(|&c| matches!(self.prop("joining", c), "R" | "D"))
    }

    fn context_o(&self, label: &[char], index: usize) -> bool {
        match label[index] {
            '\u{b7}' => index > 0 && label[index - 1] == 'l' && label.get(index + 1) == Some(&'l'),
            '\u{375}' => label
                .get(index + 1)
                .is_some_and(|&c| self.prop("scripts", c) == "Greek"),
            '\u{5f3}' | '\u{5f4}' => {
                index > 0 && self.prop("scripts", label[index - 1]) == "Hebrew"
            }
            '\u{30fb}' => label
                .iter()
                .any(|&c| matches!(self.prop("scripts", c), "Hiragana" | "Katakana" | "Han")),
            '\u{660}'..='\u{669}' => !label.iter().any(|c| ('\u{6f0}'..='\u{6f9}').contains(c)),
            '\u{6f0}'..='\u{6f9}' => !label.iter().any(|c| ('\u{660}'..='\u{669}').contains(c)),
            _ => false,
        }
    }

    fn bidi(&self, label: &[char]) -> Result<(), Error> {
        let first = self.prop("bidi", *label.first().ok_or("idna_empty_label")?);
        let rtl = matches!(first, "R" | "AL");
        if !rtl && first != "L" {
            return Err("idna_bidi_start");
        }
        let mut last = "";
        let (mut arabic, mut european) = (false, false);
        for &cp in label {
            let direction = self.prop("bidi", cp);
            let common = matches!(direction, "EN" | "ES" | "CS" | "ET" | "ON" | "BN" | "NSM");
            if !common
                && !(if rtl {
                    matches!(direction, "R" | "AL" | "AN")
                } else {
                    direction == "L"
                })
            {
                return Err("idna_bidi_character");
            }
            if direction != "NSM" {
                last = direction;
            }
            arabic |= direction == "AN";
            european |= direction == "EN";
        }
        if !(if rtl {
            matches!(last, "R" | "AL" | "EN" | "AN")
        } else {
            matches!(last, "L" | "EN")
        }) {
            return Err("idna_bidi_end");
        }
        if rtl && arabic && european {
            return Err("idna_bidi_digits");
        }
        Ok(())
    }

    fn valid_uts_label(&self, label: &[char]) -> Result<(), Error> {
        if label.is_empty() {
            return Err("idna_empty_label");
        }
        let text: String = label.iter().collect();
        if self.nfc.normalize(&text) != text {
            return Err("idna_nfc");
        }
        if label[0] == '-'
            || label[label.len() - 1] == '-'
            || label.len() >= 4 && label[2..4] == ['-', '-']
        {
            return Err("idna_hyphen");
        }
        if self.prop("categories", label[0]).starts_with('M') {
            return Err("idna_initial_mark");
        }
        for (index, &cp) in label.iter().enumerate() {
            if !matches!(self.prop("mapping", cp), "valid" | "deviation") {
                return Err("idna_validity");
            }
            if matches!(cp, '\u{200c}' | '\u{200d}') && !self.context_j(label, index) {
                return Err("idna_contextj");
            }
        }
        Ok(())
    }

    pub fn process(&self, input: &str) -> Result<(String, Vec<Vec<char>>, bool), Error> {
        let mut mapped = String::new();
        for cp in input.chars() {
            match self.lookup("mapping", cp) {
                Some(row) if row.kind == "mapped" => mapped.extend(&row.mapped),
                Some(row) if row.kind == "ignored" => {}
                // UTS46 r31 checks validity after NFC composition.
                Some(row)
                    if matches!(
                        row.kind.as_str(),
                        "valid"
                            | "deviation"
                            | "disallowed"
                            | "disallowed_STD3_valid"
                            | "disallowed_STD3_mapped"
                    ) =>
                {
                    mapped.push(cp)
                }
                None => mapped.push(cp),
                _ => return Err("idna_mapping"),
            }
        }
        let normalized = self.nfc.normalize(&mapped);
        let mut names: Vec<&str> = normalized.split('.').collect();
        let trailing = names.last() == Some(&"");
        if trailing {
            names.pop();
        }
        if names.is_empty() {
            return Err("idna_empty_domain");
        }
        let mut labels = Vec::new();
        let mut bidi_domain = false;
        for name in names {
            let label: Vec<char> = if let Some(payload) = name.strip_prefix("xn--") {
                if name.len() > 63 {
                    return Err("idna_label_length");
                }
                let label = puny_decode(payload)?;
                if label.iter().all(|c| c.is_ascii()) {
                    return Err("idna_fake_alabel");
                }
                if puny_encode(&label)? != payload {
                    return Err("idna_alabel_roundtrip");
                }
                label
            } else {
                name.chars().collect()
            };
            self.valid_uts_label(&label)?;
            bidi_domain |= label
                .iter()
                .any(|&c| matches!(self.prop("bidi", c), "R" | "AL" | "AN"));
            labels.push(label);
        }
        let mut ascii = Vec::new();
        for label in &labels {
            if bidi_domain {
                self.bidi(label)?;
            }
            let text: String = if label.iter().any(|c| !c.is_ascii()) {
                format!("xn--{}", puny_encode(label)?)
            } else {
                label.iter().collect()
            };
            if text.is_empty() || text.len() > 63 {
                return Err("idna_label_length");
            }
            ascii.push(text);
        }
        let mut result = ascii.join(".");
        if result.len() > 253 {
            return Err("idna_domain_length");
        }
        if trailing {
            result.push('.');
        }
        Ok((result, labels, trailing))
    }

    pub fn issuer_dns(&self, input: &str) -> Result<String, Error> {
        if input.chars().any(|cp| !self.nfc.assigned(cp)) {
            return Err("idna_unassigned");
        }
        let (ascii, labels, trailing) = self.process(input)?;
        if trailing {
            return Err("idna_trailing_dot");
        }
        for label in labels {
            for (index, &cp) in label.iter().enumerate() {
                if !self.nfc.assigned(cp) {
                    return Err("idna_unassigned");
                }
                let allowed = match self.prop("classes", cp) {
                    "PVALID" => true,
                    "CONTEXTJ" => self.context_j(&label, index),
                    "CONTEXTO" => self.context_o(&label, index),
                    _ => false,
                };
                if !allowed {
                    return Err("idna2008_validity");
                }
            }
        }
        Ok(ascii)
    }

    pub fn wire_dns(&self, input: &str) -> Result<(), Error> {
        if input.is_empty() || !input.is_ascii() {
            return Err("idna_wire_ascii");
        }
        if self.issuer_dns(input)? != input {
            return Err("idna_wire_noncanonical");
        }
        Ok(())
    }
}

const PUNY_MAX: u64 = 0x7fff_ffff;

fn threshold(k: u64, bias: u64) -> u64 {
    k.saturating_sub(bias).clamp(1, 26)
}

fn adapt(mut delta: u64, count: u64, first: bool) -> u64 {
    delta /= if first { 700 } else { 2 };
    delta += delta / count;
    let mut k = 0;
    while delta > 455 {
        delta /= 35;
        k += 36;
    }
    k + 36 * delta / (delta + 38)
}

fn digit(n: u64) -> char {
    char::from(if n < 26 {
        n as u8 + b'a'
    } else {
        (n - 26) as u8 + b'0'
    })
}

pub fn puny_encode(input: &[char]) -> Result<String, Error> {
    let mut out: String = input.iter().filter(|c| c.is_ascii()).collect();
    let basic = out.len() as u64;
    let (mut handled, mut n, mut delta, mut bias) = (basic, 128u64, 0u64, 72u64);
    if basic > 0 {
        out.push('-');
    }
    while handled < input.len() as u64 {
        let next = input
            .iter()
            .map(|&c| u64::from(c))
            .filter(|&cp| cp >= n)
            .min()
            .ok_or("punycode_scalar")?;
        if next - n > (PUNY_MAX - delta) / (handled + 1) {
            return Err("punycode_overflow");
        }
        delta += (next - n) * (handled + 1);
        n = next;
        for &cp in input {
            let cp = u64::from(cp);
            if cp < n {
                if delta == PUNY_MAX {
                    return Err("punycode_overflow");
                }
                delta += 1;
            }
            if cp != n {
                continue;
            }
            let (mut q, mut k) = (delta, 36);
            loop {
                let t = threshold(k, bias);
                if q < t {
                    break;
                }
                out.push(digit(t + (q - t) % (36 - t)));
                q = (q - t) / (36 - t);
                k += 36;
            }
            out.push(digit(q));
            bias = adapt(delta, handled + 1, handled == basic);
            delta = 0;
            handled += 1;
        }
        if delta == PUNY_MAX {
            return Err("punycode_overflow");
        }
        delta += 1;
        n += 1;
    }
    Ok(out)
}

pub fn puny_decode(input: &str) -> Result<Vec<char>, Error> {
    if !input.is_ascii() {
        return Err("punycode_ascii");
    }
    let mut out = Vec::new();
    let mut index = 0;
    if let Some(dash) = input.rfind('-').filter(|&n| n > 0) {
        out.extend(input[..dash].chars());
        index = dash + 1;
    }
    let (mut n, mut i, mut bias) = (128u64, 0u64, 72u64);
    while index < input.len() {
        let (old, mut weight, mut k) = (i, 1, 36);
        loop {
            let b = *input.as_bytes().get(index).ok_or("punycode_truncated")?;
            index += 1;
            let digit = u64::from(match b {
                b'a'..=b'z' => b - b'a',
                b'A'..=b'Z' => b - b'A',
                b'0'..=b'9' => b - b'0' + 26,
                _ => return Err("punycode_digit"),
            });
            if digit > (PUNY_MAX - i) / weight {
                return Err("punycode_overflow");
            }
            i += digit * weight;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            if weight > PUNY_MAX / (36 - t) {
                return Err("punycode_overflow");
            }
            weight *= 36 - t;
            k += 36;
        }
        let count = out.len() as u64 + 1;
        bias = adapt(i - old, count, old == 0);
        if i / count > PUNY_MAX - n {
            return Err("punycode_overflow");
        }
        n += i / count;
        i %= count;
        let cp = char::from_u32(u32::try_from(n).map_err(|_| "punycode_scalar")?)
            .ok_or("punycode_scalar")?;
        out.insert(i as usize, cp);
        i += 1;
    }
    Ok(out)
}
