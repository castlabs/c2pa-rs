// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Bounded validation and deterministic encoding of CBOR used by trusted VSI.
//!
//! The scanner works on raw bytes. `c2pa_cbor` decoding is permissive about
//! encoding choices, so it cannot prove that caller bytes are deterministic.
//! Rules follow RFC 8949 section 4.2.1 core deterministic encoding: definite
//! lengths, shortest integer/length/tag heads, preferred-width floats with the
//! canonical half-precision NaN, and map keys strictly increasing in bytewise
//! order of their encodings (which also rejects duplicate keys).

use crate::{Error, Result};

/// Maximum accepted expert Sig_structure size.
pub(super) const MAX_SIG_STRUCTURE_LEN: usize = 1024 * 1024;
/// Maximum accepted protected-header or hash-map size.
pub(super) const MAX_SMALL_CBOR_LEN: usize = 64 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 4096;

fn invalid(message: impl Into<String>) -> Error {
    Error::BadParam(format!(
        "non-canonical or unsupported CBOR: {}",
        message.into()
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KeyRule {
    /// Outer COSE header labels: integer or text.
    CoseLabel,
    /// Nested maps: integer, byte string, or text.
    Nested,
}

pub(super) struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
    items: usize,
    ordered_maps: bool,
}

impl<'a> Scanner<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            items: 0,
            ordered_maps: true,
        }
    }

    /// Native serde struct maps preserve field order, not deterministic key order.
    pub(super) fn well_formed(data: &'a [u8]) -> Self {
        Self {
            ordered_maps: false,
            ..Self::new(data)
        }
    }

    pub(super) fn at_end(&self) -> bool {
        self.pos == self.data.len()
    }

    pub(super) fn position(&self) -> usize {
        self.pos
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .data
            .get(self.pos)
            .ok_or_else(|| invalid("truncated item"))?;
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8]> {
        let len = usize::try_from(len).map_err(|_| invalid("length exceeds address space"))?;
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| invalid("length exceeds input"))?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Reads a head, enforcing definite and shortest argument encodings.
    /// Major type 7 heads are returned raw (major, additional info, argument).
    pub(super) fn head(&mut self) -> Result<(u8, u8, u64)> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let argument = match info {
            0..=23 => u64::from(info),
            24 => {
                let value = u64::from(self.byte()?);
                if major != 7 && value < 24 {
                    return Err(invalid("non-minimal one-byte argument"));
                }
                value
            }
            25 => {
                let bytes = self.take(2)?;
                let value = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                if major != 7 && value <= 0xff {
                    return Err(invalid("non-minimal two-byte argument"));
                }
                value
            }
            26 => {
                let bytes = self.take(4)?;
                let value = u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                if major != 7 && value <= 0xffff {
                    return Err(invalid("non-minimal four-byte argument"));
                }
                value
            }
            27 => {
                let bytes = self.take(8)?;
                let mut array = [0u8; 8];
                array.copy_from_slice(bytes);
                let value = u64::from_be_bytes(array);
                if major != 7 && value <= 0xffff_ffff {
                    return Err(invalid("non-minimal eight-byte argument"));
                }
                value
            }
            31 => return Err(invalid("indefinite length or break")),
            _ => return Err(invalid("reserved additional information")),
        };
        Ok((major, info, argument))
    }

    fn count_item(&mut self) -> Result<()> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(invalid("too many items"));
        }
        Ok(())
    }

    /// Scans one complete value and returns its encoded byte range.
    pub(super) fn value(&mut self, depth: usize) -> Result<&'a [u8]> {
        if depth > MAX_DEPTH {
            return Err(invalid("nesting too deep"));
        }
        self.count_item()?;
        let start = self.pos;
        let (major, info, argument) = self.head()?;
        match major {
            0 | 1 => {}
            2 => {
                self.take(argument)?;
            }
            3 => {
                let text = self.take(argument)?;
                std::str::from_utf8(text).map_err(|_| invalid("text is not UTF-8"))?;
            }
            4 => {
                for _ in 0..argument {
                    self.value(depth + 1)?;
                }
            }
            5 => self.map_entries(argument, depth, KeyRule::Nested)?,
            6 => {
                self.value(depth + 1)?;
            }
            7 => check_simple_or_float(info, argument)?,
            _ => unreachable!("major type is three bits"),
        }
        Ok(&self.data[start..self.pos])
    }

    fn key(&mut self, rule: KeyRule) -> Result<&'a [u8]> {
        let start = self.pos;
        let major = self.data.get(start).map(|byte| byte >> 5);
        let allowed = matches!(
            (rule, major),
            (_, Some(0 | 1 | 3)) | (KeyRule::Nested, Some(2))
        );
        if !allowed {
            return Err(invalid("unsupported map key type"));
        }
        self.value(MAX_DEPTH)
    }

    fn map_entries(&mut self, count: u64, depth: usize, rule: KeyRule) -> Result<()> {
        let mut previous: Option<&[u8]> = None;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..count {
            let key = self.key(rule)?;
            if !seen.insert(key)
                || (self.ordered_maps && previous.is_some_and(|previous| previous >= key))
            {
                return Err(invalid(
                    "map keys are duplicated or not in deterministic order",
                ));
            }
            previous = Some(key);
            self.value(depth + 1)?;
        }
        Ok(())
    }

    /// Scans a map at the current position using the supplied key rule and
    /// returns its raw `(key, value)` encodings.
    pub(super) fn map(&mut self, rule: KeyRule) -> Result<Vec<(&'a [u8], &'a [u8])>> {
        self.count_item()?;
        let (major, _, count) = self.head()?;
        if major != 5 {
            return Err(invalid("expected a map"));
        }
        let mut entries = Vec::new();
        let mut previous: Option<&[u8]> = None;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..count {
            let key = self.key(rule)?;
            if !seen.insert(key)
                || (self.ordered_maps && previous.is_some_and(|previous| previous >= key))
            {
                return Err(invalid(
                    "map keys are duplicated or not in deterministic order",
                ));
            }
            previous = Some(key);
            let value = self.value(1)?;
            entries.push((key, value));
        }
        Ok(entries)
    }

    /// Reads a definite byte string at the current position.
    pub(super) fn bytes(&mut self) -> Result<&'a [u8]> {
        self.count_item()?;
        let (major, _, len) = self.head()?;
        if major != 2 {
            return Err(invalid("expected a byte string"));
        }
        self.take(len)
    }
}

fn check_simple_or_float(info: u8, argument: u64) -> Result<()> {
    match info {
        20..=22 => Ok(()), // false, true, null
        25 => {
            let bits = argument as u16;
            let is_nan = bits & 0x7c00 == 0x7c00 && bits & 0x03ff != 0;
            if is_nan && bits != 0x7e00 {
                return Err(invalid("non-canonical NaN"));
            }
            Ok(())
        }
        26 => {
            let value = f64::from(f32::from_bits(argument as u32));
            if value.is_nan() || fits_f16(value) {
                return Err(invalid("float32 is not the preferred width"));
            }
            Ok(())
        }
        27 => {
            let value = f64::from_bits(argument);
            if value.is_nan() || fits_f32(value) {
                return Err(invalid("float64 is not the preferred width"));
            }
            Ok(())
        }
        _ => Err(invalid("unsupported simple value")),
    }
}

/// Decomposes a finite nonzero f64 into (unbiased exponent, 53-bit mantissa).
fn decompose(value: f64) -> Option<(i32, u64)> {
    let bits = value.abs().to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    if exponent == 0 {
        // f64 subnormals are below every f16/f32 value except zero.
        return None;
    }
    Some((exponent - 1023, fraction | (1u64 << 52)))
}

fn fits_width(value: f64, mantissa_bits: u32, min_normal: i32, max_exponent: i32) -> bool {
    if value.is_infinite() || value == 0.0 {
        return true;
    }
    let Some((exponent, mantissa)) = decompose(value) else {
        return false;
    };
    if exponent > max_exponent {
        return false;
    }
    let required_zero_bits = if exponent >= min_normal {
        52 - mantissa_bits as i32
    } else {
        // Subnormal: value must be a multiple of 2^(min_normal - mantissa_bits).
        52 - mantissa_bits as i32 + (min_normal - exponent)
    };
    required_zero_bits <= 52 && mantissa.trailing_zeros() as i32 >= required_zero_bits
}

pub(super) fn fits_f16(value: f64) -> bool {
    fits_width(value, 10, -14, 15)
}

pub(super) fn fits_f32(value: f64) -> bool {
    fits_width(value, 23, -126, 127)
}

/// Validates that `data` is exactly one deterministic CBOR value.
pub(super) fn validate_single_value(data: &[u8], max_len: usize) -> Result<()> {
    if data.len() > max_len {
        return Err(invalid("input exceeds size limit"));
    }
    let mut scanner = Scanner::new(data);
    scanner.value(0)?;
    if !scanner.at_end() {
        return Err(invalid("trailing bytes"));
    }
    Ok(())
}

// ── deterministic encoding of internally generated values ────────────────────

fn encode_head(out: &mut Vec<u8>, major: u8, argument: u64) {
    let major = major << 5;
    if argument < 24 {
        out.push(major | argument as u8);
    } else if argument <= 0xff {
        out.push(major | 24);
        out.push(argument as u8);
    } else if argument <= 0xffff {
        out.push(major | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= 0xffff_ffff {
        out.push(major | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

/// Encodes a value using deterministic encoding. Floats are rejected because
/// native templates never contain them.
pub(super) fn encode_deterministic(value: &c2pa_cbor::Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_into(&mut out, value, 0)?;
    Ok(out)
}

fn encode_into(out: &mut Vec<u8>, value: &c2pa_cbor::Value, depth: usize) -> Result<()> {
    use c2pa_cbor::Value;
    if depth > MAX_DEPTH {
        return Err(invalid("nesting too deep"));
    }
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Integer(integer) => {
            if *integer >= 0 {
                encode_head(out, 0, *integer as u64);
            } else {
                encode_head(out, 1, !(*integer as u64));
            }
        }
        Value::Float(_) => return Err(invalid("floats are not supported in templates")),
        Value::Bytes(bytes) => {
            encode_head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            encode_head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            encode_head(out, 4, items.len() as u64);
            for item in items {
                encode_into(out, item, depth + 1)?;
            }
        }
        Value::Map(map) => {
            let mut entries = Vec::with_capacity(map.len());
            for (key, value) in map {
                let mut key_bytes = Vec::new();
                encode_into(&mut key_bytes, key, depth + 1)?;
                let mut value_bytes = Vec::new();
                encode_into(&mut value_bytes, value, depth + 1)?;
                entries.push((key_bytes, value_bytes));
            }
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            encode_head(out, 5, entries.len() as u64);
            for (key, value) in entries {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
        }
        Value::Tag(tag, inner) => {
            encode_head(out, 6, *tag);
            encode_into(out, inner, depth + 1)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn ok(bytes: &[u8]) {
        validate_single_value(bytes, MAX_SMALL_CBOR_LEN)
            .unwrap_or_else(|e| panic!("expected valid {bytes:02x?}: {e}"));
    }

    fn bad(bytes: &[u8]) {
        assert!(
            validate_single_value(bytes, MAX_SMALL_CBOR_LEN).is_err(),
            "expected rejection of {bytes:02x?}"
        );
    }

    #[test]
    fn integers_and_lengths_must_be_minimal() {
        ok(&[0x17]);
        ok(&[0x18, 0x18]);
        bad(&[0x18, 0x17]);
        bad(&[0x19, 0x00, 0xff]);
        bad(&[0x1a, 0x00, 0x00, 0xff, 0xff]);
        bad(&[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        ok(&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]);
        bad(&[0x58, 0x01, 0x00]); // one-byte bstr with long head
        bad(&[0xd8, 0x01, 0x00]); // tag 1 with long head
        bad(&[0x1c]);
    }

    #[test]
    fn indefinite_trailing_and_truncation_are_rejected() {
        bad(&[0x5f, 0x41, 0x00, 0xff]);
        bad(&[0x9f, 0xff]);
        bad(&[0xbf, 0xff]);
        bad(&[0x00, 0x00]);
        bad(&[0x42, 0x00]);
        bad(&[0xff]);
    }

    #[test]
    fn map_keys_are_ordered_and_unique() {
        ok(&[0xa2, 0x01, 0x00, 0x63, b'i', b'a', b't', 0x00]);
        bad(&[0xa2, 0x63, b'i', b'a', b't', 0x00, 0x01, 0x00]);
        bad(&[0xa2, 0x01, 0x00, 0x01, 0x00]);
        // bytewise order: 0x19 (int 1000) sorts before 0x61 ("a")
        ok(&[0xa2, 0x19, 0x03, 0xe8, 0x00, 0x61, b'a', 0x00]);
        bad(&[0xa2, 0x61, b'a', 0x00, 0x19, 0x03, 0xe8, 0x00]);
        bad(&[0xa1, 0x80, 0x00]); // array key
        bad(&[0xa1, 0xc1, 0x00, 0x00]); // tagged key
    }

    #[test]
    fn well_formed_payload_maps_allow_field_order_but_not_duplicates() {
        let native_order = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x00];
        let mut scanner = Scanner::well_formed(&native_order);
        scanner.map(KeyRule::Nested).unwrap();
        assert!(scanner.at_end());
        assert!(Scanner::new(&native_order).map(KeyRule::Nested).is_err());
        let duplicate = [0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x00];
        assert!(Scanner::well_formed(&duplicate)
            .map(KeyRule::Nested)
            .is_err());
        let nested_duplicate = [0xa1, 0x61, b'a', 0xa2, 0x01, 0x00, 0x01, 0x00];
        assert!(Scanner::well_formed(&nested_duplicate)
            .map(KeyRule::Nested)
            .is_err());
    }

    /// RFC 8949 §4.2.1 core deterministic encoding (the rule COSE, RFC 9052,
    /// references) orders keys bytewise by their complete encodings. The
    /// obsolete RFC 7049 §3.9 "canonical" rule sorted shorter encodings first;
    /// that order must be rejected. Keys: `1` = 0x01, `1000` = 0x19 03 e8,
    /// `"a"` = 0x61 61, so bytewise is 1, 1000, "a" but length-first is 1, "a", 1000.
    #[test]
    fn mixed_keys_use_rfc8949_bytewise_order_not_length_first() {
        let bytewise = [0xa3, 0x01, 0x26, 0x19, 0x03, 0xe8, 0x00, 0x61, b'a', 0x00];
        let length_first = [0xa3, 0x01, 0x26, 0x61, b'a', 0x00, 0x19, 0x03, 0xe8, 0x00];
        ok(&bytewise);
        bad(&length_first);
        for rule in [KeyRule::CoseLabel, KeyRule::Nested] {
            let mut scanner = Scanner::new(&bytewise);
            let keys: Vec<_> = scanner
                .map(rule)
                .unwrap()
                .into_iter()
                .map(|e| e.0)
                .collect();
            assert_eq!(keys, [&[0x01][..], &[0x19, 0x03, 0xe8], &[0x61, b'a']]);
            assert!(Scanner::new(&length_first).map(rule).is_err());
        }

        use std::collections::BTreeMap;

        use c2pa_cbor::Value;
        let mut map = BTreeMap::new();
        map.insert(Value::Text("a".into()), Value::Integer(0));
        map.insert(Value::Integer(1000), Value::Integer(0));
        map.insert(Value::Integer(1), Value::Integer(-7));
        assert_eq!(encode_deterministic(&Value::Map(map)).unwrap(), bytewise);
    }

    #[test]
    fn floats_must_use_preferred_width_and_canonical_nan() {
        ok(&[0xf9, 0x3c, 0x00]); // 1.0 as f16
        ok(&[0xf9, 0x7e, 0x00]); // canonical NaN
        bad(&[0xf9, 0x7e, 0x01]);
        bad(&[0xfa, 0x3f, 0x80, 0x00, 0x00]); // 1.0 as f32
        ok(&[0xfa, 0x3f, 0x80, 0x00, 0x01]);
        bad(&[0xfa, 0x7f, 0xc0, 0x00, 0x00]); // f32 NaN
        bad(&[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0]); // 1.0 as f64
        ok(&[0xfb, 0x3f, 0xb9, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]); // 0.1
        bad(&[0xfa, 0x00, 0x00, 0x00, 0x00]); // zero as f32
        bad(&[0xfa, 0x33, 0x80, 0x00, 0x00]); // 2^-24 fits an f16 subnormal
        ok(&[0xfa, 0x33, 0x00, 0x00, 0x00]); // 2^-25 needs f32
    }

    #[test]
    fn preferred_width_boundaries() {
        assert!(fits_f16(65504.0));
        assert!(!fits_f16(65505.0));
        assert!(fits_f16(2f64.powi(-24)));
        assert!(!fits_f16(2f64.powi(-25)));
        assert!(fits_f16(f64::INFINITY));
        assert!(fits_f32(f64::from(f32::MAX)));
        assert!(!fits_f32(0.1));
        assert!(fits_f32(2f64.powi(-149)));
        assert!(!fits_f32(2f64.powi(-150)));
    }

    #[test]
    fn simple_values_utf8_and_depth() {
        ok(&[0xf4]);
        ok(&[0xf6]);
        bad(&[0xf7]); // undefined
        bad(&[0xf8, 0x20]); // extended simple
        bad(&[0xe0]);
        bad(&[0x62, 0xc3, 0x28]);
        ok(&[0x62, 0xc3, 0xa9]);
        let mut deep = vec![0x81; 33];
        deep.push(0x00);
        bad(&deep);
        let mut shallow = vec![0x81; 32];
        shallow.push(0x00);
        ok(&shallow);
        ok(&[0xc1, 0x1a, 0x5f, 0x5e, 0x10, 0x00]); // tagged value
    }

    #[test]
    fn item_count_is_bounded() {
        let mut many = vec![0x99, 0x10, 0x00];
        many.extend(std::iter::repeat_n(0x00, 4096));
        bad(&many);
        let mut enough = vec![0x99, 0x0f, 0xff];
        enough.extend(std::iter::repeat_n(0x00, 4095));
        ok(&enough);
    }

    #[test]
    fn deterministic_encoder_sorts_keys_bytewise() {
        use std::collections::BTreeMap;

        use c2pa_cbor::Value;
        let mut map = BTreeMap::new();
        map.insert(Value::Text("exclusions".into()), Value::Array(vec![]));
        map.insert(Value::Text("alg".into()), Value::Text("sha256".into()));
        map.insert(Value::Text("hash".into()), Value::Bytes(vec![0; 2]));
        let bytes = encode_deterministic(&Value::Map(map)).unwrap();
        ok(&bytes);
        let alg = bytes.windows(3).position(|w| w == b"alg").unwrap();
        let hash = bytes.windows(4).position(|w| w == b"hash").unwrap();
        let exclusions = bytes.windows(10).position(|w| w == b"exclusions").unwrap();
        assert!(alg < hash && hash < exclusions);
        let decoded: Value = c2pa_cbor::from_slice(&bytes).unwrap();
        assert_eq!(encode_deterministic(&decoded).unwrap(), bytes);
    }
}
