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

//! Defines the `c2pa.session-keys` assertion ([§18.25]) for live video streams.
//!
//! [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys

use serde::{Deserialize, Serialize};

use super::labels;
use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    cbor_types::DateT,
    Result,
};

/// Serialize the `signer_binding` field as COSE_Sign1_Tagged (CBOR tag 18 + content).
///
/// Use the CBOR crate's tag wrapper rather than a serializer-private marker.
fn serialize_cose_sign1_tagged<S>(
    value: &c2pa_cbor::Value,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use c2pa_cbor::Value;

    let value = match value {
        Value::Tag(18, inner) => inner.as_ref(),
        value => value,
    };
    if !matches!(value, Value::Array(items) if matches!(items.as_slice(),
        [Value::Bytes(_), Value::Map(_), Value::Null | Value::Bytes(_), Value::Bytes(_)]
    )) {
        return Err(serde::ser::Error::custom(
            "signerBinding must be a COSE_Sign1 array with at most one tag 18",
        ));
    }
    c2pa_cbor::tags::Tagged::new(Some(18), value).serialize(serializer)
}

/// Deserialize the `signer_binding` field.
///
/// Keep the inner representation for tag 18; retain legacy untagged values.
/// Other tags are not stripped and will fail signer-binding validation.
fn deserialize_cose_sign1_tagged<'de, D>(
    deserializer: D,
) -> std::result::Result<c2pa_cbor::Value, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match c2pa_cbor::Value::deserialize(deserializer)? {
        c2pa_cbor::Value::Tag(18, value) => Ok(*value),
        value => Ok(value),
    }
}

/// A single session key used to verify VSI signatures ([§18.25]).
///
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionKey {
    /// COSE_Key (RFC 9052) with mandatory `kid`, stored as raw CBOR.
    pub key: c2pa_cbor::Value,
    pub min_sequence_number: u64,
    /// Key creation time (CBOR tag 0 date-time string).
    pub created_at: DateT,
    /// Seconds from `created_at` for which this key is valid.
    pub validity_period: u64,
    /// COSE_Sign1_Tagged binding this key to the signer's certificate.
    ///
    /// Stored internally as the inner COSE_Sign1 content (without tag 18).
    /// Serialization also accepts one existing tag 18 wrapper without duplicating it.
    /// The CBOR tag 18 is added/stripped transparently during serialization/deserialization.
    #[serde(
        serialize_with = "serialize_cose_sign1_tagged",
        deserialize_with = "deserialize_cose_sign1_tagged"
    )]
    pub signer_binding: c2pa_cbor::Value,
}

/// The `c2pa.session-keys` assertion embedded in a live video init segment manifest ([§18.25]).
///
/// [§18.25]: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_session_keys
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SessionKeys {
    pub keys: Vec<SessionKey>,
}

impl SessionKeys {
    pub const LABEL: &'static str = labels::SESSION_KEYS;
}

impl AssertionBase for SessionKeys {
    const LABEL: &'static str = Self::LABEL;

    fn to_assertion(&self) -> Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Self::from_cbor_assertion(assertion)
    }
}

impl AssertionCbor for SessionKeys {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::assertions::labels;

    fn minimal_session_key() -> SessionKey {
        // Minimal COSE_Key map: {1: 2} — kty: EC2
        let mut key_map = std::collections::BTreeMap::new();
        key_map.insert(
            c2pa_cbor::Value::Integer(1.into()),
            c2pa_cbor::Value::Integer(2.into()),
        );
        SessionKey {
            key: c2pa_cbor::Value::Map(key_map),
            min_sequence_number: 0,
            created_at: DateT("2026-01-01T00:00:00Z".to_string()),
            validity_period: 3600,
            signer_binding: c2pa_cbor::Value::Array(vec![
                c2pa_cbor::Value::Bytes(vec![]),
                c2pa_cbor::Value::Map(Default::default()),
                c2pa_cbor::Value::Null,
                c2pa_cbor::Value::Bytes(vec![0; 64]),
            ]),
        }
    }

    #[test]
    fn label_matches_spec() {
        assert_eq!(SessionKeys::LABEL, labels::SESSION_KEYS);
        assert_eq!(SessionKeys::LABEL, "c2pa.session-keys");
    }

    #[test]
    fn signer_binding_wire_has_exactly_one_cose_tag() {
        use c2pa_cbor::Value;
        use coset::TaggedCborSerializable;

        let original = SessionKeys {
            keys: vec![SessionKey {
                signer_binding: Value::Array(vec![
                    Value::Bytes(vec![]),
                    Value::Map(Default::default()),
                    Value::Null,
                    Value::Bytes(vec![0; 64]),
                ]),
                ..minimal_session_key()
            }],
        };
        let bytes = c2pa_cbor::to_vec(&original).unwrap();
        let mut pretagged = original.clone();
        pretagged.keys[0].signer_binding =
            Value::Tag(18, Box::new(original.keys[0].signer_binding.clone()));
        assert_eq!(c2pa_cbor::to_vec(&pretagged).unwrap(), bytes);
        let Value::Map(root) = c2pa_cbor::from_slice(&bytes).unwrap() else {
            panic!("session keys must be a map");
        };
        let Value::Array(keys) = &root[&Value::Text("keys".into())] else {
            panic!("keys must be an array");
        };
        let Value::Map(key) = &keys[0] else {
            panic!("session key must be a map");
        };
        let binding = &key[&Value::Text("signerBinding".into())];
        assert!(matches!(binding, Value::Tag(18, inner) if matches!(**inner, Value::Array(_))));
        coset::CoseSign1::from_tagged_slice(&c2pa_cbor::to_vec(binding).unwrap()).unwrap();
        assert!(matches!(
            key[&Value::Text("createdAt".into())],
            Value::Tag(0, _)
        ));
        let restored: SessionKeys = c2pa_cbor::from_slice(&bytes).unwrap();
        assert_eq!(restored, original);
        assert_eq!(c2pa_cbor::to_vec(&restored).unwrap(), bytes);
    }

    #[test]
    fn signer_binding_serialization_rejects_invalid_shapes_and_tags() {
        use c2pa_cbor::Value;

        let key = minimal_session_key();
        let inner = key.signer_binding.clone();
        for invalid in [
            Value::Tag(17, Box::new(inner.clone())),
            Value::Tag(18, Box::new(Value::Tag(18, Box::new(inner)))),
            Value::Null,
            Value::Bytes(vec![0xd2, 0x84]),
            Value::Array(vec![]),
            Value::Array(vec![Value::Null; 4]),
            Value::Array(vec![
                Value::Bytes(vec![]),
                Value::Map(Default::default()),
                Value::Tag(18, Box::new(Value::Null)),
                Value::Bytes(vec![0; 64]),
            ]),
        ] {
            let invalid_key = SessionKey {
                signer_binding: invalid,
                ..key.clone()
            };
            assert!(c2pa_cbor::to_vec(&invalid_key).is_err());
        }
    }

    #[test]
    fn round_trip_cbor_single_key() {
        let original = SessionKeys {
            keys: vec![minimal_session_key()],
        };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn round_trip_cbor_multiple_keys() {
        let original = SessionKeys {
            keys: vec![minimal_session_key(), minimal_session_key()],
        };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn round_trip_preserves_validity_period() {
        let key = SessionKey {
            validity_period: 86400,
            ..minimal_session_key()
        };
        let original = SessionKeys { keys: vec![key] };
        let assertion = original.to_assertion().unwrap();
        let restored = SessionKeys::from_assertion(&assertion).unwrap();
        assert_eq!(restored.keys[0].validity_period, 86400);
    }
}
