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

//! Live video signing support for C2PA section 19.3 (per-segment C2PA Manifest Box method).

use std::{collections::HashMap, io::Cursor};

use crate::{
    assertions::{ContinuityMethod, LiveVideoSegment},
    builder::Builder,
    error::{Error, Result},
    Reader, Signer,
};

/// Signs a sequence of live video segments using the per-segment C2PA Manifest Box method (§19.3).
///
/// Call [`sign_init_segment`] before [`sign_media_segment`]. Sequence numbers and continuity links
/// are managed automatically, and the signed init manifest is the first continuity link.
///
/// [`sign_media_segment`]: LiveVideoSigner::sign_media_segment
/// [`sign_init_segment`]: LiveVideoSigner::sign_init_segment
pub struct LiveVideoSigner {
    stream_id: String,
    next_sequence_number: u64,
    sequence_number_configured: bool,
    previous_manifest_id: Option<String>,
    base_manifest_json: String,
}

impl LiveVideoSigner {
    /// Creates a new signer from a manifest JSON string.
    ///
    /// The manifest must contain a `c2pa.livevideo.segment` assertion with a `streamId` field.
    /// That assertion is used only to read `streamId` — it is stripped from the base manifest
    /// and rebuilt with full continuity metadata on each [`sign_media_segment`] call.
    ///
    /// [`sign_media_segment`]: LiveVideoSigner::sign_media_segment
    pub fn from_manifest_json(manifest_json: impl Into<String>) -> Result<Self> {
        let json = manifest_json.into();
        let (
            stream_id,
            previous_manifest_id,
            next_sequence_number,
            sequence_number_configured,
            base_manifest_json,
        ) = extract_live_video_state(&json)?;
        Ok(Self {
            stream_id,
            next_sequence_number,
            sequence_number_configured,
            previous_manifest_id,
            base_manifest_json,
        })
    }

    /// Returns the original manifest JSON updated with the current continuity state.
    ///
    /// Call this after signing a batch of segments and persist the result back to the manifest
    /// file so that the next invocation resumes the chain automatically.
    pub fn updated_manifest_json(&self, original_manifest_json: &str) -> Result<String> {
        let prepared = super::prepare_live_manifest_json(original_manifest_json)?;
        let mut value: serde_json::Value = serde_json::from_str(&prepared)
            .map_err(|e| Error::BadParam(format!("invalid manifest JSON: {e}")))?;

        let assertions = value["assertions"].as_array_mut().ok_or_else(|| {
            Error::BadParam("manifest must have an 'assertions' array".to_string())
        })?;

        let assertion = assertions
            .iter_mut()
            .find(|a| a["label"].as_str() == Some(LiveVideoSegment::LABEL))
            .ok_or_else(|| {
                Error::BadParam(format!(
                    "manifest must include a '{}' assertion",
                    LiveVideoSegment::LABEL
                ))
            })?;

        if let Some(prev_id) = &self.previous_manifest_id {
            assertion["data"]["previousManifestId"] = serde_json::Value::String(prev_id.clone());
        }
        assertion["data"]["nextSequenceNumber"] =
            serde_json::Value::Number(self.next_sequence_number.into());

        serde_json::to_string_pretty(&value)
            .map_err(|e| Error::BadParam(format!("failed to serialize manifest: {e}")))
    }

    /// Restores the signed initialization manifest used by an existing §19.3 session.
    pub fn restore_init_segment(&mut self, segment_data: &[u8], format: &str) -> Result<()> {
        super::bmff::parse_init_segment(segment_data)?;
        self.previous_manifest_id = Some(extract_signed_manifest_id(segment_data, format)?);
        Ok(())
    }

    /// Signs the required init segment with the base manifest (§19.2.3).
    ///
    /// No `c2pa.livevideo.segment` assertion is added. The signed init manifest becomes the
    /// previous manifest for the first media segment.
    pub fn sign_init_segment(
        &mut self,
        segment_data: &[u8],
        format: &str,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        super::bmff::parse_init_segment(segment_data)?;
        let mut builder = Builder::from_context(super::context_from_thread_local_settings()?)
            .with_definition(self.base_manifest_json.as_str())?;
        let mut source = Cursor::new(segment_data);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(signer, format, &mut source, &mut dest)?;
        let signed_bytes = dest.into_inner();
        let manifest_id = extract_signed_manifest_id(&signed_bytes, format)?;
        if !manifest_id.starts_with("urn:c2pa:") || manifest_id.len() == "urn:c2pa:".len() {
            return Err(Error::BadParam(
                "signed initialization manifest must have a non-empty urn:c2pa: label".to_string(),
            ));
        }
        self.previous_manifest_id = Some(manifest_id);
        Ok(signed_bytes)
    }

    /// Signs a media segment, embeds a `c2pa.livevideo.segment` assertion, and advances state.
    pub fn sign_media_segment(
        &mut self,
        segment_data: &[u8],
        format: &str,
        signer: &dyn Signer,
    ) -> Result<Vec<u8>> {
        let sequence_number = super::bmff::moof_sequence_number(segment_data).ok_or_else(|| {
            Error::BadParam(
                "media segment must contain exactly one moof/traf and a valid mfhd".to_string(),
            )
        })?;
        if self.previous_manifest_id.is_none() {
            return Err(Error::BadParam(
                "a signed initialization segment must establish continuity before media signing"
                    .to_string(),
            ));
        }
        if !self.sequence_number_configured {
            self.next_sequence_number = u64::from(sequence_number);
            self.sequence_number_configured = true;
        }
        if u64::from(sequence_number) != self.next_sequence_number {
            return Err(Error::BadParam(format!(
                "live video sequenceNumber ({}) does not match moof/mfhd.sequence_number ({})",
                self.next_sequence_number, sequence_number
            )));
        }
        let assertion = self.build_live_video_assertion();

        let mut builder = Builder::from_context(super::context_from_thread_local_settings()?)
            .with_definition(self.base_manifest_json.as_str())?;
        builder.add_assertion(LiveVideoSegment::LABEL, &assertion)?;

        let mut source = Cursor::new(segment_data);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(signer, format, &mut source, &mut dest)?;

        let signed_bytes = dest.into_inner();
        let manifest_id = extract_signed_manifest_id(&signed_bytes, format)?;

        self.next_sequence_number = self.next_sequence_number.checked_add(1).ok_or_else(|| {
            Error::BadParam("live video sequenceNumber cannot advance past u64::MAX".to_string())
        })?;
        self.previous_manifest_id = Some(manifest_id);

        Ok(signed_bytes)
    }

    /// Returns the manifest ID of the most recently signed media segment, if any.
    pub fn previous_manifest_id(&self) -> Option<&str> {
        self.previous_manifest_id.as_deref()
    }

    /// Returns the sequence number that will be assigned to the next media segment.
    pub fn next_sequence_number(&self) -> u64 {
        self.next_sequence_number
    }

    fn build_live_video_assertion(&self) -> LiveVideoSegment {
        LiveVideoSegment {
            sequence_number: self.next_sequence_number,
            stream_id: self.stream_id.clone(),
            continuity_method: ContinuityMethod::ManifestId,
            previous_manifest_id: self.previous_manifest_id.clone(),
            additional_fields: HashMap::new(),
        }
    }
}

fn extract_signed_manifest_id(signed_segment: &[u8], format: &str) -> Result<String> {
    let reader = Reader::from_context(super::context_from_thread_local_settings()?)
        .with_stream(format, Cursor::new(signed_segment))?;
    if let Some(status) = reader.validation_status().and_then(|statuses| {
        statuses
            .iter()
            .find(|status| !status.passed() && super::is_manifest_integrity_failure(status.code()))
    }) {
        return Err(Error::BadParam(format!(
            "signed live manifest failed integrity validation: {}",
            status.code()
        )));
    }
    let manifest_id = reader
        .active_manifest()
        .and_then(|m| m.label())
        .map(|l| l.to_string())
        .ok_or(Error::NotFound)?;
    if !manifest_id.starts_with("urn:c2pa:") || manifest_id.len() == "urn:c2pa:".len() {
        return Err(Error::BadParam(
            "signed live manifest must have a non-empty urn:c2pa: label".to_string(),
        ));
    }
    Ok(manifest_id)
}

/// Parses the manifest JSON and extracts the live video signer state.
///
/// Returns `(stream_id, previous_manifest_id, next_sequence_number, base_manifest_json)`.
/// The `c2pa.livevideo.segment` assertion is removed from `base_manifest_json` so it is
/// not duplicated when the full assertion is added at signing time.
fn extract_live_video_state(
    manifest_json: &str,
) -> Result<(String, Option<String>, u64, bool, String)> {
    let prepared = super::prepare_live_manifest_json(manifest_json)?;
    let mut value: serde_json::Value = serde_json::from_str(&prepared)
        .map_err(|e| Error::BadParam(format!("invalid manifest JSON: {e}")))?;

    let assertions = value["assertions"]
        .as_array_mut()
        .ok_or_else(|| Error::BadParam("manifest must have an 'assertions' array".to_string()))?;

    let position = assertions
        .iter()
        .position(|a| a["label"].as_str() == Some(LiveVideoSegment::LABEL))
        .ok_or_else(|| {
            Error::BadParam(format!(
                "manifest must include a '{}' assertion with 'streamId'",
                LiveVideoSegment::LABEL
            ))
        })?;

    let live_video_assertion = assertions.remove(position);
    let data = &live_video_assertion["data"];

    let stream_id = data["streamId"]
        .as_str()
        .ok_or_else(|| {
            Error::BadParam(format!(
                "'{}' assertion must have a 'streamId' string field",
                LiveVideoSegment::LABEL
            ))
        })?
        .to_string();

    let previous_manifest_id = data["previousManifestId"].as_str().map(String::from);

    let configured_sequence_number = data.get("nextSequenceNumber").and_then(|v| v.as_u64());
    let next_sequence_number = configured_sequence_number.unwrap_or(1);

    let base_json = serde_json::to_string(&value)
        .map_err(|e| Error::BadParam(format!("failed to serialize manifest: {e}")))?;

    Ok((
        stream_id,
        previous_manifest_id,
        next_sequence_number,
        configured_sequence_number.is_some(),
        base_json,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::utils::ephemeral_signer::EphemeralSigner;

    fn test_signer() -> EphemeralSigner {
        EphemeralSigner::new("test-manifestbox.local").unwrap()
    }

    fn test_manifest_json() -> &'static str {
        r#"{"assertions": [
            {"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}},
            {"label": "c2pa.livevideo.segment", "data": {"sequenceNumber": 5, "nextSequenceNumber": 5, "streamId": "stream-1", "continuityMethod": "c2pa.manifestId"}}
        ]}"#
    }

    /// Regression test: `manifestId`/`previousManifestId` must be the manifest's c2pa URN
    /// label (§8.1), not its XMP instance ID — otherwise continuity breaks with any
    /// spec-compliant third-party validator, since instance IDs and manifest labels are
    /// different, unrelated identifiers.
    #[test]
    fn sign_media_segment_manifest_id_is_c2pa_urn_label() {
        // EphemeralSigner certs are intentionally untrusted (see ephemeral_signer.rs).
        crate::settings::set_settings_value("verify.verify_trust", false).unwrap();

        let signer = test_signer();
        let init_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_791182bps/BigBuckBunny_2s_init.mp4");
        let segment_data =
            include_bytes!("../../tests/fixtures/bunny/bunny_791182bps/BigBuckBunny_2s5.m4s");

        let mut live_signer = LiveVideoSigner::from_manifest_json(test_manifest_json()).unwrap();
        live_signer
            .sign_init_segment(init_data, "video/mp4", &signer)
            .unwrap();
        let signed = live_signer
            .sign_media_segment(segment_data, "video/mp4", &signer)
            .unwrap();

        let manifest_id = live_signer.previous_manifest_id().unwrap().to_string();
        assert!(
            manifest_id.starts_with("urn:c2pa:"),
            "manifestId must be the manifest's c2pa URN label (§8.1), got: {manifest_id}"
        );

        // Cross-check against the label actually embedded in the signed segment's manifest.
        let reader =
            Reader::from_context(crate::live_video::context_from_thread_local_settings().unwrap())
                .with_stream("video/mp4", Cursor::new(&signed))
                .unwrap();
        let manifest = reader.active_manifest().unwrap();
        assert_eq!(manifest.label().unwrap(), manifest_id);
    }
}
