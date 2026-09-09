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

//! Reserved API surface for prehashed trusted VSI signing.
//!
//! This module intentionally provides no signing implementation yet. Callers
//! must inspect [`TrustedVsiCapabilities`] before using the API. Every session
//! operation returns [`Error::UnsupportedType`] in this scaffold.

use std::sync::Arc;

use super::VsiSessionConfig;
use crate::{error::Error, Context, Result};

/// Capability bits for prehashed trusted VSI signing.
///
/// The bit assignments are stable: bit 0 (value 1) is split init UUID, bit 1
/// (value 2) is expert EMSG/Sig_structure signing, bit 2 (value 4) is
/// signer-composed EMSG, bit 3 (value 8) is recovery, bit 4 (value 16) is
/// signing-context V1, and bit 5 (value 32) is full `u32` exhaustion handling.
/// The current scaffold reports no capabilities.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustedVsiCapabilities(u64);

impl TrustedVsiCapabilities {
    /// Bit mask for split initialization-segment UUID support.
    pub const SPLIT_INIT_UUID_BIT: u64 = 1;
    /// Bit mask for expert EMSG/Sig_structure support.
    pub const EXPERT_EMSG_SIG_STRUCTURE_BIT: u64 = 2;
    /// Bit mask for signer-composed EMSG support.
    pub const SIGNER_COMPOSED_EMSG_BIT: u64 = 4;
    /// Bit mask for signed-artifact recovery support.
    pub const RECOVERY_BIT: u64 = 8;
    /// Bit mask for [`VsiSigningContextV1`] support.
    pub const SIGNING_CONTEXT_V1_BIT: u64 = 16;
    /// Bit mask for safely signing through the full `u32` sequence space.
    pub const FULL_UINT32_EXHAUSTION_BIT: u64 = 32;

    /// Returns the capabilities implemented by this build.
    pub const fn current() -> Self {
        Self(0)
    }

    /// Returns the raw capability bit mask.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Reports whether split initialization-segment UUID signing is supported.
    pub const fn supports_split_init_uuid(self) -> bool {
        self.0 & Self::SPLIT_INIT_UUID_BIT != 0
    }

    /// Reports whether caller-composed EMSG/Sig_structure signing is supported.
    pub const fn supports_expert_emsg_sig_structure(self) -> bool {
        self.0 & Self::EXPERT_EMSG_SIG_STRUCTURE_BIT != 0
    }

    /// Reports whether the SDK can compose a reserved EMSG around a supplied hash.
    pub const fn supports_signer_composed_emsg(self) -> bool {
        self.0 & Self::SIGNER_COMPOSED_EMSG_BIT != 0
    }

    /// Reports whether recovery from signed UUID/EMSG artifacts is supported.
    pub const fn supports_recovery(self) -> bool {
        self.0 & Self::RECOVERY_BIT != 0
    }

    /// Reports whether callbacks receive [`VsiSigningContextV1`].
    pub const fn supports_signing_context_v1(self) -> bool {
        self.0 & Self::SIGNING_CONTEXT_V1_BIT != 0
    }

    /// Reports whether the terminal `u32::MAX` sequence can be signed safely.
    pub const fn supports_full_uint32_exhaustion(self) -> bool {
        self.0 & Self::FULL_UINT32_EXHAUSTION_BIT != 0
    }
}

/// Purpose of a trusted VSI signing callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedVsiSigningPurpose {
    /// Bind the session key to the claim signer's certificate.
    SignerBinding,
    /// Sign one media segment's VSI Sig_structure.
    Vsi,
}

/// Version-one authorization context for a trusted VSI signing callback.
///
/// Optional sequence and event identifiers are absent for signatures that are
/// not associated with a media EMSG. `exhaust_after_sign` tells an external
/// signer that the authorized signature consumes the final usable identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VsiSigningContextV1 {
    purpose: TrustedVsiSigningPurpose,
    sequence_number: Option<u32>,
    event_id: Option<u32>,
    exhaust_after_sign: bool,
}

impl VsiSigningContextV1 {
    /// Returns the explicit reason for the signature request.
    pub const fn purpose(&self) -> TrustedVsiSigningPurpose {
        self.purpose
    }

    /// Returns the media sequence number, when the request represents media.
    pub const fn sequence_number(&self) -> Option<u32> {
        self.sequence_number
    }

    /// Returns the EMSG event identifier, when one has been reserved.
    pub const fn event_id(&self) -> Option<u32> {
        self.event_id
    }

    /// Returns whether this signature exhausts the usable identifier space.
    pub const fn exhaust_after_sign(&self) -> bool {
        self.exhaust_after_sign
    }
}

/// Reserved initialization UUID bytes and their public manifest identifier.
///
/// Instances will be returned by [`TrustedVsiPrehashedSession::reserve_init_uuid`]
/// once that capability is implemented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedVsiInitUuidReservation {
    bytes: Vec<u8>,
    manifest_id: String,
}

impl TrustedVsiInitUuidReservation {
    /// Returns the immutable reserved UUID box bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the manifest identifier represented by the UUID reservation.
    pub fn manifest_id(&self) -> &str {
        &self.manifest_id
    }
}

/// Reserved media EMSG bytes and their public signing metadata.
///
/// Instances will be returned by
/// [`TrustedVsiPrehashedSession::reserve_media_emsg_at`] once that capability
/// is implemented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedVsiMediaEmsgReservation {
    bytes: Vec<u8>,
    signing_time_unix_seconds: i64,
    timescale: u32,
    event_duration: u32,
    signing_context: VsiSigningContextV1,
}

/// Successful terminal reason for a trusted VSI session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrustedVsiExhaustionReason {
    /// The final `u32::MAX` MFHD/VSI sequence was consumed.
    SequenceMax,
    /// The final `u32::MAX` EMSG event identifier was consumed.
    EventIdMax,
    /// A migrated legacy session stopped at the former sequence sentinel.
    LegacySentinel,
}

impl TrustedVsiMediaEmsgReservation {
    /// Returns the immutable reserved EMSG box bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the protected COSE `iat` source time.
    pub const fn signing_time_unix_seconds(&self) -> i64 {
        self.signing_time_unix_seconds
    }

    /// Returns the EMSG timescale.
    pub const fn timescale(&self) -> u32 {
        self.timescale
    }

    /// Returns the EMSG event duration.
    pub const fn event_duration(&self) -> u32 {
        self.event_duration
    }

    /// Returns the callback authorization metadata reserved for this EMSG.
    pub const fn signing_context(&self) -> &VsiSigningContextV1 {
        &self.signing_context
    }
}

/// Public state of a prehashed trusted VSI session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedVsiStatus {
    init_uuid_committed: bool,
    init_uuid_pending: bool,
    media_emsg_pending: bool,
    next_sequence_number: Option<u32>,
    next_event_id: Option<u32>,
    exhausted: bool,
    exhaustion_reason: Option<TrustedVsiExhaustionReason>,
}

impl TrustedVsiStatus {
    /// Returns whether the initialization UUID has been committed as published.
    pub const fn init_uuid_committed(&self) -> bool {
        self.init_uuid_committed
    }

    /// Returns whether an initialization UUID reservation is pending.
    pub const fn init_uuid_pending(&self) -> bool {
        self.init_uuid_pending
    }

    /// Returns whether a media EMSG reservation is pending.
    pub const fn media_emsg_pending(&self) -> bool {
        self.media_emsg_pending
    }

    /// Returns the next media sequence number, or `None` after exhaustion.
    pub const fn next_sequence_number(&self) -> Option<u32> {
        self.next_sequence_number
    }

    /// Returns the next EMSG event identifier, or `None` after exhaustion.
    pub const fn next_event_id(&self) -> Option<u32> {
        self.next_event_id
    }

    /// Returns whether no further media identifiers can be signed.
    pub const fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Returns the successful terminal reason, when exhausted.
    pub const fn exhaustion_reason(&self) -> Option<TrustedVsiExhaustionReason> {
        self.exhaustion_reason
    }
}

/// Reserved state machine for future prehashed trusted VSI signing.
///
/// The callback receives the exact final COSE Sig_structure and a versioned
/// authorization context. It must return a raw COSE signature using the
/// algorithm in [`VsiSessionConfig`]. No constructor or operation is supported
/// by this scaffold; all return [`Error::UnsupportedType`] before invoking the
/// callback or allocating signing state.
pub struct TrustedVsiPrehashedSession {
    _private: (),
}

impl TrustedVsiPrehashedSession {
    /// Returns the prehashed trusted VSI capabilities implemented by this build.
    pub const fn capabilities() -> TrustedVsiCapabilities {
        TrustedVsiCapabilities::current()
    }

    /// Creates a callback-backed prehashed trusted VSI session.
    ///
    /// This scaffold returns [`Error::UnsupportedType`] without inspecting the
    /// context, manifest, configuration, or callback.
    pub fn from_shared_context_with_callback<F>(
        _context: &Arc<Context>,
        _manifest_json: impl Into<String>,
        _config: VsiSessionConfig,
        _callback: F,
    ) -> Result<Self>
    where
        F: Fn(&VsiSigningContextV1, &[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
    {
        Err(Error::UnsupportedType)
    }

    /// Reserves an initialization-segment UUID box for the supplied format.
    pub fn reserve_init_uuid(&mut self, _format: &str) -> Result<TrustedVsiInitUuidReservation> {
        Err(Error::UnsupportedType)
    }

    /// Returns the manifest ID held by the pending initialization reservation.
    pub fn reserved_manifest_id(&self) -> Result<&str> {
        Err(Error::UnsupportedType)
    }

    /// Finalizes the pending UUID using a caller-computed canonical BMFF hash.
    pub fn finalize_init_uuid(&mut self, _canonical_bmff_hash: &[u8]) -> Result<Vec<u8>> {
        Err(Error::UnsupportedType)
    }

    /// Commits the finalized initialization UUID as published.
    pub fn commit_init_uuid(&mut self) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    /// Signs a caller-composed EMSG skeleton and exact COSE Sig_structure.
    pub fn sign_emsg_sig_structure(
        &mut self,
        _emsg_skeleton: &[u8],
        _sig_structure: &[u8],
    ) -> Result<Vec<u8>> {
        Err(Error::UnsupportedType)
    }

    /// Reserves a signer-composed media EMSG at an explicit Unix timestamp.
    pub fn reserve_media_emsg_at(
        &mut self,
        _signing_time_unix_seconds: i64,
        _timescale: u32,
        _event_duration: u32,
    ) -> Result<TrustedVsiMediaEmsgReservation> {
        Err(Error::UnsupportedType)
    }

    /// Finalizes the pending media EMSG using a canonical BMFF hash.
    pub fn finalize_media_emsg(&mut self, _canonical_bmff_hash: &[u8]) -> Result<Vec<u8>> {
        Err(Error::UnsupportedType)
    }

    /// Recovers public state from a signed UUID and optional previous signed EMSG.
    pub fn recover(
        &mut self,
        _signed_uuid_box: &[u8],
        _previous_signed_emsg: Option<&[u8]>,
    ) -> Result<()> {
        Err(Error::UnsupportedType)
    }

    /// Returns the public session status.
    pub fn status(&self) -> Result<TrustedVsiStatus> {
        Err(Error::UnsupportedType)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::SigningAlg;

    fn config() -> VsiSessionConfig {
        VsiSessionConfig {
            algorithm: SigningAlg::Es256,
            kid: b"trusted-vsi-scaffold".to_vec(),
            public_cose_key_cbor: Vec::new(),
            min_sequence_number: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            validity_period_secs: 60,
        }
    }

    #[test]
    fn scaffold_capabilities_are_zero() {
        let capabilities = TrustedVsiPrehashedSession::capabilities();
        assert_eq!(capabilities.bits(), 0);
        assert!(!capabilities.supports_split_init_uuid());
        assert!(!capabilities.supports_expert_emsg_sig_structure());
        assert!(!capabilities.supports_signer_composed_emsg());
        assert!(!capabilities.supports_recovery());
        assert!(!capabilities.supports_signing_context_v1());
        assert!(!capabilities.supports_full_uint32_exhaustion());
    }

    #[test]
    fn scaffold_constructor_is_unsupported_without_callback_invocation() {
        let callback_calls = Arc::new(AtomicUsize::new(0));
        let callback_calls_for_closure = Arc::clone(&callback_calls);
        let result = TrustedVsiPrehashedSession::from_shared_context_with_callback(
            &Context::new().into_shared(),
            "not inspected",
            config(),
            move |_context, _sig_structure| {
                callback_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            },
        );

        assert!(matches!(result, Err(Error::UnsupportedType)));
        assert_eq!(callback_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn scaffold_operations_are_unsupported() {
        let mut session = TrustedVsiPrehashedSession { _private: () };

        assert!(matches!(
            session.reserve_init_uuid("video/mp4"),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.finalize_init_uuid(b"bmff-hash"),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.reserved_manifest_id(),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.commit_init_uuid(),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.sign_emsg_sig_structure(b"emsg", b"sig-structure"),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.reserve_media_emsg_at(0, 1, 1),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.finalize_media_emsg(b"bmff-hash"),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(
            session.recover(b"uuid", Some(b"emsg")),
            Err(Error::UnsupportedType)
        ));
        assert!(matches!(session.status(), Err(Error::UnsupportedType)));
    }
}
