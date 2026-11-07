"""Isolated native compatibility probe, not an automatic qualification gate.

Requires the functional c2pa-python source and its test-helper directory on
PYTHONPATH, and an explicit C2PA_LIBRARY_NAME. See the archived probe evidence.
"""

import io
import json
from pathlib import Path

import cbor2
import c2pa
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import test_trusted_vsi_api as fixture


CREATED = "2026-09-10T00:00:00Z"
KID = b"same-key-epoch-probe"
MANIFEST = {
    "claim_version": 2,
    "format": "video/mp4",
    "assertions": [{
        "label": "c2pa.actions",
        "data": {"actions": [{
            "action": "c2pa.created",
            "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty",
        }]},
    }],
}


def session_key(algorithm):
    if algorithm == "ed25519":
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
        public = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {1: 1, 2: KID, 3: -8, -1: 6, -2: public}, key.sign
    key = ec.derive_private_key(7, ec.SECP256R1())
    public = key.public_key().public_numbers()

    def sign(data):
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    return {
        1: 2, 2: KID, 3: -7, -1: 1,
        -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big"),
    }, sign


def manifest_metadata(asset, context):
    with c2pa.Reader("video/mp4", io.BytesIO(asset), context=context) as reader:
        assert reader.get_validation_state() == "Trusted"
        assert reader.get_validation_results()["activeManifest"]["failure"] == []
        report = json.loads(reader.json())
        active = report["manifests"][report["active_manifest"]]
        assertion = next(a for a in active["assertions"]
                         if a["label"] == "c2pa.session-keys")
        return report["active_manifest"], assertion["data"]["keys"][0]


def with_sequence(media, sequence):
    result = bytearray(media)
    position = result.index(b"mfhd")
    assert int.from_bytes(result[position - 4:position], "big") == 16
    result[position + 8:position + 12] = sequence.to_bytes(4, "big")
    assert c2pa.moof_sequence_number(bytes(result)) == sequence
    return bytes(result)


@pytest.mark.parametrize("algorithm", ["ed25519", "es256"])
@pytest.mark.parametrize("mode", ["complete_buffer", "expert_sig_structure", "signer_composed_emsg"])
def test_new_init_epoch_reuses_key_binding_without_mutating_old_epoch(algorithm, mode):
    assert all(probe() for probe in fixture.PROBES)
    cose, sign = session_key(algorithm)
    resources = []
    binding_tbs = []
    binding_signature = None
    media_calls = []

    def callback(purpose, sequence, data):
        nonlocal binding_signature
        if purpose == "signer_binding":
            binding_tbs.append(data)
            if binding_signature is None:
                binding_signature = sign(data)
            else:
                assert data == binding_tbs[0]
            return binding_signature
        media_calls.append((sequence, data))
        return sign(data)

    try:
        signer = c2pa.Signer.from_info(c2pa.C2paSignerInfo(
            alg=b"es256",
            sign_cert=(fixture.FIXTURES / "es256_certs.pem").read_bytes(),
            private_key=(fixture.FIXTURES / "es256_private.key").read_bytes(),
            ta_url=None))
        resources.append(signer)
        settings = json.loads((Path(fixture.__file__).parent
                               / "trust_config_test_settings.json").read_text())
        settings["builder"] = {"thumbnail": {"enabled": False}}
        context = c2pa.Context.from_dict(settings, signer=signer)
        resources.append(context)
        raw = fixture._unsigned_media()
        minimum = c2pa.moof_sequence_number(raw)
        epochs = []
        event_ids = []

        for index, validity in enumerate((86400, 172800)):
            sequence = minimum + index
            iat = fixture.IAT + index * 86400
            if mode == "complete_buffer":
                session = c2pa.LiveVideoVsiSession.from_callback(
                    MANIFEST, context, callback, algorithm,
                    cbor2.dumps(cose, canonical=True), KID, sequence, CREATED, validity)
                resources.append(session)
                asset = session.sign_init_segment(fixture._unsigned_init())
            else:
                def trusted_callback(cx, data):
                    return callback(cx.purpose, cx.sequence_number, data)

                session = c2pa.TrustedVsiSession.from_callback(
                    context, MANIFEST, algorithm, cbor2.dumps(cose, canonical=True),
                    KID, sequence, CREATED, validity, trusted_callback,
                    mode=mode, reservation_nonce=("1" if index == 0 else "2") * 32,
                    signing_time_unix_seconds=iat)
                resources.append(session)
                if index:
                    fresh_state = session.export_state()
                    with pytest.raises(c2pa.C2paError):
                        session.import_state(epochs[0][0].export_state())
                    assert session.export_state() == fresh_state
                asset, _ = fixture._init(session)

            manifest_id, metadata = manifest_metadata(asset, context)
            assert metadata["minSequenceNumber"] == sequence
            assert metadata["validityPeriod"] == validity
            epochs.append((session, asset, manifest_id, metadata))

            media = with_sequence(raw, sequence)
            if mode == "complete_buffer":
                signed = session.sign_media_segment_at(media, iat)
                emsg = next(box for _, kind, box in fixture._boxes(signed) if kind == b"emsg")
                _, timing, _ = fixture._parse_vsi_emsg(emsg)
                event_ids.append(timing[3])
                assert session.next_sequence_number == sequence + 1
            elif mode == "signer_composed_emsg":
                reserved = session.reserve_media_emsg_at(sequence, iat, 1000, 2000)
                canonical = fixture._hash_input(
                    fixture.KIND.MEDIA_HASH, fixture._place(media, reserved.placeholder_emsg_box))
                emsg = session.finalize_media_emsg(canonical)
                _, timing, _ = fixture._parse_vsi_emsg(emsg)
                event_ids.append(timing[3])
                assert session.status().next_sequence_number == sequence + 1
            else:
                protected = cbor2.dumps({1: cose[3], "iat": iat}, canonical=True)
                payload = cbor2.dumps({
                    "sequenceNumber": sequence,
                    "manifestId": manifest_id,
                    "bmffHash": cbor2.loads(c2pa.trusted_vsi_hash_template(fixture.KIND.MEDIA_HASH)),
                }, canonical=True)
                tbs = cbor2.dumps(["Signature1", protected, b"", payload], canonical=True)
                assert len(session.sign_sig_structure(tbs, sequence)) == 64
                assert session.status().next_event_id is None

        assert len(binding_tbs) == 2 and binding_tbs[0] == binding_tbs[1]
        assert epochs[0][2] != epochs[1][2]
        assert epochs[0][3]["createdAt"] == epochs[1][3]["createdAt"]
        assert epochs[0][3]["key"] == epochs[1][3]["key"]
        assert epochs[0][3]["signerBinding"] == epochs[1][3]["signerBinding"]
        assert manifest_metadata(epochs[0][1], context) == (epochs[0][2], epochs[0][3])
        assert len(media_calls) == 2
        if mode != "expert_sig_structure":
            assert event_ids == [1, 1], "Current native API restarts event IDs on fresh handles"
            before = len(media_calls)
            with pytest.raises(c2pa.C2paError):
                if mode == "complete_buffer":
                    epochs[0][0].sign_media_segment_at(
                        with_sequence(raw, minimum + 1), fixture.IAT + 86400)
                else:
                    epochs[0][0].reserve_media_emsg_at(
                        minimum + 1, fixture.IAT + 86400, 1000, 2000)
            assert len(media_calls) == before
        print(json.dumps({
            "algorithm": algorithm, "mode": mode,
            "same_key": True, "same_binding_tbs": True, "cached_binding_reused": True,
            "distinct_manifests": True, "physical_created_at_preserved": True,
            "signed_validity_periods": [86400, 172800],
            "media_sequences": [minimum, minimum + 1], "event_ids": event_ids,
            "old_epoch_unchanged": True, "sdk_version": c2pa.sdk_version(),
        }, sort_keys=True))
    finally:
        for resource in reversed(resources):
            resource.close()
