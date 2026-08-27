// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

//! Checked ISO BMFF parsing for the Milestone 1 live-video profile.

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct InitSegmentInfo {
    pub track_id: u32,
    pub timescale: u32,
    pub default_sample_duration: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MediaSegmentInfo {
    pub sequence_number: u32,
    pub track_id: u32,
    pub duration_ticks: u32,
}

#[derive(Clone, Copy)]
struct BmffBox<'a> {
    box_type: [u8; 4],
    payload: &'a [u8],
}

pub(super) fn parse_init_segment(data: &[u8]) -> Result<InitSegmentInfo> {
    let top_level = parse_boxes(data, "initialization segment")?;
    if top_level.iter().any(|b| b.box_type == *b"mdat") {
        return Err(Error::BadParam(
            "initialization segment must not contain an mdat box".to_string(),
        ));
    }

    let moov = exactly_one(&top_level, b"moov", "initialization segment")?;
    let moov_children = parse_boxes(moov.payload, "moov")?;
    let trak = exactly_one(&moov_children, b"trak", "moov")?;
    let trak_children = parse_boxes(trak.payload, "trak")?;

    let tkhd = exactly_one(&trak_children, b"tkhd", "trak")?;
    let track_id = parse_tkhd_track_id(tkhd.payload)?;

    let mdia = exactly_one(&trak_children, b"mdia", "trak")?;
    let mdia_children = parse_boxes(mdia.payload, "mdia")?;
    let mdhd = exactly_one(&mdia_children, b"mdhd", "mdia")?;
    let timescale = parse_mdhd_timescale(mdhd.payload)?;

    let default_sample_duration = match at_most_one(&moov_children, b"mvex", "moov")? {
        Some(mvex) => {
            let mvex_children = parse_boxes(mvex.payload, "mvex")?;
            let trex = exactly_one(&mvex_children, b"trex", "mvex")?;
            let (trex_track_id, duration) = parse_trex(trex.payload)?;
            if trex_track_id != track_id {
                return Err(Error::BadParam(
                    "trex track_ID does not match the initialization track".to_string(),
                ));
            }
            duration
        }
        None => None,
    };

    Ok(InitSegmentInfo {
        track_id,
        timescale,
        default_sample_duration,
    })
}

pub(super) fn parse_media_segment(
    data: &[u8],
    init_default_sample_duration: Option<u32>,
) -> Result<MediaSegmentInfo> {
    let top_level = parse_boxes(data, "media segment")?;
    let moof = exactly_one(&top_level, b"moof", "media segment")?;
    let moof_children = parse_boxes(moof.payload, "moof")?;

    let mfhd = exactly_one(&moof_children, b"mfhd", "moof")?;
    let sequence_number = parse_mfhd_sequence_number(mfhd.payload)?;

    // Milestone 1 intentionally supports one media track and one traf only.
    let traf = exactly_one(&moof_children, b"traf", "moof")?;
    let traf_children = parse_boxes(traf.payload, "traf")?;
    let tfhd = exactly_one(&traf_children, b"tfhd", "traf")?;
    let (track_id, tfhd_default_sample_duration) = parse_tfhd(tfhd.payload)?;
    let default_sample_duration = tfhd_default_sample_duration.or(init_default_sample_duration);

    let truns: Vec<_> = traf_children
        .iter()
        .filter(|b| b.box_type == *b"trun")
        .collect();
    if truns.is_empty() {
        return Err(Error::BadParam(
            "media segment traf must contain at least one trun box".to_string(),
        ));
    }

    let mut duration_ticks = 0u64;
    for trun in truns {
        duration_ticks = duration_ticks
            .checked_add(parse_trun_duration(trun.payload, default_sample_duration)?)
            .ok_or_else(|| Error::BadParam("media segment duration overflow".to_string()))?;
    }
    let duration_ticks = u32::try_from(duration_ticks).map_err(|_| {
        Error::BadParam("media segment duration does not fit in an emsg event_duration".to_string())
    })?;
    if duration_ticks == 0 {
        return Err(Error::BadParam(
            "media segment duration must be greater than zero".to_string(),
        ));
    }

    Ok(MediaSegmentInfo {
        sequence_number,
        track_id,
        duration_ticks,
    })
}

pub(super) fn moof_sequence_number(data: &[u8]) -> Option<u32> {
    let top_level = parse_boxes(data, "media segment").ok()?;
    let moof = exactly_one(&top_level, b"moof", "media segment").ok()?;
    let moof_children = parse_boxes(moof.payload, "moof").ok()?;
    let mfhd = exactly_one(&moof_children, b"mfhd", "moof").ok()?;
    // Milestone 1 rejects muxed/multi-traf media even for sequence inference.
    exactly_one(&moof_children, b"traf", "moof").ok()?;
    parse_mfhd_sequence_number(mfhd.payload).ok()
}

fn parse_boxes<'a>(data: &'a [u8], parent: &str) -> Result<Vec<BmffBox<'a>>> {
    let mut boxes = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let header = data
            .get(
                pos..pos.checked_add(8).ok_or_else(|| {
                    Error::BadParam(format!("{parent} BMFF box header offset overflow"))
                })?,
            )
            .ok_or_else(|| {
                Error::BadParam(format!("{parent} contains a truncated BMFF box header"))
            })?;
        let size32 = u32::from_be_bytes(header[0..4].try_into().map_err(|_| Error::NotFound)?);
        let box_type: [u8; 4] = header[4..8].try_into().map_err(|_| Error::NotFound)?;

        let (header_len, box_size) = match size32 {
            0 => (8usize, data.len() - pos),
            1 => {
                let large_end = pos.checked_add(16).ok_or_else(|| {
                    Error::BadParam(format!("{parent} large-size box header overflow"))
                })?;
                let large = data.get(pos + 8..large_end).ok_or_else(|| {
                    Error::BadParam(format!(
                        "{parent} contains a truncated large-size box header"
                    ))
                })?;
                let size = usize::try_from(u64::from_be_bytes(
                    large.try_into().map_err(|_| Error::NotFound)?,
                ))
                .map_err(|_| Error::BadParam(format!("{parent} box size is unsupported")))?;
                (16, size)
            }
            size => (8, size as usize),
        };

        if box_size < header_len {
            return Err(Error::BadParam(format!(
                "{parent} contains a BMFF box smaller than its header"
            )));
        }
        let end = pos.checked_add(box_size).ok_or_else(|| {
            Error::BadParam(format!("{parent} BMFF box size overflows the input"))
        })?;
        if end > data.len() {
            return Err(Error::BadParam(format!(
                "{parent} contains a BMFF box extending beyond the input"
            )));
        }

        boxes.push(BmffBox {
            box_type,
            payload: &data[pos + header_len..end],
        });
        pos = end;
    }

    Ok(boxes)
}

fn exactly_one<'a>(
    boxes: &'a [BmffBox<'a>],
    box_type: &[u8; 4],
    parent: &str,
) -> Result<BmffBox<'a>> {
    let mut matches = boxes.iter().filter(|b| b.box_type == *box_type);
    let found = matches.next().copied().ok_or_else(|| {
        Error::BadParam(format!(
            "{parent} must contain exactly one {} box",
            String::from_utf8_lossy(box_type)
        ))
    })?;
    if matches.next().is_some() {
        return Err(Error::BadParam(format!(
            "{parent} must contain exactly one {} box; muxed/multi-track live video is not supported in Milestone 1",
            String::from_utf8_lossy(box_type)
        )));
    }
    Ok(found)
}

fn at_most_one<'a>(
    boxes: &'a [BmffBox<'a>],
    box_type: &[u8; 4],
    parent: &str,
) -> Result<Option<BmffBox<'a>>> {
    let mut matches = boxes.iter().filter(|b| b.box_type == *box_type);
    let found = matches.next().copied();
    if matches.next().is_some() {
        return Err(Error::BadParam(format!(
            "{parent} must not contain multiple {} boxes",
            String::from_utf8_lossy(box_type)
        )));
    }
    Ok(found)
}

fn full_box<'a>(payload: &'a [u8], name: &str) -> Result<(u8, u32, &'a [u8])> {
    let header = payload
        .get(..4)
        .ok_or_else(|| Error::BadParam(format!("{name} box is truncated")))?;
    let flags = u32::from_be_bytes([0, header[1], header[2], header[3]]);
    Ok((header[0], flags, &payload[4..]))
}

fn parse_tkhd_track_id(payload: &[u8]) -> Result<u32> {
    let (version, _, fields) = full_box(payload, "tkhd")?;
    let offset = match version {
        0 => 8,
        1 => 16,
        _ => return Err(Error::BadParam("unsupported tkhd version".to_string())),
    };
    let track_id = read_u32(fields, offset, "tkhd track_ID")?;
    if track_id == 0 {
        return Err(Error::BadParam(
            "tkhd track_ID must not be zero".to_string(),
        ));
    }
    Ok(track_id)
}

fn parse_mdhd_timescale(payload: &[u8]) -> Result<u32> {
    let (version, _, fields) = full_box(payload, "mdhd")?;
    let offset = match version {
        0 => 8,
        1 => 16,
        _ => return Err(Error::BadParam("unsupported mdhd version".to_string())),
    };
    let timescale = read_u32(fields, offset, "mdhd timescale")?;
    if timescale == 0 {
        return Err(Error::BadParam(
            "mdhd timescale must be greater than zero".to_string(),
        ));
    }
    Ok(timescale)
}

fn parse_mfhd_sequence_number(payload: &[u8]) -> Result<u32> {
    let (version, flags, fields) = full_box(payload, "mfhd")?;
    if version != 0 || flags != 0 {
        return Err(Error::BadParam(
            "mfhd must use version 0 with zero flags".to_string(),
        ));
    }
    read_u32(fields, 0, "mfhd sequence_number")
}

fn parse_trex(payload: &[u8]) -> Result<(u32, Option<u32>)> {
    let (version, flags, fields) = full_box(payload, "trex")?;
    if version != 0 || flags != 0 || fields.len() != 20 {
        return Err(Error::BadParam(
            "trex must use the supported version 0 layout".to_string(),
        ));
    }
    let track_id = read_u32(fields, 0, "trex track_ID")?;
    if track_id == 0 {
        return Err(Error::BadParam(
            "trex track_ID must not be zero".to_string(),
        ));
    }
    let duration = read_u32(fields, 8, "trex default_sample_duration")?;
    Ok((track_id, (duration != 0).then_some(duration)))
}

fn parse_tfhd(payload: &[u8]) -> Result<(u32, Option<u32>)> {
    const ALLOWED_FLAGS: u32 = 0x03003b;
    const DURATION_IS_EMPTY: u32 = 0x010000;

    let (version, flags, fields) = full_box(payload, "tfhd")?;
    if version != 0 {
        return Err(Error::BadParam("unsupported tfhd version".to_string()));
    }
    if flags & !ALLOWED_FLAGS != 0 || flags & DURATION_IS_EMPTY != 0 {
        return Err(Error::BadParam(
            "tfhd uses unsupported flags for Milestone 1 live video".to_string(),
        ));
    }

    let track_id = read_u32(fields, 0, "tfhd track_ID")?;
    if track_id == 0 {
        return Err(Error::BadParam(
            "tfhd track_ID must not be zero".to_string(),
        ));
    }
    let mut pos = 4usize;
    if flags & 0x000001 != 0 {
        pos = checked_skip(fields, pos, 8, "tfhd base_data_offset")?;
    }
    if flags & 0x000002 != 0 {
        pos = checked_skip(fields, pos, 4, "tfhd sample_description_index")?;
    }
    let default_sample_duration = if flags & 0x000008 != 0 {
        let duration = read_u32(fields, pos, "tfhd default_sample_duration")?;
        pos = checked_skip(fields, pos, 4, "tfhd default_sample_duration")?;
        if duration == 0 {
            return Err(Error::BadParam(
                "tfhd default_sample_duration must be greater than zero".to_string(),
            ));
        }
        Some(duration)
    } else {
        None
    };
    if flags & 0x000010 != 0 {
        pos = checked_skip(fields, pos, 4, "tfhd default_sample_size")?;
    }
    if flags & 0x000020 != 0 {
        pos = checked_skip(fields, pos, 4, "tfhd default_sample_flags")?;
    }
    if pos != fields.len() {
        return Err(Error::BadParam(
            "tfhd contains unexpected trailing bytes".to_string(),
        ));
    }
    Ok((track_id, default_sample_duration))
}

fn parse_trun_duration(payload: &[u8], default_sample_duration: Option<u32>) -> Result<u64> {
    const ALLOWED_FLAGS: u32 = 0x000f05;

    let (version, flags, fields) = full_box(payload, "trun")?;
    if version > 1 || flags & !ALLOWED_FLAGS != 0 {
        return Err(Error::BadParam(
            "trun uses an unsupported version or flags".to_string(),
        ));
    }
    let sample_count = read_u32(fields, 0, "trun sample_count")?;
    if sample_count == 0 {
        return Err(Error::BadParam(
            "trun sample_count must be greater than zero".to_string(),
        ));
    }

    let mut pos = 4usize;
    if flags & 0x000001 != 0 {
        pos = checked_skip(fields, pos, 4, "trun data_offset")?;
    }
    if flags & 0x000004 != 0 {
        pos = checked_skip(fields, pos, 4, "trun first_sample_flags")?;
    }

    let sample_duration_present = flags & 0x000100 != 0;
    let per_sample_field_count = [0x000100, 0x000200, 0x000400, 0x000800]
        .iter()
        .filter(|flag| flags & **flag != 0)
        .count();
    let per_sample_width = per_sample_field_count
        .checked_mul(4)
        .ok_or_else(|| Error::BadParam("trun per-sample field width overflow".to_string()))?;
    let sample_count_usize = usize::try_from(sample_count)
        .map_err(|_| Error::BadParam("trun sample_count is unsupported".to_string()))?;
    let sample_bytes = sample_count_usize
        .checked_mul(per_sample_width)
        .ok_or_else(|| Error::BadParam("trun sample table size overflow".to_string()))?;
    let expected_end = pos
        .checked_add(sample_bytes)
        .ok_or_else(|| Error::BadParam("trun sample table offset overflow".to_string()))?;
    if expected_end != fields.len() {
        return Err(Error::BadParam(
            "trun sample table length does not match sample_count and flags".to_string(),
        ));
    }

    if !sample_duration_present {
        let default_duration = default_sample_duration.ok_or_else(|| {
            Error::BadParam(
                "trun omits sample durations and tfhd has no default_sample_duration".to_string(),
            )
        })?;
        return u64::from(default_duration)
            .checked_mul(u64::from(sample_count))
            .ok_or_else(|| Error::BadParam("trun duration overflow".to_string()));
    }

    let mut duration = 0u64;
    for _ in 0..sample_count {
        let sample_duration = read_u32(fields, pos, "trun sample_duration")?;
        pos = checked_skip(fields, pos, 4, "trun sample_duration")?;
        if sample_duration == 0 {
            return Err(Error::BadParam(
                "trun sample_duration must be greater than zero".to_string(),
            ));
        }
        duration = duration
            .checked_add(u64::from(sample_duration))
            .ok_or_else(|| Error::BadParam("trun duration overflow".to_string()))?;

        for (flag, name) in [
            (0x000200, "trun sample_size"),
            (0x000400, "trun sample_flags"),
            (0x000800, "trun sample_composition_time_offset"),
        ] {
            if flags & flag != 0 {
                pos = checked_skip(fields, pos, 4, name)?;
            }
        }
    }
    debug_assert_eq!(pos, fields.len());
    Ok(duration)
}

fn checked_skip(data: &[u8], pos: usize, count: usize, field: &str) -> Result<usize> {
    let end = pos
        .checked_add(count)
        .ok_or_else(|| Error::BadParam(format!("{field} offset overflow")))?;
    if end > data.len() {
        return Err(Error::BadParam(format!("{field} is truncated")));
    }
    Ok(end)
}

fn read_u32(data: &[u8], pos: usize, field: &str) -> Result<u32> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| Error::BadParam(format!("{field} offset overflow")))?;
    let bytes = data
        .get(pos..end)
        .ok_or_else(|| Error::BadParam(format!("{field} is truncated")))?;
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| Error::NotFound)?,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn make_box(box_type: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&u32::try_from(8 + payload.len()).unwrap().to_be_bytes());
        data.extend_from_slice(box_type);
        data.extend_from_slice(payload);
        data
    }

    fn make_full_box(box_type: &[u8; 4], flags: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        body.extend_from_slice(&flags.to_be_bytes()[1..]);
        body.extend_from_slice(payload);
        make_box(box_type, &body)
    }

    fn media_segment(sequence: u32, traf_count: usize) -> Vec<u8> {
        let mfhd = make_full_box(b"mfhd", 0, &sequence.to_be_bytes());
        let mut tfhd_payload = 1u32.to_be_bytes().to_vec();
        tfhd_payload.extend_from_slice(&1000u32.to_be_bytes());
        let tfhd = make_full_box(b"tfhd", 0x000008, &tfhd_payload);
        let trun = make_full_box(b"trun", 0, &2u32.to_be_bytes());
        let traf = make_box(b"traf", &[tfhd, trun].concat());
        let mut moof_payload = mfhd;
        for _ in 0..traf_count {
            moof_payload.extend_from_slice(&traf);
        }
        [make_box(b"moof", &moof_payload), make_box(b"mdat", &[])].concat()
    }

    #[test]
    fn parses_single_traf_media_timing() {
        assert_eq!(
            parse_media_segment(&media_segment(7, 1), None).unwrap(),
            MediaSegmentInfo {
                sequence_number: 7,
                track_id: 1,
                duration_ticks: 2000,
            }
        );
    }

    #[test]
    fn rejects_multiple_traf_boxes() {
        let error = parse_media_segment(&media_segment(7, 2), None).unwrap_err();
        assert!(error.to_string().contains("exactly one traf"));
    }

    #[test]
    fn rejects_truncated_and_undersized_boxes_without_panicking() {
        assert!(parse_media_segment(&[0, 0, 0, 1, b'm', b'o', b'o', b'f'], None).is_err());
        assert!(parse_media_segment(&[0, 0, 0, 4, b'm', b'o', b'o', b'f'], None).is_err());
    }

    #[test]
    fn rejects_impossible_sample_table_without_iterating_sample_count() {
        let mfhd = make_full_box(b"mfhd", 0, &1u32.to_be_bytes());
        let tfhd = make_full_box(b"tfhd", 0, &1u32.to_be_bytes());
        let trun = make_full_box(b"trun", 0x000100, &u32::MAX.to_be_bytes());
        let traf = make_box(b"traf", &[tfhd, trun].concat());
        let segment = [
            make_box(b"moof", &[mfhd, traf].concat()),
            make_box(b"mdat", &[]),
        ]
        .concat();

        let error = parse_media_segment(&segment, None).unwrap_err();
        assert!(error.to_string().contains("sample table length"));
    }
}
