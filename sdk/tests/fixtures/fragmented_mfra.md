# Fragmented MP4 TFRA Fixture

`fragmented_mfra.mp4` is Bibin's original regression fixture from
[PR #1](https://github.com/mstattma/c2pa-rs/pull/1), commit
`6c1328cd83fe170123cf630a5a15b049a384c063`. It was imported unchanged from that
commit. The original description identifies an ffmpeg `testsrc` video with
five fragments; an exact generation command is not recorded here.

The fixture exercises preservation of the intended `moof` targets in `mfra/tfra`
when a C2PA manifest is inserted, grown, shrunk, or removed. Its one-entry-per-moof
layout is specific to this fixture, not a general TFRA requirement.
