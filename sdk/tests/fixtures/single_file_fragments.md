# Single-File Fragment Fixtures

Generated with FFmpeg 6.1.1, from the built-in synthetic `testsrc2` source:

```sh
ffmpeg -hide_banner -loglevel error -f lavfi -i testsrc2=size=32x32:rate=2 -t 3 -c:v libx264 -threads 1 -g 2 -bf 0 -movflags +empty_moov+frag_keyframe+default_base_moof+global_sidx -y single_file_fragments.mp4
ffmpeg -hide_banner -loglevel error -f lavfi -i testsrc2=size=32x32:rate=2 -t 3 -c:v libx264 -threads 1 -g 2 -bf 0 -movflags +empty_moov+frag_keyframe -y single_file_fragments_absolute.mp4
```

Both contain an initialization prefix, three H.264 moof/mdat fragments, and an
mfra with three tfra entries. The first uses default-base-is-moof and a global
sidx; the second uses explicit absolute tfhd bases. FFmpeg 6.1.1's global_sidx
pass does not relocate absolute tfhd bases correctly, so it is intentionally
not used for the second fixture. Both fixtures decode successfully.
Tests use the committed bytes and do not require FFmpeg.

Post-audit regressions also repeat real encoded fragments with advancing mfhd
sequence numbers and tfdt decode times to exercise 25- and 257-fragment trees.
They check equal UUID sizes across CBOR integer-width changes, independent
auxiliary-locator and tkhd/localId parsing, suffix hashing through EOF, and
tfra preservation during XMP insertion/replacement and manifest removal.

Single-file signing uses a leaf-row Merkle map, bounded by
`core.merkle_tree_max_leaves` (default 10,000) and the hash-memory budget.
It requires one stable tkhd/tfhd track, using its track ID as localId. Multiplexed
or changing track layouts fail explicitly. It rejects implicit tfhd bases,
cross-fragment sample references, hybrid
initialization samples, auxiliary-offset boxes (saio/iloc), ssix and hierarchical
sidx. Existing Merkle-bound files require an update manifest: rebuilding their
UUID maps while retaining older bindings is not currently supported. Legacy
flat-bound fragmented files remain verifiable and can be re-signed.
