# VSI Updates In Signer 1.0.8

The operator approved including the VSI update work in the still-unpublished
signer 1.0.8 release, subject to qualification and review. Qualification runs on
GitHub-hosted CI, not local builds. This is an integration plan, not release
approval or evidence that the combined candidate has passed.

## Native Scope

- [#27](https://github.com/castlabs/c2pa-rs/pull/27): BMFF extra exclusions,
  ZIP 9.0.4 remediation and WASI test fixes. The owning agent merged final head
  `33721e6a` into `feat/trusted-vsi-functional` as `6ce147fb`. Do not rewrite its
  branch or duplicate its merge. The dependency-fix integration hold is lifted;
  #28/#29 still require checks on this updated base before their source merges.
- [#28](https://github.com/castlabs/c2pa-rs/pull/28): verified init refresh fix
  and Reader-trusted transition tests, targeting `feat/trusted-vsi-functional`.
- [#29](https://github.com/castlabs/c2pa-rs/pull/29): explicit CLI update schedules,
  stacked on #28. Merge #28 first and carry #29 into the same functional line.

Use true merge commits. No rebase, cherry-pick, force-push, or dependency on the
independent mstattma #38/#39/#40 proposals is needed for this Castlabs release.

## CI Gates

The normal tier workflows exclude `unstable_live_video`; they do not establish
that the update API or CLI update path works.

`.github/workflows/vsi-update-validation.yml` runs the focused SDK live-video
suite with isolated native-crypto and OpenSSL backends, library Clippy,
feature-off checks, and CLI tests/Clippy including subprocess output regressions.
It uses the declared Castlabs SDK MSRV, Rust 1.96.0.

`.github/workflows/castlabs-live-video-qualification.yml` qualifies Linux and
Windows SDK/FFI/CLI profiles, builds same-source native/CLI bundles, and records
source-bound evidence. Dispatch it with `publish_release=false`; test-only
qualification must not publish a release.

Both workflows run on functional-branch pushes. After all three changes reach
that line, select an exact native SHA and use its push-triggered runs, or rerun
both workflows on that SHA's branch ref. Confirm the run's `headSha`
and recorded source identity match the selected candidate. Per-PR runs are useful
but do not replace qualification of the combined tree. If the ref advances,
qualify the new SHA before updating dependency evidence.

Record and resolve remaining dependency audit failures separately; do not
suppress inherited advisories to make the update PRs appear green.

## Dependency And Signer Adoption

1. Produce a newly versioned, approved `c2pa-python` prerelease containing the
   qualified native candidate. Do not replace the immutable dev2 release.
2. Update signer `release/1.0.8` dependency declarations, release input, lockfile,
   source facts and artifact approval together. Preserve the release owner's
   other changes; do not use the older signer functional branch as the candidate.
3. Build the bundled `c2patool` from the same native SHA, Cargo.lock and toolchain
   identified by the dependency evidence. Do not substitute an independently
   built CLI.
4. Requalify installed signer artifacts and complete independent review before
   publication. Publishing 1.0.8 still requires explicit authorization.

The update work adds a native Rust verification API and the CLI's offline
`--updates` schedule. It does not add a persistent Python/browser receiver API,
signed numbering restarts, or a historical manifest/key cache.
