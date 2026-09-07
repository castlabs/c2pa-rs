#!/usr/bin/env python3
"""Build reproducible Castlabs live-video qualification evidence and bundles."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence


SCHEMA = "https://castlabs.com/schemas/c2pa-rs-live-video-source-qualification/v2"
SCHEMA_VERSION = 2
COMMAND_SCHEMA = "https://castlabs.com/schemas/c2pa-rs-cargo-command-manifest/v1"
REPOSITORY = "https://github.com/castlabs/c2pa-rs"
TOOLCHAIN = "1.88.0"
RUSTFMT_TOOLCHAIN = "nightly-2026-01-16"
PYTHON_VERSION = "3.12"
CARGO_BUILD_JOBS = 1
SDK_MANIFEST = "sdk/Cargo.toml"
FFI_MANIFEST = "c2pa_c_ffi/Cargo.toml"
TOOL_MANIFEST = "cli/Cargo.toml"
SDK_FEATURES = (
    "rust_native_crypto",
    "http_reqwest",
    "http_reqwest_blocking",
    "add_thumbnails",
    "file_io",
    "fetch_remote_manifests",
    "pdf",
    "unstable_live_video",
)
FFI_FEATURES = (
    "rust_native_crypto",
    "http",
    "add_thumbnails",
    "file_io",
    "unstable_live_video",
)
# c2patool retains its default `networking` feature. Its fixed c2pa dependency
# enables the SDK's vendored OpenSSL profile; only live video is added here.
TOOL_FEATURES = ("unstable_live_video",)
SDK_FEATURE_PROFILE = "no-default-rust-native-crypto"
FFI_FEATURE_PROFILE = "no-default-rust-native-crypto"
TOOL_FEATURE_PROFILE = "default-networking-vendored-openssl"
SUPPORTED_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
)
TARGET_ARTIFACT_SPECS = {
    "x86_64-unknown-linux-gnu": {
        "native": {
            "fileName": "libc2pa_c.so",
            "archivePath": "lib/libc2pa_c.so",
            "role": "c-ffi-shared-library",
        },
        "c2patool": {
            "fileName": "c2patool",
            "archivePath": "bin/c2patool",
            "role": "c2patool-executable",
        },
        "header": {
            "fileName": "c2pa.h",
            "archivePath": "include/c2pa.h",
            "role": "c-ffi-generated-header",
        },
    },
    "x86_64-pc-windows-msvc": {
        "native": {
            "fileName": "c2pa_c.dll",
            "archivePath": "lib/c2pa_c.dll",
            "role": "c-ffi-shared-library",
        },
        "importLibrary": {
            "fileName": "c2pa_c.dll.lib",
            "archivePath": "lib/c2pa_c.dll.lib",
            "role": "c-ffi-msvc-import-library",
        },
        "c2patool": {
            "fileName": "c2patool.exe",
            "archivePath": "bin/c2patool.exe",
            "role": "c2patool-executable",
        },
        "header": {
            "fileName": "c2pa.h",
            "archivePath": "include/c2pa.h",
            "role": "c-ffi-generated-header",
        },
    },
}
REQUIRED_SYMBOLS = (
    "c2pa_signer_add_dynamic_assertion",
    "c2pa_reader_from_fragmented_files",
    "c2pa_reader_from_fragmented_files_context",
    "c2pa_builder_sign_fragmented",
    "c2pa_live_video_vsi_signer_create_ed25519",
    "c2pa_live_video_vsi_signer_sign_init_segment",
    "c2pa_live_video_vsi_signer_sign_media_segment",
    "c2pa_live_video_vsi_signer_next_sequence_number",
    "c2pa_live_video_vsi_signer_active_manifest_id",
    "c2pa_live_video_vsi_signer_create_callback",
    "c2pa_live_video_vsi_signer_recover",
    "c2pa_live_video_vsi_signer_sign_media_segment_at",
    "c2pa_live_video_moof_sequence_number",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _features_csv(features: Sequence[str]) -> str:
    return ",".join(features)


def feature_configuration(
    kind: str,
) -> tuple[str, str, tuple[str, ...], bool, str]:
    configurations = {
        "sdk": (
            "c2pa",
            SDK_MANIFEST,
            SDK_FEATURES,
            True,
            SDK_FEATURE_PROFILE,
        ),
        "ffi": (
            "c2pa-c-ffi",
            FFI_MANIFEST,
            FFI_FEATURES,
            True,
            FFI_FEATURE_PROFILE,
        ),
        "c2patool": (
            "c2patool",
            TOOL_MANIFEST,
            TOOL_FEATURES,
            False,
            TOOL_FEATURE_PROFILE,
        ),
    }
    return configurations[kind]


def artifact_build_path(target: str, logical_name: str) -> str:
    file_name = TARGET_ARTIFACT_SPECS[target][logical_name]["fileName"]
    return f"target/{target}/release/{file_name}"


def _package_cargo_command(action: str, kind: str, target: str) -> list[str]:
    _, manifest, features, no_default, _ = feature_configuration(kind)
    command = ["cargo", f"+{TOOLCHAIN}", action, "--locked"]
    if action == "test" and kind == "sdk":
        command.extend(("--lib", "--test", "bmff_timed_media_merkle"))
    if action == "build":
        command.append("--release")
    command.extend(("--manifest-path", manifest, "--target", target))
    if no_default:
        command.append("--no-default-features")
    command.extend(("--features", _features_csv(features)))
    return command


def _feature_report_command(kind: str, target: str) -> list[str]:
    package, manifest, features, no_default, _ = feature_configuration(kind)
    command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "tree",
        "--locked",
        "--manifest-path",
        manifest,
        "--package",
        package,
        "--target",
        target,
        "--edges",
        "features",
        "--charset",
        "ascii",
        "--format",
        "{p}_features=[{f}]",
    ]
    if no_default:
        command.append("--no-default-features")
    command.extend(("--features", _features_csv(features)))
    return command


def _recorded_command(command: Sequence[str], output: str | None = None) -> str:
    rendered = " ".join(command)
    if output is not None:
        rendered += f" > {output}"
    return f"CARGO_BUILD_JOBS={CARGO_BUILD_JOBS} {rendered}"


def cargo_commands(target: str) -> list[str]:
    work = f"qualification-work/{target}"
    return [
        _recorded_command(
            (
                "cargo",
                f"+{TOOLCHAIN}",
                "metadata",
                "--locked",
                "--manifest-path",
                "Cargo.toml",
                "--format-version",
                "1",
                "--no-deps",
            ),
            "/dev/null",
        ),
        _recorded_command(
            ("cargo", f"+{RUSTFMT_TOOLCHAIN}", "fmt", "--all", "--", "--check")
        ),
        _recorded_command(_package_cargo_command("test", "sdk", target)),
        _recorded_command(_package_cargo_command("test", "ffi", target)),
        _recorded_command(_package_cargo_command("test", "c2patool", target)),
        _recorded_command(
            _feature_report_command("sdk", target), f"{work}/sdk-features.txt"
        ),
        _recorded_command(
            _feature_report_command("ffi", target), f"{work}/ffi-features.txt"
        ),
        _recorded_command(
            _feature_report_command("c2patool", target),
            f"{work}/c2patool-features.txt",
        ),
        _recorded_command(_package_cargo_command("build", "ffi", target)),
        _recorded_command(_package_cargo_command("build", "c2patool", target)),
    ]


def command_manifest_data(target: str) -> dict[str, object]:
    if target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported qualification target: {target}")
    return {
        "schema": COMMAND_SCHEMA,
        "schemaVersion": 1,
        "target": target,
        "cargoBuildJobs": CARGO_BUILD_JOBS,
        "commands": cargo_commands(target),
    }


def _json_bytes(data: object) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_command_manifest(target: str, output: Path) -> None:
    _write_new_files(((output, _json_bytes(command_manifest_data(target))),))


def _validate_command_manifest(data: object, target: str) -> list[str]:
    expected = command_manifest_data(target)
    if data != expected:
        raise ValueError("Cargo command manifest does not match qualification commands")
    commands = expected["commands"]
    assert isinstance(commands, list)
    return commands


def load_command_manifest(path: Path, target: str) -> list[str]:
    if path.name != "cargo-commands.json" or not path.is_file() or path.is_symlink():
        raise ValueError(
            f"command manifest must be a regular cargo-commands.json: {path}"
        )
    try:
        data = json.loads(path.read_bytes())
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid Cargo command manifest: {path}") from error
    return _validate_command_manifest(data, target)


def _readobj_blocks(text: str, kind: str) -> list[str]:
    return re.findall(rf"(?ms)^[ \t]*{re.escape(kind)}[ \t]*\{{(.*?)^[ \t]*\}}", text)


def _block_name(block: str) -> str | None:
    match = re.search(r"(?m)^[ \t]*Name:[ \t]+([^\s(]+)", block)
    return match.group(1).lstrip("_") if match is not None else None


def parse_elf_exported_symbols(text: str) -> set[str]:
    symbols = set()
    row = re.compile(
        r"(?m)^\s*\d+:\s+\S+\s+\d+\s+(FUNC|IFUNC)\s+"
        r"(GLOBAL|WEAK)\s+(DEFAULT|PROTECTED)\s+(\S+)\s+(\S+)"
    )
    for match in row.finditer(text):
        section_index = match.group(4)
        name = match.group(5).split("@", 1)[0]
        if section_index not in {"UND", "UNDEF", "0"} and name.startswith("c2pa_"):
            symbols.add(name)
    return symbols


def parse_coff_exported_symbols(text: str) -> set[str]:
    symbols = set()
    for block in _readobj_blocks(text, "Export"):
        name = _block_name(block)
        if name is not None and name.startswith("c2pa_"):
            symbols.add(name)
    return symbols


def parse_exported_symbols(text: str, target: str) -> set[str]:
    if "windows" in target:
        return parse_coff_exported_symbols(text)
    return parse_elf_exported_symbols(text)


def _llvm_readobj(target: str) -> Path:
    sysroot = Path(
        subprocess.run(
            ["rustc", f"+{TOOLCHAIN}", "--print", "sysroot"],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.strip()
    )
    executable = "llvm-readobj.exe" if "windows" in target else "llvm-readobj"
    tool = sysroot / "lib" / "rustlib" / target / "bin" / executable
    if not tool.is_file():
        raise RuntimeError(
            f"{tool} is missing; install llvm-tools-preview for Rust {TOOLCHAIN}"
        )
    return tool


def verify_symbols(library: Path, target: str) -> None:
    options = (
        ["--coff-exports"]
        if "windows" in target
        else ["--elf-output-style=GNU", "--dyn-symbols"]
    )
    result = subprocess.run(
        [str(_llvm_readobj(target)), *options, str(library)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    missing = sorted(
        set(REQUIRED_SYMBOLS) - parse_exported_symbols(result.stdout, target)
    )
    if missing:
        raise RuntimeError("missing defined exported symbols: " + ", ".join(missing))
    print(f"verified {len(REQUIRED_SYMBOLS)} required defined native exports")


def workspace_version(manifest: Path = Path("Cargo.toml")) -> str:
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    version = data.get("workspace", {}).get("package", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError(f"workspace package version is missing from {manifest}")
    return version


def _strip_c_comments(text: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\r\n]*", "", without_blocks)


def parse_header_function_declarations(text: str) -> set[str]:
    uncommented = _strip_c_comments(text)
    declaration = re.compile(
        r"(?ms)^[ \t]*(?:C2PA_API[ \t]+)?"
        r"(?:[A-Za-z_][A-Za-z0-9_]*[ \t\r\n*]+)+"
        r"(c2pa_[A-Za-z0-9_]+)[ \t\r\n]*"
        r"\([^;{}]*\)[ \t\r\n]*;"
    )
    return {match.group(1) for match in declaration.finditer(uncommented)}


def _validate_header_bytes(data: bytes, expected_version: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("generated c2pa.h is not UTF-8") from error
    if "This file is generated by cbindgen. Do not edit by hand." not in text:
        raise ValueError("c2pa.h does not contain the cbindgen generated-file marker")
    version_match = re.search(r"(?m)^// Version: (\S+)$", text)
    if version_match is None or version_match.group(1) != expected_version:
        raise ValueError(
            f"c2pa.h version does not match workspace version {expected_version}"
        )
    declarations = parse_header_function_declarations(text)
    missing = [symbol for symbol in REQUIRED_SYMBOLS if symbol not in declarations]
    if missing:
        raise ValueError(
            "generated c2pa.h is missing declarations: " + ", ".join(missing)
        )


def verify_header(header: Path) -> None:
    if not header.is_file() or header.is_symlink():
        raise ValueError(f"generated header must be a regular file: {header}")
    _validate_header_bytes(header.read_bytes(), workspace_version())
    print(f"verified {len(REQUIRED_SYMBOLS)} required generated header declarations")


def verify_c2patool_help(executable: Path) -> None:
    invocations = (
        ([str(executable), "--version"], ("c2patool",)),
        ([str(executable), "--help"], ("live-video", "live-video-sign")),
        (
            [str(executable), "qualification.mp4", "live-video", "--help"],
            ("segments_glob",),
        ),
        (
            [str(executable), "qualification", "live-video-sign", "--help"],
            ("--method", "--session-key", "--min-sequence-number"),
        ),
    )
    for command, required in invocations:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        missing = [token for token in required if token not in result.stdout]
        if missing:
            raise RuntimeError(f"{command!r} output is missing: {', '.join(missing)}")
    print("verified c2patool executable smoke and live-video command help")


def _parse_named_paths(values: Iterable[str]) -> list[tuple[str, Path]]:
    parsed = []
    names = set()
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or not name or not raw_path:
            raise ValueError(f"expected NAME=PATH, got {value!r}")
        if name in names:
            raise ValueError(f"duplicate name: {name}")
        names.add(name)
        parsed.append((name, Path(raw_path)))
    return parsed


def _require_exact_names(
    entries: Sequence[tuple[str, Path]], expected: set[str], label: str
) -> list[tuple[str, Path]]:
    actual = {name for name, _ in entries}
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ValueError(f"invalid {label}: " + "; ".join(details))
    return sorted(entries)


def _report_digest(records: Sequence[dict[str, object]]) -> str:
    digest_input = "".join(
        f"{record['package']}\0{record['sha256']}\n" for record in records
    ).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()


def _write_new_files(files: Sequence[tuple[Path, bytes]]) -> None:
    resolved = [path.resolve() for path, _ in files]
    if len(set(resolved)) != len(resolved):
        raise ValueError("output paths must be distinct")
    for path, _ in files:
        if path.exists() or path.is_symlink():
            raise ValueError(f"refusing to overwrite existing output: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)

    created: list[Path] = []
    try:
        for path, data in files:
            with path.open("xb") as destination:
                created.append(path)
                destination.write(data)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def _file_record(path: Path) -> dict[str, object]:
    return {
        "fileName": path.name,
        "sha256": sha256_file(path),
        "byteSize": path.stat().st_size,
    }


def build_evidence(args: argparse.Namespace) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        raise ValueError(
            "source SHA must be exactly 40 lowercase hexadecimal characters"
        )
    if args.target not in SUPPORTED_TARGETS:
        raise ValueError(f"unsupported qualification target: {args.target}")

    reports = _require_exact_names(
        _parse_named_paths(args.feature_report),
        {"c2pa", "c2pa-c-ffi", "c2patool"},
        "feature reports",
    )
    expected_report_names = {
        "c2pa": "sdk-features.txt",
        "c2pa-c-ffi": "ffi-features.txt",
        "c2patool": "c2patool-features.txt",
    }
    for name, path in reports:
        if path.name != expected_report_names[name]:
            raise ValueError(
                f"unexpected feature-report filename for {name}: {path.name}"
            )
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"feature report must be a regular file: {path}")

    artifact_specs = TARGET_ARTIFACT_SPECS[args.target]
    artifacts = _require_exact_names(
        _parse_named_paths(args.artifact), set(artifact_specs), "artifacts"
    )
    artifact_records = {}
    for name, path in artifacts:
        spec = artifact_specs[name]
        if path.name != spec["fileName"]:
            raise ValueError(f"unexpected artifact filename for {name}: {path.name}")
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"artifact must be a regular file: {path}")
        record = _file_record(path)
        record.update(
            {
                "role": spec["role"],
                "buildPath": artifact_build_path(args.target, name),
            }
        )
        artifact_records[name] = record
    _validate_header_bytes(dict(artifacts)["header"].read_bytes(), workspace_version())

    package_by_name = {
        feature_configuration(kind)[0]: feature_configuration(kind)
        for kind in ("sdk", "ffi", "c2patool")
    }
    report_records = [
        {
            "package": name,
            "manifestPath": package_by_name[name][1],
            "fileName": path.name,
            "sha256": sha256_file(path),
            "byteSize": path.stat().st_size,
        }
        for name, path in reports
    ]

    cargo_lock = Path(args.cargo_lock)
    if (
        cargo_lock.name != "Cargo.lock"
        or not cargo_lock.is_file()
        or cargo_lock.is_symlink()
    ):
        raise ValueError(
            f"Cargo.lock must be a regular file named Cargo.lock: {cargo_lock}"
        )
    command_manifest = Path(args.command_manifest)
    commands = load_command_manifest(command_manifest, args.target)
    runner = {
        "os": args.runner_os,
        "arch": args.runner_arch,
        "name": args.runner_name,
        "image": args.runner_image,
    }
    if not all(isinstance(value, str) and value for value in runner.values()):
        raise ValueError("runner facts must be non-empty strings")

    packages = {}
    for kind in ("sdk", "ffi", "c2patool"):
        package, manifest, features, no_default, profile = feature_configuration(kind)
        packages[package] = {
            "manifestPath": manifest,
            "noDefaultFeatures": no_default,
            "requestedFeatures": list(features),
            "featureProfile": profile,
        }
    evidence = {
        "schema": SCHEMA,
        "schemaVersion": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "sourceSha": args.source_sha,
        "cargoLock": _file_record(cargo_lock),
        "rust": {
            "releaseToolchain": TOOLCHAIN,
            "rustfmtToolchain": RUSTFMT_TOOLCHAIN,
            "target": args.target,
            "cargoBuildJobs": CARGO_BUILD_JOBS,
        },
        "python": {"version": PYTHON_VERSION},
        "qualification": {
            "packages": packages,
            "resolvedCargoFeatures": {
                "sha256": _report_digest(report_records),
                "reports": report_records,
            },
            "commandManifest": _file_record(command_manifest),
            "commands": commands,
        },
        "artifacts": artifact_records,
        "runner": runner,
    }
    output = Path(args.output)
    digest_output = Path(args.sha256_output)
    evidence_bytes = _json_bytes(evidence)
    evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
    _write_new_files(
        (
            (output, evidence_bytes),
            (
                digest_output,
                f"{evidence_digest}  {output.name}\n".encode("ascii"),
            ),
        )
    )


def safe_archive_name(raw_name: str) -> str:
    if not raw_name or "\\" in raw_name or re.match(r"^[A-Za-z]:", raw_name):
        raise ValueError(f"unsafe archive path: {raw_name!r}")
    if raw_name.startswith("/") or "//" in raw_name:
        raise ValueError(f"unsafe archive path: {raw_name!r}")
    raw_parts = raw_name.split("/")
    path = PurePosixPath(raw_name)
    if any(part in ("", ".", "..") for part in raw_parts):
        raise ValueError(f"unsafe archive path: {raw_name!r}")
    return path.as_posix()


def _archive_mode(name: str) -> int:
    if name.startswith("bin/") or name.endswith((".so", ".dll", ".dylib")):
        return 0o755
    return 0o644


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = _archive_mode(name)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    return info


def create_bundle(output: Path, mappings: Sequence[tuple[Path, str]]) -> None:
    entries: list[tuple[Path, str]] = []
    names: set[str] = set()
    for source, raw_name in mappings:
        name = safe_archive_name(raw_name)
        if name == "SHA256SUMS":
            raise ValueError("SHA256SUMS is a reserved archive path")
        if name in names:
            raise ValueError(f"duplicate archive path: {name}")
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"bundle input must be a regular file: {source}")
        names.add(name)
        entries.append((source, name))
    output_resolved = output.resolve()
    if any(source.resolve() == output_resolved for source, _ in entries):
        raise ValueError("bundle output must not also be an input")
    if output.exists() or output.is_symlink():
        raise ValueError(f"refusing to overwrite existing output: {output}")
    entries.sort(key=lambda item: item[1])
    checksums = "".join(
        f"{sha256_file(source)}  {name}\n" for source, name in entries
    ).encode("ascii")

    output.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with output.open("xb") as raw_output:
            created = True
            with gzip.GzipFile(
                filename="", mode="wb", fileobj=raw_output, compresslevel=9, mtime=0
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
                ) as archive:
                    for source, name in entries:
                        data = source.read_bytes()
                        archive.addfile(_tar_info(name, len(data)), _BytesReader(data))
                    archive.addfile(
                        _tar_info("SHA256SUMS", len(checksums)),
                        _BytesReader(checksums),
                    )
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise


class _BytesReader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self._data) - self._offset
        start = self._offset
        self._offset += size
        return self._data[start : self._offset]


def bundle_from_args(args: argparse.Namespace) -> None:
    mappings = []
    for value in args.file:
        source, separator, archive_name = value.partition("=")
        if not separator:
            raise ValueError(f"expected SOURCE=ARCHIVE_PATH, got {value!r}")
        mappings.append((Path(source), archive_name))
    output = Path(args.output)
    digest_output = Path(args.sha256_output)
    if digest_output.exists() or digest_output.is_symlink():
        raise ValueError(f"refusing to overwrite existing output: {digest_output}")
    if output.resolve() == digest_output.resolve():
        raise ValueError("bundle and checksum outputs must be distinct")
    create_bundle(output, mappings)
    try:
        digest = sha256_file(output)
        _write_new_files(
            ((digest_output, f"{digest}  {output.name}\n".encode("ascii")),)
        )
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def _archive_files(bundle: Path) -> dict[str, bytes]:
    bundle_bytes = bundle.read_bytes()
    if len(bundle_bytes) < 4 or bundle_bytes[3] & 0x08:
        raise ValueError(
            f"bundle has a non-deterministic gzip filename header: {bundle}"
        )
    with gzip.GzipFile(fileobj=io.BytesIO(bundle_bytes)) as compressed:
        with tarfile.open(fileobj=compressed, mode="r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise ValueError(f"bundle contains duplicate paths: {bundle}")
            files: dict[str, bytes] = {}
            for member in members:
                safe_archive_name(member.name)
                if not member.isfile():
                    raise ValueError(
                        f"bundle member is not a regular file: {member.name}"
                    )
                if (
                    member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mode != _archive_mode(member.name)
                ):
                    raise ValueError(
                        f"bundle member metadata is not normalized: {member.name}"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"unable to read bundle member: {member.name}")
                files[member.name] = extracted.read()
    return files


def _verify_checksums(files: dict[str, bytes], bundle: Path) -> None:
    try:
        checksum_text = files["SHA256SUMS"].decode("ascii")
    except (KeyError, UnicodeDecodeError) as error:
        raise ValueError(f"bundle has no valid SHA256SUMS: {bundle}") from error
    records: dict[str, str] = {}
    for line in checksum_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or match.group(2) in records:
            raise ValueError(f"bundle has an invalid SHA256SUMS: {bundle}")
        records[match.group(2)] = match.group(1)
    expected_names = set(files) - {"SHA256SUMS"}
    if set(records) != expected_names:
        raise ValueError(
            f"bundle SHA256SUMS does not cover exactly its contents: {bundle}"
        )
    for name, expected in records.items():
        actual = hashlib.sha256(files[name]).hexdigest()
        if actual != expected:
            raise ValueError(f"bundle member checksum mismatch: {name}")


def _expected_package_records() -> dict[str, dict[str, object]]:
    records = {}
    for kind in ("sdk", "ffi", "c2patool"):
        package, manifest, features, no_default, profile = feature_configuration(kind)
        records[package] = {
            "manifestPath": manifest,
            "noDefaultFeatures": no_default,
            "requestedFeatures": list(features),
            "featureProfile": profile,
        }
    return records


def _verify_evidence(
    files: dict[str, bytes],
    bundle: Path,
    target: str,
    source_sha: str,
    cargo_lock: Path,
) -> None:
    evidence_name = "qualification/source-qualification.json"
    sidecar_name = f"{evidence_name}.sha256"
    try:
        evidence_bytes = files[evidence_name]
        sidecar = files[sidecar_name].decode("ascii")
        evidence = json.loads(evidence_bytes)
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"bundle has invalid qualification evidence: {bundle}"
        ) from error
    if not isinstance(evidence, dict):
        raise ValueError(f"bundle qualification evidence is not an object: {bundle}")
    evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
    if sidecar != f"{evidence_digest}  source-qualification.json\n":
        raise ValueError(f"bundle evidence checksum mismatch: {bundle}")
    if (
        evidence.get("schema") != SCHEMA
        or evidence.get("schemaVersion") != SCHEMA_VERSION
        or evidence.get("repository") != REPOSITORY
        or evidence.get("sourceSha") != source_sha
    ):
        raise ValueError(f"bundle evidence source identity mismatch: {bundle}")
    if evidence.get("cargoLock") != _file_record(cargo_lock):
        raise ValueError(f"bundle Cargo.lock evidence mismatch: {bundle}")
    if evidence.get("rust") != {
        "releaseToolchain": TOOLCHAIN,
        "rustfmtToolchain": RUSTFMT_TOOLCHAIN,
        "target": target,
        "cargoBuildJobs": CARGO_BUILD_JOBS,
    }:
        raise ValueError(f"bundle Rust facts mismatch: {bundle}")
    if evidence.get("python") != {"version": PYTHON_VERSION}:
        raise ValueError(f"bundle Python facts mismatch: {bundle}")

    qualification = evidence.get("qualification")
    if not isinstance(qualification, dict):
        raise ValueError(f"bundle has invalid qualification facts: {bundle}")
    if qualification.get("packages") != _expected_package_records():
        raise ValueError(f"bundle package feature facts mismatch: {bundle}")

    command_name = "qualification/cargo-commands.json"
    command_bytes = files.get(command_name)
    if command_bytes is None:
        raise ValueError(f"bundle has no Cargo command manifest: {bundle}")
    expected_command_record = {
        "fileName": "cargo-commands.json",
        "sha256": hashlib.sha256(command_bytes).hexdigest(),
        "byteSize": len(command_bytes),
    }
    if qualification.get("commandManifest") != expected_command_record:
        raise ValueError(f"bundle Cargo command manifest digest mismatch: {bundle}")
    try:
        command_data = json.loads(command_bytes)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"bundle Cargo command manifest is invalid: {bundle}"
        ) from error
    commands = _validate_command_manifest(command_data, target)
    if qualification.get("commands") != commands:
        raise ValueError(f"bundle command facts mismatch: {bundle}")

    resolved = qualification.get("resolvedCargoFeatures")
    if not isinstance(resolved, dict) or not isinstance(resolved.get("reports"), list):
        raise ValueError(f"bundle feature-report facts are invalid: {bundle}")
    report_records = resolved["reports"]
    report_record_fields = {
        "package",
        "manifestPath",
        "fileName",
        "sha256",
        "byteSize",
    }
    if len(report_records) != 3 or any(
        not isinstance(record, dict) or set(record) != report_record_fields
        for record in report_records
    ):
        raise ValueError(f"bundle feature-report records are invalid: {bundle}")
    if resolved.get("sha256") != _report_digest(report_records):
        raise ValueError(f"bundle aggregate feature-report digest mismatch: {bundle}")
    report_paths = {
        "c2pa": "qualification/sdk-features.txt",
        "c2pa-c-ffi": "qualification/ffi-features.txt",
        "c2patool": "qualification/c2patool-features.txt",
    }
    records_by_package = {
        record.get("package"): record
        for record in report_records
        if isinstance(record, dict)
    }
    if set(records_by_package) != set(report_paths):
        raise ValueError(f"bundle feature-report set mismatch: {bundle}")
    expected_packages = _expected_package_records()
    for package, archive_name in report_paths.items():
        data = files.get(archive_name)
        record = records_by_package[package]
        expected_manifest = expected_packages[package]["manifestPath"]
        if data is None or record != {
            "package": package,
            "manifestPath": expected_manifest,
            "fileName": Path(archive_name).name,
            "sha256": hashlib.sha256(data).hexdigest() if data is not None else "",
            "byteSize": len(data) if data is not None else -1,
        }:
            raise ValueError(f"bundle feature-report digest mismatch: {package}")

    artifact_specs = TARGET_ARTIFACT_SPECS[target]
    expected_artifacts = {}
    for name, spec in artifact_specs.items():
        archive_name = spec["archivePath"]
        data = files.get(archive_name)
        if data is None:
            raise ValueError(f"bundle is missing artifact: {archive_name}")
        expected_artifacts[name] = {
            "fileName": spec["fileName"],
            "sha256": hashlib.sha256(data).hexdigest(),
            "byteSize": len(data),
            "role": spec["role"],
            "buildPath": artifact_build_path(target, name),
        }
    if evidence.get("artifacts") != expected_artifacts:
        raise ValueError(f"bundle artifact digest or role facts mismatch: {bundle}")
    _validate_header_bytes(
        files[artifact_specs["header"]["archivePath"]], workspace_version()
    )

    runner = evidence.get("runner")
    if not isinstance(runner, dict) or set(runner) != {"os", "arch", "name", "image"}:
        raise ValueError(f"bundle runner facts are invalid: {bundle}")
    if not all(isinstance(value, str) and value for value in runner.values()):
        raise ValueError(f"bundle runner facts are incomplete: {bundle}")

    expected_files = {
        "SHA256SUMS",
        evidence_name,
        sidecar_name,
        command_name,
        *report_paths.values(),
        *(spec["archivePath"] for spec in artifact_specs.values()),
    }
    if set(files) != expected_files:
        raise ValueError(
            f"bundle contents do not match the platform qualification schema: {bundle}"
        )


def verify_release_assets(
    directory: Path, source_sha: str, targets: Sequence[str], cargo_lock: Path
) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError(
            "source SHA must be exactly 40 lowercase hexadecimal characters"
        )
    if len(targets) != len(set(targets)) or set(targets) != set(SUPPORTED_TARGETS):
        raise ValueError("release must contain each supported target exactly once")
    expected: dict[str, tuple[Path, Path]] = {}
    for target in targets:
        bundle = directory / f"castlabs-c2pa-live-video-{source_sha}-{target}.tar.gz"
        expected[target] = (bundle, Path(f"{bundle}.sha256"))
    actual = set(directory.iterdir()) if directory.is_dir() else set()
    expected_paths = {path for pair in expected.values() for path in pair}
    if actual != expected_paths:
        missing = sorted(str(path.name) for path in expected_paths - actual)
        unexpected = sorted(str(path.name) for path in actual - expected_paths)
        raise ValueError(
            "release asset set mismatch: "
            + "; ".join(
                part
                for part in (
                    "missing " + ", ".join(missing) if missing else "",
                    "unexpected " + ", ".join(unexpected) if unexpected else "",
                )
                if part
            )
        )
    for target, (bundle, sidecar) in expected.items():
        if (
            not bundle.is_file()
            or bundle.is_symlink()
            or not sidecar.is_file()
            or sidecar.is_symlink()
        ):
            raise ValueError(
                f"release assets must be regular files for target: {target}"
            )
        digest = sha256_file(bundle)
        if sidecar.read_text(encoding="ascii") != f"{digest}  {bundle.name}\n":
            raise ValueError(f"bundle checksum mismatch for target: {target}")
        files = _archive_files(bundle)
        _verify_checksums(files, bundle)
        _verify_evidence(files, bundle, target, source_sha, cargo_lock)
    print(f"verified {len(targets)} complete platform qualification bundles")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    command_manifest = commands.add_parser("command-manifest")
    command_manifest.add_argument("--target", choices=SUPPORTED_TARGETS, required=True)
    command_manifest.add_argument("--output", required=True)

    symbols = commands.add_parser("verify-symbols")
    symbols.add_argument("--library", required=True)
    symbols.add_argument("--target", choices=SUPPORTED_TARGETS, required=True)

    header = commands.add_parser("verify-header")
    header.add_argument("--header", required=True)

    help_check = commands.add_parser("verify-c2patool-help")
    help_check.add_argument("--executable", required=True)

    evidence = commands.add_parser("evidence")
    evidence.add_argument("--source-sha", required=True)
    evidence.add_argument("--cargo-lock", default="Cargo.lock")
    evidence.add_argument("--command-manifest", required=True)
    evidence.add_argument("--target", choices=SUPPORTED_TARGETS, required=True)
    evidence.add_argument("--feature-report", action="append", required=True)
    evidence.add_argument("--artifact", action="append", required=True)
    evidence.add_argument("--runner-os", required=True)
    evidence.add_argument("--runner-arch", required=True)
    evidence.add_argument("--runner-name", required=True)
    evidence.add_argument("--runner-image", required=True)
    evidence.add_argument("--output", required=True)
    evidence.add_argument("--sha256-output", required=True)

    bundle = commands.add_parser("bundle")
    bundle.add_argument("--file", action="append", required=True)
    bundle.add_argument("--output", required=True)
    bundle.add_argument("--sha256-output", required=True)

    release = commands.add_parser("verify-release-assets")
    release.add_argument("--directory", required=True)
    release.add_argument("--source-sha", required=True)
    release.add_argument("--cargo-lock", default="Cargo.lock")
    release.add_argument(
        "--target", choices=SUPPORTED_TARGETS, action="append", required=True
    )
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "command-manifest":
        write_command_manifest(args.target, Path(args.output))
    elif args.command == "verify-symbols":
        verify_symbols(Path(args.library), args.target)
    elif args.command == "verify-header":
        verify_header(Path(args.header))
    elif args.command == "verify-c2patool-help":
        verify_c2patool_help(Path(args.executable))
    elif args.command == "evidence":
        build_evidence(args)
    elif args.command == "bundle":
        bundle_from_args(args)
    elif args.command == "verify-release-assets":
        verify_release_assets(
            Path(args.directory), args.source_sha, args.target, Path(args.cargo_lock)
        )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.CalledProcessError,
        tarfile.TarError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
