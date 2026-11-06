#!/usr/bin/env python3
"""Assemble one complete CI run into immutable release assets and a pinned client."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile

PLATFORMS = ("darwin-arm64", "linux-x86_64", "linux-arm64")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def members(path):
    """Read regular archive members without extracting attacker-controlled paths."""
    result = {}
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            name = member.name
            parts = PurePosixPath(name).parts
            if (name.startswith("/") or not parts or any(p in (".", "..") for p in name.split("/"))
                    or name in result or not (member.isfile() or member.isdir())
                    or member.pax_headers or member.size > 128 * 1024 * 1024):
                raise ValueError("Unsafe/duplicate archive member: " + name)
            result[name] = archive.extractfile(member).read() if member.isfile() else None
    return result


def write_archive(path, files, prefix):
    with tarfile.open(path, "x:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(prefix + "/" + name)
            member.size = len(data)
            member.mode = 0o755 if name.endswith(".py") else 0o644
            archive.addfile(member, io.BytesIO(data))


def stamp_client(text, version, pins):
    if set(pins) != set(PLATFORMS) or any(not re.fullmatch(r"[0-9a-f]{64}", p) for p in pins.values()):
        raise ValueError("Exactly three verified service pins required")
    replacements = [
        (r"^;; Version: .+$", ";; Version: " + version[1:]),
        (r'\(defconst lispm-auth-service-version "[^"]+"',
         '(defconst lispm-auth-service-version "' + version + '"'),
        (r"(\(defconst lispm-auth-service-sha256\s+)'\(.*?\)\n(?=  \"Alist)",
         r"\g<1>'(" + "\n      ".join('(\"' + p + '\" . \"' + pins[p] + '\")' for p in PLATFORMS) + ")\n"),
    ]
    for pattern, replacement in replacements:
        text, count = re.subn(pattern, replacement, text, flags=re.M | re.S if "sha256" in pattern else re.M)
        if count != 1:
            raise ValueError("Client release marker missing/ambiguous: " + pattern)
    return text


def validate_sources(path, platform, dependencies):
    files = members(path)
    prefix = "dependency-sources/"
    provenance = json.loads(files[prefix + "SOURCE-PROVENANCE.json"])
    if provenance["platform"] != platform:
        raise ValueError("Source platform mismatch")
    packages = provenance["packages"]
    names = [p["dependency"] for p in packages]
    if len(names) != len(set(names)) or set(names) != dependencies:
        raise ValueError("Incomplete dependency source set")
    declared = provenance["files"]
    actual = {n[len(prefix):]: hashlib.sha256(data).hexdigest()
              for n, data in files.items() if data is not None
              and n not in (prefix + "SOURCE-PROVENANCE.json", prefix + "BUILD-AND-RELINK.txt")}
    if declared != actual or not files.get(prefix + "BUILD-AND-RELINK.txt"):
        raise ValueError("Source provenance/checksum mismatch")


def assemble(inputs, output, source, version, commit):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError("Release version must be vMAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Full source commit required")
    if output.exists():
        raise ValueError("Refusing to overwrite release directory")
    expected_dirs = {"service-" + p for p in PLATFORMS}
    if {p.name for p in inputs.iterdir()} != expected_dirs:
        raise ValueError("Exactly three platform artifacts are required")
    pins = {}
    assets = []
    for platform in PLATFORMS:
        directory = inputs / ("service-" + platform)
        runtime = directory / f"lispm-auth-service-{version}-{platform}.tar.gz"
        sources = directory / f"lispm-auth-{version}-{platform}-dependency-sources.tar.gz"
        if {p.name for p in directory.iterdir()} != {runtime.name, sources.name, "SHA256SUMS"}:
            raise ValueError("Unexpected/missing artifact files: " + platform)
        expected_sums = "".join(digest(p) + "  " + p.name + "\n" for p in sorted((runtime, sources)))
        if (directory / "SHA256SUMS").read_text() != expected_sums:
            raise ValueError("Artifact checksum mismatch: " + platform)
        content = members(runtime)
        if not content.get("lispm-auth-service") or not content.get("LICENSE"):
            raise ValueError("Incomplete runtime archive")
        notices = json.loads(content["DEPENDENCY-NOTICES.json"])
        dependencies = {n["dependency"] for n in notices}
        if not {"ecl", "gmp", "bdw-gc", "libsodium"} <= dependencies:
            raise ValueError("Missing runtime source notices")
        validate_sources(sources, platform, dependencies)
        pins[platform] = digest(runtime)
        assets.extend((runtime, sources))
    # git's index supplies only project sources, never ignored build artifacts,
    # working-directory secrets, or untracked user files.
    paths = subprocess.check_output(["git", "ls-files", "-z"], cwd=source).decode().split("\0")
    files = {}
    for name in filter(None, paths):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Non-regular project source: " + name)
        files[name] = path.read_bytes()
    original = files["lispm-auth.el"].decode()
    files["lispm-auth.el"] = stamp_client(original, version, pins).encode()
    output.mkdir(parents=True)
    for asset in assets:
        shutil.copyfile(asset, output / asset.name)
    write_archive(output / f"lispm-auth-client-{version[1:]}.tar.gz", files, "lispm-auth-client-" + version[1:])
    files["lispm-auth.el"] = original.encode()
    write_archive(output / f"lispm-auth-{version}-source.tar.gz", files, "lispm-auth-" + version)
    shutil.copyfile(source / "LICENSE", output / "LICENSE-AGPL-3.0.txt")
    manifest = {"version": version, "source_commit": commit, "service_sha256": pins,
                "assets": {p.name: digest(p) for p in sorted(output.iterdir())}}
    (output / "RELEASE-MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "RELEASE-NOTES.md").write_text(
        f"LispM Auth {version}\n\nBuilt and tested by CI from {commit}.\n\n"
        "Use the lispm-auth-client archive: its generated lispm-auth.el pins these exact three service archives. "
        "The bare git tag is build input and does not contain the post-build pins.\n\n"
        "Platforms: macOS 15 ARM64, Ubuntu 22.04 x86_64, Ubuntu 24.04 ARM64 (glibc). Intel macOS is no longer supported. "
        "Older systems, musl and Windows are not supported. macOS signatures are ad-hoc, not notarized.\n\n"
        "Each platform dependency-sources archive contains SOURCE-PROVENANCE.json, exact vendor sources/patches "
        "and BUILD-AND-RELINK.txt. The project source archive contains build scripts and license. "
        "Keep these assets together when redistributing. No bit-for-bit reproducibility is claimed.\n")
    (output / "SHA256SUMS").write_text("".join(digest(p) + "  " + p.name + "\n" for p in sorted(output.iterdir())))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path("."))
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    assemble(args.inputs, args.output, args.source, args.version, args.commit)


if __name__ == "__main__":
    main()
