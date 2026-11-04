#!/usr/bin/env python3
"""Verify the exact asset set and checksums before native tests or publication."""
import hashlib
import json
from pathlib import Path
import re
import sys


def verify(root):
    manifest = json.loads((root / "RELEASE-MANIFEST.json").read_text())
    version = manifest["version"]
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid release version")
    platforms = {"darwin-arm64", "darwin-x86_64", "linux-x86_64", "linux-arm64"}
    if set(manifest["service_sha256"]) != platforms:
        raise ValueError("Incomplete platform set")
    expected = {f"lispm-auth-service-{version}-{p}.tar.gz" for p in platforms}
    expected |= {f"lispm-auth-{version}-{p}-dependency-sources.tar.gz" for p in platforms}
    expected |= {f"lispm-auth-client-{version[1:]}.tar.gz", f"lispm-auth-{version}-source.tar.gz", "LICENSE-AGPL-3.0.txt"}
    if set(manifest["assets"]) != expected:
        raise ValueError("Incomplete manifest")
    expected |= {"RELEASE-MANIFEST.json", "RELEASE-NOTES.md", "SHA256SUMS"}
    if {p.name for p in root.iterdir()} != expected:
        raise ValueError("Unexpected/missing release asset")
    checksums = "".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
                        for p in sorted(root.iterdir()) if p.name != "SHA256SUMS")
    if (root / "SHA256SUMS").read_text() != checksums:
        raise ValueError("Release checksum mismatch")
    for filename, digest in manifest["assets"].items():
        if hashlib.sha256((root / filename).read_bytes()).hexdigest() != digest:
            raise ValueError("Manifest checksum mismatch")
    for platform, digest in manifest["service_sha256"].items():
        if manifest["assets"][f"lispm-auth-service-{version}-{platform}.tar.gz"] != digest:
            raise ValueError("Service pin mismatch")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
