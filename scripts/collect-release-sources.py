#!/usr/bin/env python3
"""Collect exact vendor sources on the machine which built the service.

No source is executed. Unsupported vendor metadata fails closed. Linux uses
APT's authenticated source indexes; Homebrew downloads use formula checksums.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

PACKAGES = {"ecl": "libecl-dev", "gmp": "libgmp-dev", "bdw-gc": "libgc-dev",
            "libffi": "libffi-dev", "libsodium": "libsodium-dev"}
INSTRUCTIONS = """Corresponding dependency sources

These files accompany the service built in the same CI job. SOURCE-PROVENANCE.json
records exact vendor revisions and source hashes. Original source licenses apply.
Project sources/build scripts and the AGPL license are in the client source asset.

Ubuntu: dpkg-source -x PACKAGE.dsc combines the original source and Debian/Ubuntu
changes. Install the build dependencies from debian/control and rebuild with
dpkg-buildpackage -b -us -uc. Package rules and patches are included.

Homebrew: use the included formula and installed receipt, not today's moving
formula. Apply the included patches in formula order; follow the formula's
configure/build recipe using Homebrew's standard build helpers. Upstream archive
and patch SHA256 values were verified against the actual installed formula.

Rebuild service: see Makefile, common-lisp/build.lisp and the CI workflow in the
client source archive. Use ECL and a static sodium prefix, make service
SODIUM_PREFIX=/absolute/prefix, then make crypto-test test compile packaging-test.
The packaging script changes loader paths/IDs and macOS ad-hoc signatures only.

ECL/GMP/GC and Linux libffi are dynamically linked. Replace lib/NAME with an
ABI-compatible build preserving expected filenames/SONAMEs and relative loader
paths ($ORIGIN on Linux, @loader_path on macOS). Re-sign modified macOS libraries
with codesign --force --sign - PATH; no proprietary signing key is required.
Audit with scripts/package-service.py --audit DIRECTORY and rerun crypto tests.
Sodium is ISC-licensed and static: rebuild the service to replace it. Reverse
engineering for debugging modifications to the libraries is not restricted.
Keep these sources available beside the binary assets. No bit-reproducibility,
notarization, or compatibility with untested operating systems is claimed.
"""


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def checked_download(url, destination, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected) or not url.startswith("https://"):
        raise ValueError("A fixed HTTPS source URL and SHA256 are required")
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Source size/checksum mismatch: " + url)
    destination.write_bytes(data)
    return {"file": destination.name, "url": url, "sha256": expected}


def formula_sources(text):
    # Resources/embedded patches require explicit support instead of silently
    # publishing incomplete corresponding source. Only stable pinned releases.
    if re.search(r"^\s*(resource\s|patch\s+:|__END__)", text, re.M):
        raise ValueError("Unsupported resource/embedded patch in installed formula")
    first = re.search(r'^  url "(https://[^"\n]+)"\n(?:  mirror [^\n]+\n)*  sha256 "([0-9a-f]{64})"', text, re.M)
    if not first:
        raise ValueError("Missing fixed formula source/checksum")
    patches = re.findall(r'patch do\s+url "(https://[^"\n]+)"\s+sha256 "([0-9a-f]{64})"', text)
    if len(patches) != len(re.findall(r"^\s*patch do\s*$", text, re.M)):
        raise ValueError("Unrecognized formula patch")
    return [first.groups()] + patches


def descriptor_files(text):
    match = re.search(r"^Checksums-Sha256:\n((?: [^\n]+\n)+)", text, re.M)
    if not match:
        raise ValueError("Missing source descriptor checksums")
    result = []
    for line in match[1].splitlines():
        digest, size, name = line.split()
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or Path(name).name != name or name in (".", ".."):
            raise ValueError("Unsafe source descriptor entry")
        result.append((name, int(size), digest))
    return result


def collect(notices, runtime, output, platform):
    if output.exists():
        raise ValueError("Refusing to overwrite source artifact")
    records = []
    with tempfile.TemporaryDirectory(prefix="auth-sources-") as tmp:
        root = Path(tmp) / "dependency-sources"
        root.mkdir()
        for notice in notices:
            name = notice["dependency"]
            dest = root / name
            dest.mkdir()
            if sys.platform == "darwin":
                metadata = notice["build_metadata"]
                formulae = [runtime / f for f in metadata if f.endswith(".rb")]
                receipts = [runtime / f for f in metadata if f.endswith("INSTALL_RECEIPT.json")]
                if len(formulae) != 1 or len(receipts) != 1:
                    raise ValueError("Missing installed formula/receipt: " + name)
                receipt = json.loads(receipts[0].read_text())
                if receipt["source"]["versions"]["stable"] != notice["version"]:
                    raise ValueError("Installed formula version mismatch")
                if receipt.get("built_as_bottle") is not True or receipt["source"].get("spec") != "stable":
                    raise ValueError("Unrecognized Homebrew build provenance")
                for path in formulae + receipts:
                    shutil.copyfile(path, dest / path.name)
                downloads = []
                for i, (url, digest) in enumerate(formula_sources(formulae[0].read_text())):
                    filename = f"{i}-" + url.rsplit("/", 1)[-1]
                    if not re.fullmatch(r"[A-Za-z0-9._+-]+", filename):
                        raise ValueError("Unsafe source URL filename")
                    downloads.append(checked_download(url, dest / filename, digest))
                records.append({"dependency": name, "vendor": "homebrew", "receipt": receipt,
                                "sources": downloads})
            elif sys.platform.startswith("linux"):
                package = PACKAGES[name]
                fields = run("dpkg-query", "-W", "-f=${Version}\t${source:Package}\t${source:Version}", package).split("\t")
                binary_version, source, version = fields
                # Confirm that the actual redistributed runtime libraries come
                # from this exact source revision, not just an unrelated -dev
                # package with a convenient name.
                installed = run("dpkg-query", "-W", "-f=${binary:Package}\\t${source:Package}\\t${source:Version}\\n")
                source_packages = [line.split("\t")[0] for line in installed.splitlines()
                                   if line.split("\t")[1:] == [source, version]]
                supplied = set()
                for source_package in source_packages:
                    supplied.update(Path(p).name for p in run("dpkg-query", "-L", source_package).splitlines())
                if not set(notice["libraries"]) <= supplied:
                    raise ValueError("Bundled library/source package mismatch: " + name)
                if not re.fullmatch(r"[a-z0-9+.-]+", source) or not version:
                    raise ValueError("Missing exact source package revision")
                subprocess.run(["apt-get", "source", "--download-only", "--only-source", source + "=" + version], cwd=dest, check=True)
                descriptors = list(dest.glob("*.dsc"))
                if len(descriptors) != 1:
                    raise ValueError("Missing/ambiguous exact source descriptor")
                for filename, size, digest in descriptor_files(descriptors[0].read_text()):
                    data = (dest / filename).read_bytes()
                    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
                        raise ValueError("Source descriptor checksum mismatch")
                records.append({"dependency": name, "vendor": "ubuntu", "binary_package": package,
                                "binary_version": binary_version, "source_package": source,
                                "source_version": version})
            else:
                raise ValueError("Unsupported source vendor")
        files = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in sorted(root.rglob("*")) if p.is_file()}
        (root / "SOURCE-PROVENANCE.json").write_text(json.dumps({"platform": platform, "packages": records,
                                                                "files": files}, indent=2) + "\n")
        (root / "BUILD-AND-RELINK.txt").write_text(INSTRUCTIONS)
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    tf.add(path, arcname="dependency-sources/" + str(path.relative_to(root)), recursive=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    args = parser.parse_args()
    collect(json.loads((args.runtime / "DEPENDENCY-NOTICES.json").read_text()), args.runtime,
            args.output, args.platform)


if __name__ == "__main__":
    main()
