#!/usr/bin/env python3
"""Build a relocatable service tarball; run on the target OS/architecture.

Only recognized dependencies may be redistributed. License texts come from the
installed dependency or its known upstream source archive, at packaging time
only. Use --dependency-root/--dependency-version when discovery is ambiguous.
The version arguments describe the actual installed build, not the dylib ABI.
No input files or existing artifacts are modified.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

REGISTRY = Path(__file__).with_name("dependency-notices.json")
NAME = "lispm-auth-service"
SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+)+(?:[-A-Za-z0-9.]*)$")
# Deliberately small baseline: other libraries need explicit license coverage.
GLIBC = re.compile(r"^(?:lib(?:c|m|pthread|dl|rt|resolv|util|anl)\.so\.[0-9]+|ld-linux[^/]*\.so\.[0-9]+)$")
PLATFORMS = ("darwin-arm64", "darwin-x86_64", "linux-arm64", "linux-x86_64")


class PackagingError(RuntimeError):
    pass


def run(*args: object) -> str:
    try:
        return subprocess.run([str(a) for a in args], check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=dict(os.environ, LC_ALL="C")).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise PackagingError(f"Command failed: {' '.join(map(str, args))}\n{detail}") from exc


def binary_platform(path: Path, host_os: str) -> str:
    """Identify one supported 64-bit architecture, never defaulting to x86_64."""
    if host_os == "darwin":
        architectures = run("lipo", "-archs", path).split()
        if len(architectures) == 1 and architectures[0] in {"arm64", "x86_64"}:
            return "darwin-" + architectures[0]
        raise PackagingError(f"Unsupported/ambiguous Mach-O architecture in {path}: {architectures}")
    if host_os == "linux":
        header = run("readelf", "-h", path)
        fields = {}
        for key in ("Class", "Data", "Machine"):
            values = re.findall(rf"^\s*{key}:\s*(.*?)\s*$", header, re.MULTILINE)
            if len(values) != 1:
                raise PackagingError(f"Missing/ambiguous ELF {key} in {path}")
            fields[key] = values[0]
        architecture = {"AArch64": "arm64", "Advanced Micro Devices X86-64": "x86_64"}.get(fields["Machine"])
        if fields["Class"] == "ELF64" and fields["Data"] == "2's complement, little endian" and architecture:
            return "linux-" + architecture
        raise PackagingError(f"Unsupported ELF architecture in {path}: {fields}")
    raise PackagingError(f"Unsupported packaging host: {host_os}")


def check_platform(path: Path, expected: str) -> None:
    actual = binary_platform(path, expected.split("-", 1)[0])
    if actual != expected:
        raise PackagingError(f"Binary architecture mismatch in {path}: expected {expected}, got {actual}")


def dependency_name(path: str) -> str:
    base = Path(path).name
    for pattern, name in ((r"libecl(?:\.|-)", "ecl"), (r"libgmp(?:\.|-)", "gmp"),
                          (r"lib(?:gc|cord|gccpp|gctba)(?:\.|-)", "bdw-gc"),
                          (r"libsodium(?:\.|-)", "libsodium"),
                          (r"libffi(?:\.|-)", "libffi")):
        if re.match(pattern, base):
            return name
    raise PackagingError(f"Unknown dependency {path!r}; add reviewed license/source coverage before redistributing")


def within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def mac_system(ref: str) -> bool:
    return (ref.startswith("/usr/lib/") or ref.startswith("/System/Library/")) and ".." not in Path(ref).parts


def mac_info(path: Path) -> tuple[list[str], list[str], str | None]:
    # Parse load commands rather than otool -L: the latter includes LC_ID_DYLIB.
    text = run("otool", "-l", path)
    deps, rpaths, identity = [], [], None
    for block in re.split(r"Load command \d+", text)[1:]:
        cmd = re.search(r"\bcmd (LC_\w+)", block)
        if not cmd:
            continue
        kind = cmd.group(1)
        if kind == "LC_RPATH":
            match = re.search(r"\n\s*path (.*?) \(offset \d+\)", block)
            if match:
                rpaths.append(match.group(1))
        elif kind in {"LC_LOAD_DYLIB", "LC_LOAD_WEAK_DYLIB", "LC_REEXPORT_DYLIB", "LC_LOAD_UPWARD_DYLIB", "LC_LAZY_LOAD_DYLIB", "LC_ID_DYLIB"}:
            match = re.search(r"\n\s*name (.*?) \(offset \d+\)", block)
            if not match:
                raise PackagingError(f"Cannot parse {kind} in {path}")
            if kind == "LC_ID_DYLIB":
                identity = match.group(1)
            else:
                deps.append(match.group(1))
    return deps, rpaths, identity


class MacBundler:
    def __init__(self, binary: Path, root: Path):
        self.binary, self.root = binary.resolve(), root
        self.copied: dict[Path, Path] = {}
        self.names: dict[str, Path] = {}
        self.origins: list[Path] = []
        self.platform = binary_platform(self.binary, "darwin")

    def resolve(self, ref: str, owner: Path, rpaths: list[Path]) -> Path:
        if ref.startswith("@loader_path/"):
            candidates = [owner.parent / ref[len("@loader_path/"):]]
        elif ref.startswith("@executable_path/"):
            candidates = [self.binary.parent / ref[len("@executable_path/"):]]
        elif ref.startswith("@rpath/"):
            candidates = [p / ref[len("@rpath/"):] for p in rpaths]
        elif ref.startswith("/"):
            candidates = [Path(ref)]
        else:
            raise PackagingError(f"Unsupported relative dependency {ref!r} in {owner}")
        for path in candidates:
            if path.is_file():
                return path.resolve()
        raise PackagingError(f"Unresolved dependency {ref!r} in {owner}")

    def expand_rpath(self, ref: str, owner: Path) -> Path:
        if ref.startswith("@loader_path"):
            return owner.parent / ref[len("@loader_path"):].lstrip("/")
        if ref.startswith("@executable_path"):
            return self.binary.parent / ref[len("@executable_path"):].lstrip("/")
        if ref.startswith("/"):
            return Path(ref)
        raise PackagingError(f"Unresolved/unsupported rpath {ref!r} in {owner}")

    def visit(self, source: Path, dest: Path, inherited: list[Path]) -> None:
        check_platform(source, self.platform)
        self.copied[source] = dest  # mark before recursion (cycles are valid)
        shutil.copyfile(source, dest)
        dest.chmod(0o755)
        deps, raw_rpaths, identity = mac_info(source)
        rpaths = [self.expand_rpath(p, source) for p in raw_rpaths] + inherited
        for ref in deps:
            if mac_system(ref):
                continue
            resolved = self.resolve(ref, source, rpaths)
            if mac_system(str(resolved)):
                run("install_name_tool", "-change", ref, resolved, dest)
                continue
            dependency_name(ref)
            name = Path(ref).name
            previous = self.names.setdefault(name, resolved)
            if previous != resolved:
                raise PackagingError(f"Dependency basename collision: {name}")
            target = self.root / "lib" / name
            if resolved in self.copied:
                target = self.copied[resolved]
            else:
                self.origins.append(resolved)
                self.visit(resolved, target, rpaths)
            relative = os.path.relpath(target, dest.parent)
            run("install_name_tool", "-change", ref, f"@loader_path/{relative}", dest)
        for ref in dict.fromkeys(raw_rpaths):
            run("install_name_tool", "-delete_rpath", ref, dest)
        if identity is not None:
            run("install_name_tool", "-id", f"@loader_path/{dest.name}", dest)

    def bundle(self) -> list[Path]:
        self.visit(self.binary, self.root / NAME, [])
        for path in self.copied.values():
            run("codesign", "--force", "--sign", "-", path)
        self.audit()
        return self.origins

    def audit(self) -> None:
        for path in self.copied.values():
            check_platform(path, self.platform)
            deps, rpaths, identity = mac_info(path)
            if rpaths:
                raise PackagingError(f"Residual rpaths in {path}: {rpaths}")
            if identity is not None and identity != f"@loader_path/{path.name}":
                raise PackagingError(f"Nonrelocatable dylib ID in {path}: {identity}")
            for ref in deps:
                if mac_system(ref):
                    continue
                if not ref.startswith("@loader_path/"):
                    raise PackagingError(f"Nonrelocatable dependency in {path}: {ref}")
                resolved = path.parent / ref[len("@loader_path/"):]
                if not within(resolved, self.root) or not resolved.is_file() or resolved.is_symlink():
                    raise PackagingError(f"Dependency escapes/is missing from artifact: {ref}")
            run("codesign", "--verify", "--strict", path)


class LinuxBundler:
    def __init__(self, binary: Path, root: Path):
        self.binary, self.root = binary.resolve(), root
        self.copied: dict[Path, Path] = {}
        self.names: dict[str, Path] = {}
        self.origins: list[Path] = []
        self.cache: dict[str, list[Path]] = {}
        self.platform = binary_platform(self.binary, "linux")
        for line in run("ldconfig", "-p").splitlines():
            match = re.match(r"\s*(\S+) .* => (\S+)", line)
            if match:
                self.cache.setdefault(match.group(1), []).append(Path(match.group(2)))

    def info(self, path: Path) -> tuple[list[str], list[str]]:
        needed = run("patchelf", "--print-needed", path).splitlines()
        raw = run("patchelf", "--print-rpath", path)
        return needed, raw.split(":") if raw else []

    def resolve(self, ref: str, owner: Path, rpaths: list[str]) -> Path:
        if "/" in ref:
            if not ref.startswith("/"):
                raise PackagingError(f"Relative DT_NEEDED is unsupported: {ref}")
            candidates = [Path(ref)]
        else:
            candidates = []
            for entry in rpaths:
                expanded = entry.replace("${ORIGIN}", str(owner.parent)).replace("$ORIGIN", str(owner.parent))
                if "$" in expanded or not expanded.startswith("/"):
                    raise PackagingError(f"Unresolved/relative ELF rpath in {owner}: {entry}")
                candidates.append(Path(expanded) / ref)
            candidates.extend(self.cache.get(ref, []))
        for path in candidates:
            if path.is_file():
                # ldconfig may contain multiple architectures and ELF classes.
                try:
                    platform = binary_platform(path, "linux")
                except PackagingError:
                    continue
                if platform == self.platform:
                    return path.resolve()
        raise PackagingError(f"Unresolved ELF dependency {ref!r} in {owner}")

    def system(self, ref: str) -> bool:
        if not GLIBC.fullmatch(Path(ref).name):
            return False
        if "/" not in ref:
            candidates = self.cache.get(ref, [])
            if not candidates:
                raise PackagingError(f"Missing system dependency {ref}")
            return any(self.system(str(p)) for p in candidates)
        # Do not exempt a Homebrew/private library merely named libc.so.6.
        return ref.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")) and ".." not in Path(ref).parts

    def visit(self, source: Path, dest: Path) -> None:
        check_platform(source, self.platform)
        self.copied[source] = dest
        shutil.copyfile(source, dest)
        dest.chmod(0o755)
        deps, rpaths = self.info(source)
        for ref in deps:
            if self.system(ref):
                # Normalize absolute glibc references to loader-resolved sonames.
                if "/" in ref:
                    run("patchelf", "--replace-needed", ref, Path(ref).name, dest)
                continue
            dependency_name(ref)
            resolved = self.resolve(ref, source, rpaths)
            name = Path(ref).name
            previous = self.names.setdefault(name, resolved)
            if previous != resolved:
                raise PackagingError(f"Dependency basename collision: {name}")
            if resolved not in self.copied:
                self.origins.append(resolved)
                self.visit(resolved, self.root / "lib" / name)
            target = self.copied[resolved]
            if ref != target.name:
                run("patchelf", "--replace-needed", ref, target.name, dest)
        run("patchelf", "--set-rpath", "$ORIGIN/lib" if dest.parent == self.root else "$ORIGIN", dest)
        if dest.parent != self.root:
            run("patchelf", "--set-soname", dest.name, dest)

    def bundle(self) -> list[Path]:
        interpreter = run("patchelf", "--print-interpreter", self.binary)
        if not self.system(interpreter) or not Path(interpreter).is_file():
            raise PackagingError(f"Unsupported ELF interpreter: {interpreter}")
        check_platform(Path(interpreter), self.platform)
        self.visit(self.binary, self.root / NAME)
        self.audit()
        return self.origins

    def audit(self) -> None:
        for path in self.copied.values():
            check_platform(path, self.platform)
            deps, rpaths = self.info(path)
            expected = "$ORIGIN/lib" if path.parent == self.root else "$ORIGIN"
            if rpaths != [expected]:
                raise PackagingError(f"Nonrelocatable rpaths in {path}: {rpaths}")
            for ref in deps:
                if "/" in ref or "$" in ref:
                    raise PackagingError(f"Nonrelocatable DT_NEEDED in {path}: {ref}")
                if self.system(ref):
                    continue
                dependency_name(ref)
                target = self.root / "lib" / ref
                if not target.is_file() or target.is_symlink():
                    raise PackagingError(f"Missing bundled dependency {ref} in {path}")


def assignments(values: list[str], known: dict) -> dict[str, str]:
    result = {}
    for value in values:
        name, sep, content = value.partition("=")
        if not sep or name not in known or not content or name in result:
            raise PackagingError(f"Expected unique known NAME=VALUE, got {value!r}")
        result[name] = content
    return result


def installed_root(path: Path) -> Path | None:
    for parent in path.resolve().parents:
        if (parent / "INSTALL_RECEIPT.json").is_file():
            return parent
    return None


def discover(name: str, paths: list[Path], roots: dict, versions: dict) -> tuple[Path | None, str]:
    root = Path(roots[name]).resolve() if name in roots else next((r for p in paths if (r := installed_root(p))), None)
    version = versions.get(name)
    if root and not root.is_dir():
        raise PackagingError(f"Missing dependency root: {root}")
    if not version and root and (root / "INSTALL_RECEIPT.json").is_file():
        version = json.loads((root / "INSTALL_RECEIPT.json").read_text())["source"]["versions"]["stable"]
    module = {"bdw-gc": "bdw-gc", "libffi": "libffi"}.get(name, name)
    if not version:
        try:
            version = run("pkg-config", "--modversion", module)
            if not root:
                root = Path(run("pkg-config", "--variable=prefix", module))
        except PackagingError:
            pass
    if not version and name == "ecl":
        try:
            output = run("ecl", "-norc", "-eval",
                         '(progn (format t "~&LISPM-ECL-VERSION=~a~%" (lisp-implementation-version)) (ext:quit 0))')
            match = re.search(r"LISPM-ECL-VERSION=([^\s]+)", output)
            version = match.group(1) if match else None
        except PackagingError:
            pass
    if not version or not VERSION.fullmatch(version):
        raise PackagingError(f"Cannot determine actual {name} version; supply --dependency-version {name}=VERSION")
    return root, version


def download_source(url: str, expected_hash: str | None) -> tarfile.TarFile:
    # Sources only from fixed registry URLs; never extract a fetched archive.
    try:
        with urllib.request.urlopen(url, timeout=90) as response:
            data = response.read(100 * 1024 * 1024 + 1)
        if len(data) > 100 * 1024 * 1024:
            raise PackagingError(f"Source archive too large: {url}")
        if expected_hash and hashlib.sha256(data).hexdigest() != expected_hash:
            raise PackagingError(f"Source archive checksum mismatch: {url}")
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except (OSError, tarfile.TarError) as exc:
        raise PackagingError(f"Cannot fetch known source/license archive {url}: {exc}") from exc


def licenses(root: Path, origins: list[Path], registry: dict, roots: dict, versions: dict) -> list[dict]:
    groups: dict[str, list[Path]] = {"libsodium": []}  # static sodium is still redistributed
    for path in origins:
        groups.setdefault(dependency_name(path.name), []).append(path)
    notices = []
    for name, paths in sorted(groups.items()):
        info = registry[name]
        prefix, version = discover(name, paths, roots, versions)
        url = info.get("source_overrides", {}).get(version, info["source"].format(version=version))
        output = root / "licenses" / name
        output.mkdir(parents=True)
        archive = None
        provenance = []
        try:
            for filename in info["licenses"]:
                candidates = []
                if prefix:
                    candidates = [prefix / filename, prefix / "share" / "doc" / name / filename,
                                  prefix / "share" / "licenses" / name / filename]
                local = next((p for p in candidates if p.is_file()), None)
                if local:
                    data = local.read_bytes()
                    origin = str(local)
                else:
                    if archive is None:
                        archive = download_source(url, info.get("sha256", {}).get(version))
                    matches = [m for m in archive.getmembers() if m.isfile() and "/" in m.name and m.name.split("/", 1)[1] == filename]
                    if len(matches) != 1 or matches[0].size > 4 * 1024 * 1024:
                        raise PackagingError(f"Missing/ambiguous license {filename} in {url}")
                    stream = archive.extractfile(matches[0])
                    assert stream is not None
                    data = stream.read()
                    origin = url + "#" + matches[0].name
                if len(data) < 80:
                    raise PackagingError(f"Empty/truncated license for {name}: {filename}")
                destination = filename.replace("/", "_")
                (output / destination).write_bytes(data)
                provenance.append({"file": f"licenses/{name}/{destination}", "origin": origin,
                                   "sha256": hashlib.sha256(data).hexdigest()})
        finally:
            if archive:
                archive.close()
        # Preserve build-vendor metadata, including Homebrew source patch URLs.
        vendor_files = []
        if prefix:
            candidates = [prefix / "INSTALL_RECEIPT.json"] + sorted((prefix / ".brew").glob("*.rb"))
            for candidate in candidates:
                if candidate.is_file():
                    target = output / ("build-" + candidate.name)
                    shutil.copyfile(candidate, target)
                    vendor_files.append(str(target.relative_to(root)))
        notices.append({"dependency": name, "name": info["name"], "version": version,
                        "license": info["license"], "source": url,
                        "linkage": "static (service)" if name == "libsodium" and not paths else "dynamic",
                        "libraries": sorted({p.name for p in paths}), "license_files": provenance,
                        "build_metadata": vendor_files})
    return notices


def create_archive(root: Path, destination: Path) -> None:
    # Build the entire member list first. Never add symlinks, devices, sockets,
    # FIFOs or tar hardlinks, even if a staging directory is accidentally changed.
    paths = sorted(root.rglob("*"))
    for path in paths:
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise PackagingError(f"Non-regular archive member: {path}")
    with tarfile.open(destination, "w:gz", format=tarfile.USTAR_FORMAT, dereference=True) as archive:
        for path in paths:
            member = archive.gettarinfo(str(path), arcname=str(path.relative_to(root)))
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mtime = 0
            if member.isfile():
                with path.open("rb") as stream:
                    archive.addfile(member, stream)
            else:
                archive.addfile(member)
    with tarfile.open(destination, "r:gz") as archive:
        if any(not (m.isfile() or m.isdir()) for m in archive):
            raise PackagingError("Archive contains a non-regular member")


def audit_directory(root: Path, platform: str | None = None) -> None:
    root = root.resolve()
    if not (root / NAME).is_file():
        raise PackagingError(f"Missing service in {root}")
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise PackagingError(f"Non-regular artifact member: {path}")
    if platform is not None:
        host_os = "darwin" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unsupported"
        if platform not in PLATFORMS or not platform.startswith(host_os + "-"):
            raise PackagingError(f"Unsupported target/host combination: {platform} / {host_os}")
        check_platform(root / NAME, platform)
    klass = MacBundler if sys.platform == "darwin" else LinuxBundler
    bundler = klass(root / NAME, root)
    binaries = [root / NAME] + list((root / "lib").iterdir())
    bundler.copied = {p: p for p in binaries}
    if sys.platform.startswith("linux"):
        interpreter = run("patchelf", "--print-interpreter", root / NAME)
        if not bundler.system(interpreter) or not Path(interpreter).is_file():
            raise PackagingError(f"Unsupported ELF interpreter: {interpreter}")
        check_platform(Path(interpreter), bundler.platform)
    bundler.audit()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, help="Audit an already extracted runtime directory")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", "--output-dir", dest="output_dir", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--platform", choices=PLATFORMS)
    parser.add_argument("--dependency-root", action="append", default=[], metavar="NAME=PREFIX")
    parser.add_argument("--dependency-version", action="append", default=[], metavar="NAME=VERSION")
    args = parser.parse_args(argv)
    try:
        if args.audit:
            audit_directory(args.audit, args.platform)
            print(f"Runtime closure verified: {args.audit}")
            return 0
        if not (args.binary and args.output_dir and args.version):
            raise PackagingError("--binary, --output and --version are required for packaging")
        if not SAFE.fullmatch(args.version) or args.version in {".", ".."}:
            raise PackagingError("Version must be a safe nonempty filename component")
        host_os = "darwin" if sys.platform == "darwin" else "linux" if sys.platform.startswith("linux") else "unsupported"
        if not args.binary.is_file():
            raise PackagingError(f"Missing service binary: {args.binary}")
        actual_platform = binary_platform(args.binary, host_os)
        if args.platform is None:
            args.platform = actual_platform
        target_os, _ = args.platform.split("-", 1)
        if target_os != host_os or args.platform not in PLATFORMS:
            raise PackagingError(f"Unsupported target/host combination: {args.platform} / {host_os}")
        if args.platform != actual_platform:
            raise PackagingError(f"Binary architecture mismatch: expected {args.platform}, got {actual_platform}")
        registry = json.loads(REGISTRY.read_text())
        roots = assignments(args.dependency_root, registry)
        versions = assignments(args.dependency_version, registry)
        artifact_name = f"{NAME}-{args.version}-{args.platform}"
        args.output_dir.mkdir(parents=True, exist_ok=True)
        destination = args.output_dir / f"{artifact_name}.tar.gz"
        if destination.exists():
            raise PackagingError(f"Refusing to overwrite existing artifact: {destination}")
        with tempfile.TemporaryDirectory(prefix="package-service-") as temp:
            root = Path(temp) / artifact_name
            (root / "lib").mkdir(parents=True)
            bundler = (MacBundler if host_os == "darwin" else LinuxBundler)(args.binary, root)
            origins = bundler.bundle()
            notices = licenses(root, origins, registry, roots, versions)
            (root / "DEPENDENCY-NOTICES.json").write_text(json.dumps(notices, indent=2) + "\n")
            (root / "SOURCE-NOTICES.txt").write_text(
                "Third-party runtime dependencies\n\n" + "\n\n".join(
                    f"{n['name']} {n['version']}\nLicense: {n['license']}\nCorresponding upstream source: {n['source']}\n"
                    f"Linkage: {n['linkage']}\nLicense texts: licenses/{n['dependency']}/"
                    for n in notices) + "\n\n"
                "Shared dependencies may be replaced by ABI-compatible builds in lib/.\n"
                "Dependency changes in this artifact are limited to loader paths/IDs and signing.\n"
                "Build-vendor metadata, when available, records additional source patches.\n"
                "Source URLs identify upstream releases, not a claim that vendor builds are unmodified.\n"
                "Distributors must also provide corresponding source (including vendor patches) and\n"
                "any required relinking materials under the applicable licenses; a URL notice alone\n"
                "is not a written source offer or a substitute for those obligations.\n")
            project_license = Path(__file__).resolve().parent.parent / "LICENSE"
            shutil.copyfile(project_license, root / "LICENSE")
            bundler.audit()
            temporary_archive = Path(temp) / "artifact.tar.gz"
            create_archive(root, temporary_archive)
            # Exclusive creation protects existing artifacts, including concurrent builds.
            with destination.open("xb") as output, temporary_archive.open("rb") as source:
                shutil.copyfileobj(source, output)
        print(destination.resolve())
        print(f"SHA256 {hashlib.sha256(destination.read_bytes()).hexdigest()}")
        return 0
    except (PackagingError, OSError, ValueError, KeyError) as exc:
        print(f"package-service: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
