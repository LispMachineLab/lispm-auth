"""Release completeness, generated pins and provenance failure regressions."""
import hashlib
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assembly = load("assemble-release")
collector = load("collect-release-sources")
verification = load("verify-release")


def archive(path, files):
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tf.addfile(member, io.BytesIO(data))


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "lispm-auth.el").write_bytes((ROOT / "lispm-auth.el").read_bytes())
        (self.source / "LICENSE").write_text("test project license")
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "add", "LICENSE", "lispm-auth.el"], check=True)
        self.output = self.root / "release"
        self.version = "v1.2.3"
        self.commit = "a" * 40
        for platform in assembly.PLATFORMS:
            directory = self.inputs / ("service-" + platform)
            directory.mkdir()
            runtime = directory / f"lispm-auth-service-{self.version}-{platform}.tar.gz"
            dependencies = ["ecl", "gmp", "bdw-gc", "libsodium"]
            archive(runtime, {"lispm-auth-service": platform.encode(), "LICENSE": b"license",
                              "DEPENDENCY-NOTICES.json": json.dumps([{"dependency": n} for n in dependencies]).encode()})
            source = directory / f"lispm-auth-{self.version}-{platform}-dependency-sources.tar.gz"
            body = b"corresponding sources"
            provenance = {"platform": platform, "packages": [{"dependency": n} for n in dependencies],
                          "files": {"sources.txt": hashlib.sha256(body).hexdigest()}}
            archive(source, {"dependency-sources/sources.txt": body,
                             "dependency-sources/SOURCE-PROVENANCE.json": json.dumps(provenance).encode(),
                             "dependency-sources/BUILD-AND-RELINK.txt": b"instructions"})
            self.sums(directory)

    def sums(self, directory):
        (directory / "SHA256SUMS").write_text("".join(assembly.digest(p) + "  " + p.name + "\n"
                                                    for p in sorted(directory.glob("*.tar.gz"))))

    def assemble(self):
        assembly.assemble(self.inputs, self.output, self.source, self.version, self.commit)

    def test_complete_release_and_actual_pins(self):
        self.assemble()
        verification.verify(self.output)
        client = assembly.members(self.output / "lispm-auth-client-1.2.3.tar.gz")
        text = client["lispm-auth-client-1.2.3/lispm-auth.el"].decode()
        self.assertIn(";; Version: 1.2.3", text)
        self.assertIn('(defconst lispm-auth-service-version "v1.2.3"', text)
        for platform in assembly.PLATFORMS:
            digest = assembly.digest(self.output / f"lispm-auth-service-v1.2.3-{platform}.tar.gz")
            self.assertIn(f'("{platform}" . "{digest}")', text)
        self.assertEqual((self.source / "lispm-auth.el").read_bytes(), (ROOT / "lispm-auth.el").read_bytes())
        with self.assertRaises(ValueError):
            self.assemble()

    def test_official_platform_sets_and_workflow_agree(self):
        packaging = load("package-service")
        expected = {"darwin-arm64", "linux-x86_64", "linux-arm64"}
        self.assertEqual(set(assembly.PLATFORMS), expected)
        self.assertEqual(set(packaging.PLATFORMS), expected)
        workflow = (ROOT / ".github/workflows/service.yml").read_text()
        platforms = re.findall(r"^\s+platform: (\S+)$", workflow, re.M)
        self.assertEqual(len(platforms), 6)
        self.assertEqual(set(platforms), expected)
        self.assertNotIn("macos-15-intel", workflow)
        self.assertFalse((ROOT / ".github/workflows/recover-v023.yml").exists())
        self.assertFalse((ROOT / "scripts/setup-rosetta.sh").exists())

    def test_extra_intel_platform_fails(self):
        (self.inputs / "service-darwin-x86_64").mkdir()
        with self.assertRaisesRegex(ValueError, "Exactly three platform artifacts"):
            self.assemble()
        self.assertFalse(self.output.exists())

    def test_intel_pin_fails_assembly_and_verification(self):
        pins = {p: "a" * 64 for p in assembly.PLATFORMS}
        pins["darwin-x86_64"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "Exactly three verified service pins"):
            assembly.stamp_client((ROOT / "lispm-auth.el").read_text(), self.version, pins)
        self.assemble()
        manifest_path = self.output / "RELEASE-MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["service_sha256"]["darwin-x86_64"] = "b" * 64
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Incomplete platform set"):
            verification.verify(self.output)

    def test_missing_platform_fails(self):
        import shutil
        for platform in assembly.PLATFORMS:
            directory = self.inputs / ("service-" + platform)
            saved = self.root / directory.name
            shutil.move(directory, saved)
            with self.subTest(platform=platform), self.assertRaises(ValueError):
                self.assemble()
            self.assertFalse(self.output.exists())
            shutil.move(saved, directory)

    def test_wrong_checksum_fails(self):
        (self.inputs / "service-linux-arm64" / "SHA256SUMS").write_text("wrong")
        with self.assertRaises(ValueError):
            self.assemble()

    def test_wrong_version_fails(self):
        self.version = "v1.2.4"
        with self.assertRaises(ValueError):
            self.assemble()

    def test_invalid_version_fails(self):
        self.version = "v1.2.3/../../elsewhere"
        with self.assertRaises(ValueError):
            self.assemble()

    def test_missing_sources_fails(self):
        directory = self.inputs / "service-linux-arm64"
        source = next(directory.glob("*-dependency-sources.tar.gz"))
        source.unlink()
        with self.assertRaises(ValueError):
            self.assemble()

    def test_corrupt_source_provenance_fails(self):
        directory = self.inputs / "service-linux-arm64"
        source = next(directory.glob("*-dependency-sources.tar.gz"))
        files = assembly.members(source)
        files["dependency-sources/sources.txt"] = b"changed"
        archive(source, files)
        self.sums(directory)
        with self.assertRaises(ValueError):
            self.assemble()

    def test_links_and_traversal_fail(self):
        path = self.root / "unsafe.tar.gz"
        archive(path, {"../escape": b"bad"})
        with self.assertRaises(ValueError):
            assembly.members(path)
        with tarfile.open(path, "w:gz") as tf:
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "outside"
            tf.addfile(member)
        with self.assertRaises(ValueError):
            assembly.members(path)

    def test_tampered_candidate_fails(self):
        self.assemble()
        (self.output / "LICENSE-AGPL-3.0.txt").write_text("changed")
        with self.assertRaises(ValueError):
            verification.verify(self.output)

    def test_missing_client_marker_fails(self):
        with self.assertRaises(ValueError):
            assembly.stamp_client("no markers", self.version,
                                  {p: "a" * 64 for p in assembly.PLATFORMS})


class SourceCollectorTests(unittest.TestCase):
    def test_formula_upstream_and_patch(self):
        text = '  url "https://example.org/source.tgz"\n  sha256 "' + "a" * 64 + '"\n'
        text += '  patch do\n    url "https://example.org/fix.diff"\n    sha256 "' + "b" * 64 + '"\n  end\n'
        self.assertEqual(len(collector.formula_sources(text)), 2)
        for unsupported in ('  resource "extra" do\n', '  patch :DATA\n', '__END__\n', '  patch do\n    url "https://example.org/no-hash"\n  end\n'):
            with self.assertRaises(ValueError):
                collector.formula_sources(text + unsupported)

    def test_descriptor_paths_and_checksums(self):
        self.assertEqual(collector.descriptor_files("Checksums-Sha256:\n " + "a" * 64 + " 5 source.tar.gz\n"),
                         [("source.tar.gz", 5, "a" * 64)])
        with self.assertRaises(ValueError):
            collector.descriptor_files("Checksums-Sha256:\n " + "a" * 64 + " 5 ../escape\n")
        with self.assertRaises(ValueError):
            collector.descriptor_files("missing checksums")

    def test_collect_linux_exact_source_revision(self):
        body = b"source archive"
        digest = hashlib.sha256(body).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = root / "runtime"
            runtime.mkdir()
            output = root / "sources.tar.gz"
            notice = {"dependency": "ecl", "libraries": ["libecl.so.21.2"]}

            def run(*args):
                if args[1] == "-L":
                    return "/usr/lib/aarch64-linux-gnu/libecl.so.21.2"
                if len(args) == 4:
                    return "21.2.1-7build1\tecl\t21.2.1-7build1"
                return "libecl21.2:arm64\tecl\t21.2.1-7build1\nother:arm64\tother\t1"

            def download(args, cwd, check):
                self.assertIn("ecl=21.2.1-7build1", args)
                (cwd / "ecl.orig.tar.gz").write_bytes(body)
                (cwd / "ecl.dsc").write_text("Checksums-Sha256:\n " + digest + " " + str(len(body)) + " ecl.orig.tar.gz\n")

            with patch.object(collector.sys, "platform", "linux"), \
                 patch.object(collector, "run", side_effect=run), \
                 patch.object(collector.subprocess, "run", side_effect=download):
                collector.collect([notice], runtime, output, "linux-arm64")
            assembly.validate_sources(output, "linux-arm64", {"ecl"})

    def test_collect_rejects_library_source_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(collector.sys, "platform", "linux"), \
                 patch.object(collector, "run", side_effect=["1\tecl\t1", "unrelated\tother\t1"]), \
                 patch.object(collector.subprocess, "run") as download:
                with self.assertRaises(ValueError):
                    collector.collect([{"dependency": "ecl", "libraries": ["libecl.so.1"]}],
                                      root, root / "sources.tar.gz", "linux-arm64")
                download.assert_not_called()

    def test_download_checksum_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(collector.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")):
                with self.assertRaises(ValueError):
                    collector.checked_download("https://example.org/a", Path(tmp) / "a", "a" * 64)
            self.assertFalse((Path(tmp) / "a").exists())


if __name__ == "__main__":
    unittest.main()
