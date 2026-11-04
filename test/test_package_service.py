"""Packaging regression tests (stdlib only; native tests require build tools)."""
from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("package_service", ROOT / "scripts/package-service.py")
pkg = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pkg)


class PackagingTests(unittest.TestCase):
    @staticmethod
    def elf_header(machine="AArch64", elf_class="ELF64", data="2's complement, little endian"):
        return f"ELF Header:\n  Class: {elf_class}\n  Data: {data}\n  Machine: {machine}\n"

    def test_binary_platform_recognizes_supported_architectures(self):
        for machine, architecture in (("AArch64", "arm64"),
                                      ("Advanced Micro Devices X86-64", "x86_64")):
            with self.subTest(machine=machine), patch.object(pkg, "run", return_value=self.elf_header(machine)):
                self.assertEqual(pkg.binary_platform(Path("service"), "linux"), "linux-" + architecture)
        with patch.object(pkg, "run", return_value="arm64"):
            self.assertEqual(pkg.binary_platform(Path("service"), "darwin"), "darwin-arm64")

    def test_binary_platform_rejects_unsupported_or_ambiguous_headers(self):
        for header in ("", "ELF Header:\n  Machine: AArch64\n", self.elf_header("RISC-V"),
                       self.elf_header(elf_class="ELF32"), self.elf_header(data="2's complement, big endian"),
                       self.elf_header() + "  Machine: Advanced Micro Devices X86-64\n"):
            with self.subTest(header=header), patch.object(pkg, "run", return_value=header):
                with self.assertRaises(pkg.PackagingError):
                    pkg.binary_platform(Path("service"), "linux")
        for architectures in ("", "x86_64", "arm64 x86_64", "arm64e", "i386"):
            with self.subTest(architectures=architectures), patch.object(pkg, "run", return_value=architectures):
                with self.assertRaises(pkg.PackagingError):
                    pkg.binary_platform(Path("service"), "darwin")

    def test_explicit_platform_requires_matching_architecture(self):
        for platform in ("linux-x86_64", "darwin-arm64"):
            output = self.elf_header() if platform.startswith("linux") else "arm64 x86_64"
            with self.subTest(platform=platform), patch.object(pkg, "run", return_value=output):
                with self.assertRaisesRegex(pkg.PackagingError, "architecture mismatch|Unsupported/ambiguous|Intel macOS is no longer supported"):
                    pkg.check_platform(Path("service"), platform)

    def test_intel_macos_packaging_rejected_before_bundling(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "service"
            binary.touch()
            with patch.object(pkg.sys, "platform", "darwin"), \
                 patch.object(pkg, "run", return_value="x86_64"), \
                 patch.object(pkg, "MacBundler") as bundler, \
                 patch("sys.stderr", new_callable=io.StringIO) as stderr:
                self.assertEqual(pkg.main(["--binary", str(binary), "--output", str(Path(tmp) / "out"),
                                           "--version", "test"]), 1)
                self.assertIn("Intel macOS is no longer supported", stderr.getvalue())
                bundler.assert_not_called()
                self.assertFalse((Path(tmp) / "out").exists())
                with self.assertRaises(SystemExit), patch("sys.stderr", new_callable=io.StringIO):
                    pkg.main(["--audit", tmp, "--platform", "darwin-x86_64"])

    def test_linux_arm64_main_packages_explicit_and_inferred_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / "service"
            binary.touch()
            for explicit in (False, True):
                output = base / str(explicit)
                args = ["--binary", str(binary), "--output", str(output), "--version", "test"]
                if explicit:
                    args.extend(["--platform", "linux-arm64"])
                with self.subTest(explicit=explicit), patch.object(pkg.sys, "platform", "linux"), \
                     patch.object(pkg, "run", return_value=self.elf_header()), \
                     patch.object(pkg, "LinuxBundler") as bundler, \
                     patch.object(pkg, "licenses", return_value=[]), \
                     patch("sys.stdout", new_callable=io.StringIO):
                    bundler.return_value.bundle.return_value = []
                    self.assertEqual(pkg.main(args), 0)
                    self.assertTrue((output / "lispm-auth-service-test-linux-arm64.tar.gz").is_file())

    def test_main_rejects_mismatched_explicit_platform_before_bundling(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "service"
            binary.touch()
            for platform in ("linux-x86_64", "darwin-arm64"):
                with self.subTest(platform=platform), patch.object(pkg.sys, "platform", "linux"), \
                     patch.object(pkg, "run", return_value=self.elf_header()), \
                     patch.object(pkg, "LinuxBundler") as bundler, \
                     patch("sys.stderr", new_callable=io.StringIO):
                    self.assertEqual(pkg.main(["--binary", str(binary), "--output", str(Path(tmp) / "out"),
                                               "--version", "test", "--platform", platform]), 1)
                    bundler.assert_not_called()

    def test_audit_honors_explicit_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / pkg.NAME).touch()
            with patch.object(pkg.sys, "platform", "linux"), \
                 patch.object(pkg, "run", return_value=self.elf_header()), \
                 patch.object(pkg, "LinuxBundler") as bundler, \
                 patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(pkg.main(["--audit", str(root), "--platform", "linux-x86_64"]), 1)
                bundler.assert_not_called()

    def test_linux_resolution_skips_wrong_architecture_and_class(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            candidates = [root / name for name in ("32bit", "x86_64", "arm64")]
            for path in candidates:
                path.touch()
            bundler = pkg.LinuxBundler.__new__(pkg.LinuxBundler)
            bundler.platform = "linux-arm64"
            bundler.cache = {"libgc.so.1": candidates}
            headers = [self.elf_header(elf_class="ELF32"),
                       self.elf_header("Advanced Micro Devices X86-64"), self.elf_header()]
            with patch.object(pkg, "run", side_effect=headers):
                self.assertEqual(bundler.resolve("libgc.so.1", root / "service", []), candidates[-1].resolve())
            with patch.object(pkg, "run", return_value=self.elf_header("Advanced Micro Devices X86-64")):
                with self.assertRaisesRegex(pkg.PackagingError, "Unresolved ELF dependency"):
                    bundler.resolve("libgc.so.1", root / "service", [])

    def test_bundlers_reject_wrong_architecture_dependencies_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependency = root / "libgc.so.1"
            dependency.touch()
            for klass, platform, header in ((pkg.LinuxBundler, "linux-arm64",
                                              self.elf_header("Advanced Micro Devices X86-64")),
                                             (pkg.MacBundler, "darwin-arm64", "x86_64")):
                bundler = klass.__new__(klass)
                bundler.platform, bundler.root = platform, root
                bundler.copied = {dependency: dependency}
                with self.subTest(platform=platform), patch.object(pkg, "run", return_value=header):
                    with self.assertRaisesRegex(pkg.PackagingError, "architecture mismatch|Unsupported/ambiguous|Intel macOS is no longer supported"):
                        if klass is pkg.MacBundler:
                            bundler.visit(dependency, root / "copy", [])
                        else:
                            bundler.visit(dependency, root / "copy")
                    self.assertFalse((root / "copy").exists())
                    with self.assertRaisesRegex(pkg.PackagingError, "architecture mismatch|Unsupported/ambiguous|Intel macOS is no longer supported"):
                        bundler.audit()

    def test_dependency_allowlist(self):
        for library, expected in (("libecl.26.5.dylib", "ecl"), ("libgmp.so.10", "gmp"),
                                  ("libgc.1.dylib", "bdw-gc"), ("libsodium.so.23", "libsodium"),
                                  ("libffi.so.8", "libffi")):
            self.assertEqual(pkg.dependency_name(library), expected)
        for library in ("libssl.so.3", "libgmpxx.so.4", "libgc_unknown.dylib", "libunknown.dylib"):
            with self.assertRaises(pkg.PackagingError):
                pkg.dependency_name(library)

    def test_mac_system_allowlist(self):
        self.assertTrue(pkg.mac_system("/usr/lib/libSystem.B.dylib"))
        for ref in ("/usr/local/lib/libffi.dylib", "/opt/homebrew/lib/libgc.dylib",
                    "/usr/lib/../../opt/homebrew/lib/libgc.dylib"):
            self.assertFalse(pkg.mac_system(ref))

    def test_load_command_parser_excludes_dylib_id(self):
        text = """some.dylib:
Load command 0
 cmd LC_ID_DYLIB
 name /opt/homebrew/lib/libecl.1.dylib (offset 24)
Load command 1
 cmd LC_LOAD_DYLIB
 name @rpath/libgmp.10.dylib (offset 24)
Load command 2
 cmd LC_RPATH
 path @loader_path/../lib (offset 12)
Load command 3
 cmd LC_LOAD_WEAK_DYLIB
 name /usr/lib/libSystem.B.dylib (offset 24)
"""
        with patch.object(pkg, "run", return_value=text):
            deps, rpaths, identity = pkg.mac_info(Path("x"))
        self.assertEqual(deps, ["@rpath/libgmp.10.dylib", "/usr/lib/libSystem.B.dylib"])
        self.assertEqual(rpaths, ["@loader_path/../lib"])
        self.assertEqual(identity, "/opt/homebrew/lib/libecl.1.dylib")

    def test_archive_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "artifact"
            root.mkdir()
            (root / "actual").write_text("hello")
            (root / "alias").symlink_to("actual")
            with self.assertRaises(pkg.PackagingError):
                pkg.create_archive(root, Path(tmp) / "test.tar.gz")

    def test_archive_has_no_hardlinks_or_special_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "artifact"
            root.mkdir()
            (root / "actual").write_text("hello")
            os.link(root / "actual", root / "alias")
            dest = Path(tmp) / "test.tar.gz"
            pkg.create_archive(root, dest)
            with tarfile.open(dest) as archive:
                members = archive.getmembers()
                self.assertTrue(all(m.isfile() or m.isdir() for m in members))
                self.assertEqual({m.name for m in members}, {"actual", "alias"})
                self.assertTrue(all(not m.pax_headers for m in members))
                self.assertEqual(archive.extractfile("alias").read(), b"hello")

    def test_mac_closure_audit_rejects_external_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / pkg.NAME
            binary.touch()
            bundler = pkg.MacBundler.__new__(pkg.MacBundler)
            bundler.root, bundler.copied, bundler.platform = root, {binary: binary}, "darwin-arm64"
            for deps, rpaths in ((["/opt/homebrew/lib/libgc.dylib"], []),
                                 (["@rpath/libgc.dylib"], []),
                                 (["@loader_path/lib/missing.dylib"], []),
                                 (["@loader_path/../../libgc.dylib"], []),
                                 ([], ["/opt/homebrew/lib"])):
                with patch.object(pkg, "mac_info", return_value=(deps, rpaths, None)), \
                     patch.object(pkg, "check_platform"):
                    with self.assertRaises(pkg.PackagingError):
                        bundler.audit()

    def test_linux_closure_audit_rejects_external_or_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / pkg.NAME
            binary.touch()
            bundler = pkg.LinuxBundler.__new__(pkg.LinuxBundler)
            bundler.root, bundler.copied, bundler.cache = root, {binary: binary}, {}
            bundler.platform = "linux-arm64"
            for deps, rpaths in ((["/opt/homebrew/lib/libgc.so.1"], ["$ORIGIN/lib"]),
                                 (["libgc.so.1"], ["$ORIGIN/lib"]),
                                 ([], ["$ORIGIN/lib", "/usr/local/lib"]),
                                 ([], ["$ORIGIN/../outside"])):
                with patch.object(bundler, "info", return_value=(deps, rpaths)), \
                     patch.object(pkg, "check_platform"):
                    with self.assertRaises(pkg.PackagingError):
                        bundler.audit()

    def test_licenses_fail_without_known_actual_version(self):
        with patch.object(pkg, "run", side_effect=pkg.PackagingError("missing")):
            with self.assertRaises(pkg.PackagingError):
                pkg.discover("libsodium", [], {}, {})

    def test_source_checksum_is_enforced(self):
        response = io.BytesIO(b"not the expected source")
        with patch.object(pkg.urllib.request, "urlopen", return_value=response):
            with self.assertRaisesRegex(pkg.PackagingError, "checksum mismatch"):
                pkg.download_source("https://example.org/source", "0" * 64)

    def test_license_texts_and_static_sodium_notice(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "dependency"
            source.mkdir()
            (source / "LICENSE").write_text("ISC permission and copyright text\n" * 4)
            registry = {"libsodium": {"name": "libsodium", "license": "ISC", "licenses": ["LICENSE"],
                                      "source": "https://download.libsodium.org/libsodium/releases/libsodium-{version}.tar.gz"}}
            notices = pkg.licenses(root, [], registry, {"libsodium": str(source)}, {"libsodium": "1.0.22"})
            self.assertEqual(notices[0]["linkage"], "static (service)")
            self.assertIn("1.0.22", notices[0]["source"])
            self.assertTrue((root / "licenses/libsodium/LICENSE").is_file())

    def test_registry_contains_required_actual_license_files(self):
        registry = json.loads(pkg.REGISTRY.read_text())
        self.assertEqual(set(registry), {"ecl", "gmp", "bdw-gc", "libsodium", "libffi"})
        self.assertIn("COPYING", registry["ecl"]["licenses"])
        self.assertIn("COPYING.LESSERv3", registry["gmp"]["licenses"])
        self.assertIn("COPYINGv2", registry["gmp"]["licenses"])
        self.assertIn("LICENSE", registry["libsodium"]["licenses"])


class NativeBundlingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="package-service-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.build = self.base / "build"
        self.build.mkdir()
        self.root = self.base / "artifact"
        (self.root / "lib").mkdir(parents=True)

    @unittest.skipUnless(sys.platform == "darwin" and shutil.which("clang"), "macOS toolchain required")
    def test_macos_recursive_rpath_bundle_survives_relocation(self):
        gc = self.build / "libgc.1.dylib"
        ecl = self.build / "libecl.1.dylib"
        binary = self.build / "service"
        (self.build / "gc.c").write_text("int gc_value(void) { return 42; }\n")
        (self.build / "ecl.c").write_text("extern int gc_value(void); int ecl_value(void) { return gc_value(); }\n")
        (self.build / "main.c").write_text("extern int ecl_value(void); int main(void) { return ecl_value() == 42 ? 0 : 1; }\n")
        pkg.run("clang", "-dynamiclib", self.build / "gc.c", "-o", gc, "-Wl,-install_name,@rpath/libgc.1.dylib")
        pkg.run("clang", "-dynamiclib", self.build / "ecl.c", gc, "-o", ecl,
                "-Wl,-install_name,@rpath/libecl.1.dylib", "-Wl,-rpath,@loader_path")
        pkg.run("clang", self.build / "main.c", ecl, "-o", binary, f"-Wl,-rpath,{self.build}")
        bundler = pkg.MacBundler(binary, self.root)
        origins = bundler.bundle()
        self.assertEqual(len(origins), 2)
        relocated = self.base / "unrelated location"
        self.root.rename(relocated)
        self.build.rename(self.base / "hidden-original-build")
        subprocess.run([str(relocated / pkg.NAME)], check=True, env={"PATH": "/usr/bin:/bin"})
        for library in (relocated / "lib").iterdir():
            self.assertFalse(library.is_symlink())
            deps, rpaths, identity = pkg.mac_info(library)
            self.assertEqual(rpaths, [])
            self.assertEqual(identity, f"@loader_path/{library.name}")

    @unittest.skipUnless(sys.platform.startswith("linux") and all(shutil.which(t) for t in ("cc", "patchelf", "ldconfig", "readelf")), "Linux compiler/patchelf required")
    def test_linux_recursive_bundle_survives_relocation(self):
        gc = self.build / "libgc.so.1"
        ecl = self.build / "libecl.so.1"
        binary = self.build / "service"
        (self.build / "gc.c").write_text("int gc_value(void) { return 42; }\n")
        (self.build / "ecl.c").write_text("extern int gc_value(void); int ecl_value(void) { return gc_value(); }\n")
        (self.build / "main.c").write_text("extern int ecl_value(void); int main(void) { return ecl_value() == 42 ? 0 : 1; }\n")
        pkg.run("cc", "-shared", "-fPIC", self.build / "gc.c", "-o", gc, "-Wl,-soname,libgc.so.1")
        pkg.run("cc", "-shared", "-fPIC", self.build / "ecl.c", gc, "-o", ecl,
                "-Wl,-soname,libecl.so.1", "-Wl,-rpath,$ORIGIN")
        pkg.run("cc", self.build / "main.c", ecl, "-o", binary, f"-Wl,-rpath,{self.build}")
        bundler = pkg.LinuxBundler(binary, self.root)
        self.assertEqual(len(bundler.bundle()), 2)
        relocated = self.base / "unrelated location"
        self.root.rename(relocated)
        self.build.rename(self.base / "hidden-original-build")
        subprocess.run([str(relocated / pkg.NAME)], check=True, env={"PATH": "/usr/bin:/bin"})


if __name__ == "__main__":
    unittest.main()
