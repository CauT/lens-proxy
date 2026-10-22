"""Real macOS archive/signature regressions; no private signing identity needed."""

import importlib.util
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "package-app.py"
spec = importlib.util.spec_from_file_location("lens_packaging", SCRIPT)
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)
DMG_SPEC = importlib.util.spec_from_file_location("lens_dmg", SCRIPT.with_name("package-dmg.py"))
dmg = importlib.util.module_from_spec(DMG_SPEC)
DMG_SPEC.loader.exec_module(dmg)


@unittest.skipUnless(sys.platform == "darwin", "requires real macOS signing/extraction tools")
class PackagingAcceptance(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lens-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / "Fixture.app"
        (self.app / "Contents/MacOS").mkdir(parents=True)
        resources = self.app / "Contents/Resources"
        resources.mkdir()
        with (self.app / "Contents/Info.plist").open("wb") as stream:
            plistlib.dump({"CFBundleExecutable": "Fixture", "CFBundleIdentifier": "dev.lens.packaging.fixture",
                          "CFBundlePackageType": "APPL"}, stream)
        shutil.copy("/usr/bin/true", self.app / "Contents/MacOS/Fixture")
        (resources / "payload").write_bytes(b"sealed payload\x00\xff")
        (resources / "alias").symlink_to("payload")
        subprocess.run(["/usr/bin/xattr", "-w", "com.lens.packaging-test", "test metadata",
                        str(resources / "payload")], check=True, capture_output=True)
        packaging.run("/usr/bin/codesign", "--force", "--deep", "--sign", "-", str(self.app))
        self.output = self.root / "Lens-development.zip"

    def test_real_archive_roundtrip_excludes_metadata_and_preserves_signed_tree(self):
        before = packaging.tree(self.app)
        report = packaging.package(self.app, self.output, development=True)
        self.assertFalse(report["gatekeeper_ready"])
        self.assertEqual(report["metadata_entries"], 0)
        self.assertEqual(len(report["extractions"]), 2)
        self.assertEqual(packaging.tree(self.app), before)
        with zipfile.ZipFile(self.output) as archive:
            self.assertFalse(any("._" in name or "__MACOSX" in name for name in archive.namelist()))
        self.assertTrue(self.output.with_suffix(".verification.json").is_file())
        # The packager must not remove attributes or re-sign the source.
        self.assertEqual(packaging.run("/usr/bin/xattr", "-p", "com.lens.packaging-test",
                                      str(self.app / "Contents/Resources/payload")).strip(), "test metadata")

    def test_default_release_refuses_adhoc_without_output(self):
        with self.assertRaisesRegex(packaging.PackageError, "Developer ID"):
            packaging.package(self.app, self.root / "Lens.zip")
        self.assertFalse((self.root / "Lens.zip").exists())

    def test_appledouble_contamination_is_rejected_without_source_repair(self):
        metadata = self.app / "Contents/Resources/._payload"
        metadata.write_bytes(b"unexpected AppleDouble")
        with self.assertRaisesRegex(packaging.PackageError, "metadata"):
            packaging.package(self.app, self.output, development=True)
        self.assertTrue(metadata.exists())
        self.assertFalse(self.output.exists())

    def test_modified_sealed_resource_is_rejected(self):
        (self.app / "Contents/Resources/payload").write_bytes(b"changed after signing")
        with self.assertRaisesRegex(packaging.PackageError, "sealed resource"):
            packaging.package(self.app, self.output, development=True)
        self.assertFalse(self.output.exists())

    def test_existing_archive_is_preserved(self):
        self.output.write_bytes(b"previous variant")
        with self.assertRaisesRegex(packaging.PackageError, "overwrite"):
            packaging.package(self.app, self.output, development=True)
        self.assertEqual(self.output.read_bytes(), b"previous variant")


@unittest.skipUnless(sys.platform == "darwin", "requires real macOS disk image/signature tools")
class DMGAcceptance(unittest.TestCase):
    setUp = PackagingAcceptance.setUp

    def test_real_dmg_mount_and_copy_preserve_signed_tree(self):
        before = packaging.tree(self.app)
        output = self.root / "Lens-development.dmg"
        report = dmg.package(self.app, output, development=True)
        self.assertFalse(report["gatekeeper_ready"])
        self.assertTrue(report["read_only_mount"])
        self.assertTrue(report["mounted_tree_match"])
        self.assertTrue(report["copied_tree_match"])
        self.assertEqual(packaging.tree(self.app), before)
        self.assertTrue(output.with_suffix(".verification.json").is_file())

    def test_dmg_release_refuses_adhoc_and_preserves_existing_output(self):
        with self.assertRaisesRegex(dmg.common.PackageError, "Developer ID"):
            dmg.package(self.app, self.root / "Lens.dmg")
        output = self.root / "Lens-development.dmg"
        output.write_bytes(b"older artifact")
        with self.assertRaisesRegex(dmg.common.PackageError, "new"):
            dmg.package(self.app, output, development=True)
        self.assertEqual(output.read_bytes(), b"older artifact")


if __name__ == "__main__":
    unittest.main(verbosity=2)
