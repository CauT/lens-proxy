#!/usr/bin/env python3
"""Build a read-only DMG and verify its mounted and copied application.

Default mode requires Developer ID, stapling and Gatekeeper. Preview builds
must explicitly select --development-only and include development in the name.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location("lens_package", Path(__file__).with_name("package-app.py"))
common = importlib.util.module_from_spec(spec)
spec.loader.exec_module(common)


def package(app, output, development=False):
    app, output = app.resolve(strict=True), output.resolve()
    if app.suffix != ".app" or not app.is_dir():
        raise common.PackageError("Input must be an application bundle")
    if output.suffix != ".dmg" or (development and "development" not in output.stem):
        raise common.PackageError("Use .dmg; development output must include development in its name")
    report_path = output.with_suffix(".verification.json")
    if output.is_relative_to(app) or output.exists() or report_path.exists():
        raise common.PackageError("Output must be new and outside the application")
    before = common.tree(app)
    signature = common.verify(app, development)
    output.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".lens-dmg-", dir=output.parent))
    mounted = None
    try:
        stage, mount = work / "stage", work / "mounted"
        stage.mkdir(); mount.mkdir()
        common.run("/usr/bin/ditto", "--norsrc", "--noextattr", str(app), str(stage / "Lens.app"))
        (stage / "Applications").symlink_to("/Applications")
        (stage / "Read Me.txt").write_text(
            "Lens for macOS\n\nDrag Lens.app into Applications, then eject this disk.\n"
            "Requires macOS 14 or later and the matching CPU architecture.\n\n" +
            ("EXPERIMENTAL PREVIEW: ad-hoc signed, NOT Developer ID signed or notarized.\n"
             "macOS may block opening this download. Source builds are available.\n"
             if development else "Developer ID and notarization verified during packaging.\n") +
            "\nSetup and source: https://github.com/CauT/lens-proxy\n"
            "Lens changes system proxy or certificate trust only with your explicit setup.\n"
            "For device capture, configure the device proxy; keep your Mac route intact.\n")
        image = work / output.name
        common.run("/usr/bin/hdiutil", "create", "-fs", "HFS+", "-format", "UDZO",
                   "-volname", "Lens Preview" if development else "Lens", "-srcfolder", str(stage), str(image))
        common.run("/usr/bin/hdiutil", "verify", str(image))
        mounted = mount
        attachment = common.run("/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen",
                                "-mountpoint", str(mount), "-plist", str(image))
        entities = plistlib.loads(attachment.encode())["system-entities"]
        if not any(item.get("mount-point") == str(mount) for item in entities):
            raise common.PackageError("DMG did not mount at its owned mount point")
        if sorted(p.name for p in mount.iterdir() if not p.name.startswith(".")) != ["Applications", "Lens.app", "Read Me.txt"]:
            raise common.PackageError("Unexpected files in DMG")
        if not (mount / "Applications").is_symlink() or os.readlink(mount / "Applications") != "/Applications":
            raise common.PackageError("Invalid Applications shortcut")
        if common.tree(mount / "Lens.app") != before:
            raise common.PackageError("Mounted application differs from source")
        common.verify(mount / "Lens.app", development)
        copied = work / "copied" / "Lens.app"
        common.run("/usr/bin/ditto", "--norsrc", "--noextattr", str(mount / "Lens.app"), str(copied))
        if common.tree(copied) != before:
            raise common.PackageError("Copied application differs from source")
        common.verify(copied, development)
        common.run("/usr/bin/hdiutil", "detach", str(mount))
        mounted = None
        if common.tree(app) != before:
            raise common.PackageError("Source changed while packaging")
        report = {"archive": output.name, "sha256": common.sha256(image), "bytes": image.stat().st_size,
                  "mode": "development-only" if development else "release", "gatekeeper_ready": not development,
                  "tree_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
                  "read_only_mount": True, "mounted_tree_match": True, "copied_tree_match": True,
                  "strict_deep_signature": "passed", "metadata_entries": 0,
                  "signature": [line for line in signature.splitlines() if line.startswith(
                      ("Identifier=", "Signature=", "Authority=", "TeamIdentifier=", "CDHash=", "Timestamp="))]}
        os.link(image, output)
        with report_path.open("x") as stream:
            json.dump(report, stream, indent=2); stream.write("\n")
        return report
    finally:
        if mounted is not None:
            try:
                common.run("/usr/bin/hdiutil", "detach", str(mounted))
                mounted = None
            except (common.PackageError, subprocess.TimeoutExpired):
                # Keep ownership and files for a later unmount; never delete a mounted tree.
                raise common.PackageError(f"Unmount failed; retained owned work directory: {work}")
        if mounted is None:
            shutil.rmtree(work)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--development-only", action="store_true")
    args = parser.parse_args()
    try:
        result = package(args.app, args.output, args.development_only)
    except (common.PackageError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"DMG packaging refused: {error}\n")
    print(json.dumps(result, indent=2))
