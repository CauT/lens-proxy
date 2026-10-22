#!/usr/bin/env python3
"""Package a signed app, then verify the actual ZIP using two macOS extractors.

Release mode requires Developer ID, a stapled ticket and Gatekeeper acceptance.
Explicit development mode verifies integrity but makes no distribution claim.
The source app is never modified or re-signed by this command.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import tempfile
import zipfile


class PackageError(Exception):
    pass


def run(*command):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=180)
    if result.returncode:
        # codesign may list thousands of added resources in a contaminated app.
        detail = (result.stdout + result.stderr).splitlines()
        raise PackageError(f"{command[0]} failed ({result.returncode}):\n" +
                           "\n".join(detail[:8]))
    return result.stdout + result.stderr


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree(app):
    """Own the archive identity: paths, types, modes, symlink targets and bytes."""
    app = app.resolve(strict=True)
    entries = {}
    for parent, directories, files in os.walk(app, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            relative = path.relative_to(app).as_posix()
            if name.startswith("._") or name in ("__MACOSX", ".DS_Store"):
                raise PackageError(f"Unexpected metadata file in signed app: {relative}")
            mode = path.lstat().st_mode
            item = {"mode": stat.S_IMODE(mode)}
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                if Path(target).is_absolute() or not path.resolve().is_relative_to(app):
                    raise PackageError(f"Non-relocatable symlink: {relative}")
                item.update(type="symlink", target=target)
            elif stat.S_ISDIR(mode):
                item.update(type="directory")
            elif stat.S_ISREG(mode):
                item.update(type="file", sha256=sha256(path))
            else:
                raise PackageError(f"Unsupported bundle entry: {relative}")
            entries[relative] = item
    return entries


def verify(app, development):
    run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app))
    description = run("/usr/bin/codesign", "--display", "--verbose=4", str(app))
    if not development:
        if "Authority=Developer ID Application:" not in description:
            raise PackageError("Release requires a Developer ID Application signature; "
                               "ad-hoc builds must use --development-only.")
        run("/usr/bin/xcrun", "stapler", "validate", str(app))
        run("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(app))
    return description


def package(app, output, development=False):
    app = app.resolve(strict=True)
    output = output.resolve()
    if app.suffix != ".app" or not app.is_dir():
        raise PackageError("Input must be a .app directory")
    if output.suffix != ".zip" or (development and "development" not in output.stem):
        raise PackageError("Output must end in .zip; development archives must include "
                           "'development' in their filename")
    if output.is_relative_to(app):
        raise PackageError("Output must be outside the signed app")
    report_path = output.with_suffix(".verification.json")
    if output.exists() or report_path.exists():
        raise PackageError("Refusing to overwrite an existing archive or verification report")
    before = tree(app)
    signature = verify(app, development)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Keep temporary files on the output volume. Nothing is published until every
    # check passes; never repair an extracted bundle to make verification pass.
    with tempfile.TemporaryDirectory(prefix=".lens-package-", dir=output.parent) as work:
        work = Path(work)
        archive = work / output.name
        run("/usr/bin/ditto", "-c", "-k", "--norsrc", "--noextattr", "--keepParent",
            str(app), str(archive))
        with zipfile.ZipFile(archive) as zipped:
            names = zipped.namelist()
            if len(names) != len(set(names)):
                raise PackageError("Duplicate ZIP entries")
            for name in names:
                parts = Path(name).parts
                if not parts or parts[0] != app.name or ".." in parts or any(
                        part.startswith("._") or part in ("__MACOSX", ".DS_Store") for part in parts):
                    raise PackageError(f"Unexpected ZIP entry: {name}")
            if zipped.testzip() is not None:
                raise PackageError("ZIP CRC verification failed")
        extractors = []
        for name in ("ditto", "unzip"):
            destination = work / name
            destination.mkdir()
            if name == "ditto":
                run("/usr/bin/ditto", "-x", "-k", str(archive), str(destination))
            else:
                run("/usr/bin/unzip", "-q", str(archive), "-d", str(destination))
            restored = destination / app.name
            if tree(restored) != before:
                raise PackageError(f"Bundle bytes, symlinks or modes changed after {name} extraction")
            verify(restored, development)
            extractors.append({"extractor": name, "exact_tree_match": True,
                               "strict_deep_signature": "passed"})
        if tree(app) != before:
            raise PackageError("Source bundle changed while packaging")
        report = {
            "mode": "development-only" if development else "release",
            "gatekeeper_ready": not development,
            "notice": ("Ad-hoc/development integrity only; not Developer ID/notarization "
                       "or browser-download installation acceptance." if development else
                       "Developer ID, stapled ticket and Gatekeeper assessment passed."),
            "archive": output.name, "sha256": sha256(archive),
            "bytes": archive.stat().st_size, "entries": len(names), "metadata_entries": 0,
            "tree_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
            "signature": [line for line in signature.splitlines() if line.startswith(
                ("Identifier=", "Format=", "CodeDirectory ", "Signature=", "Authority=",
                 "TeamIdentifier=", "CDHash=", "Timestamp=", "Sealed Resources "))],
            "extractions": extractors,
            "system": platform.mac_ver()[0],
        }
        # Hard-link publication is atomic and fails if another run claimed the
        # destination in the meantime; the temporary copy is then cleaned up.
        os.link(archive, output)
        with report_path.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--development-only", action="store_true",
                        help="explicitly allow non-notarized development output")
    args = parser.parse_args()
    try:
        report = package(args.app, args.output, args.development_only)
    except (PackageError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
        parser.exit(1, f"Packaging refused: {error}\n")
    print(json.dumps({key: report[key] for key in
                      ("archive", "sha256", "bytes", "mode", "gatekeeper_ready")}))


if __name__ == "__main__":
    main()
