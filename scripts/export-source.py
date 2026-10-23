#!/usr/bin/env python3
"""Export only tracked Lens source and public documentation into a new folder."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FOLDERS = ("Sources/", "engine/", "tests/", "scripts/", ".github/", "docs/guide/")
FILES = {"README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "VERSION",
         "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", ".gitignore",
         "docs/images/README.md", "docs/images/lens-icon.png",
         "docs/images/setup-guide-english.jpg", "docs/images/phone-setup-english.jpg"}


def export(destination):
    destination = destination.absolute()
    if destination.exists():
        raise ValueError("Destination already exists; previous exports are preserved")
    repository = Path(subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"], text=True).strip())
    prefix = ROOT.relative_to(repository)
    paths = subprocess.check_output(["git", "-C", str(repository), "ls-files", "-z", "--", str(prefix)]).decode().split("\0")
    selected = []
    for name in filter(None, paths):
        source = repository / name
        relative = source.relative_to(ROOT).as_posix()
        if relative not in FILES and not relative.startswith(FOLDERS):
            continue
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"Only regular tracked files can be published: {relative}")
        if any(part.startswith('.') and part != '.github' and relative != '.gitignore' for part in Path(relative).parts):
            raise ValueError(f"Unexpected hidden source path: {relative}")
        selected.append((source, relative))
    if not FILES.issubset({relative for _, relative in selected}):
        raise ValueError("Stage/commit every required public source file before exporting")
    destination.mkdir(parents=True)
    manifest = []
    for source, relative in sorted(selected, key=lambda item: item[1]):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        manifest.append({"path": relative, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    origin = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
    dirty = bool(subprocess.check_output(["git", "-C", str(repository), "status", "--porcelain", "--", str(prefix)]))
    report = {"source_commit": origin, "source_dirty": dirty, "files": manifest}
    (destination / "SOURCE_PROVENANCE.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"destination": str(destination), "files": len(manifest), "source_commit": origin, "source_dirty": dirty}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    export(args.destination)
