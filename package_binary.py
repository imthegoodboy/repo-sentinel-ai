"""Package a PyInstaller build in the archive layout expected by Anna."""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    executable_name = "tool-dev-repo-sentinel-ai.exe" if args.platform.startswith("windows-") else "tool-dev-repo-sentinel-ai"
    source = root / "dist" / executable_name
    if not source.is_file():
        raise FileNotFoundError(source)
    staging = root / "build" / f"package-{args.platform}"
    if staging.exists():
        shutil.rmtree(staging)
    destination = staging / "bin" / executable_name
    destination.parent.mkdir(parents=True)
    shutil.copy2(source, destination)
    if not args.platform.startswith("windows-"):
        destination.chmod(0o755)
    base = root / "dist" / f"repo-sentinel-auditor-1.0.1-{args.platform}"
    archive_format = "zip" if args.platform.startswith("windows-") else "gztar"
    archive = shutil.make_archive(str(base), archive_format, root_dir=staging)
    print(os.path.relpath(archive, root))


if __name__ == "__main__":
    main()
