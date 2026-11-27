#!/usr/bin/env python3
"""fetch_sources.py - Declarative source downloader and verifier.

Reads configs/projects/sources.yaml and fetches/verifies source repositories
via git clone/checkout or archive download/hash verification.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
SOURCES_YAML_DEFAULT = ROOT_DIR / "configs/projects/sources.yaml"
SOURCES_DIR = ROOT_DIR / "sources"


def download_url(url: str, dest_file: Path) -> bool:
    print(f"  [DOWNLOAD] {url} -> {dest_file}...")
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) TargetGraph-Fetch/1.0",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp, open(dest_file, "wb") as out:
            shutil.copyfileobj(resp, out)
        return True
    except Exception as e:
        print(f"  [ERROR] Failed to download {url}: {e}", file=sys.stderr)
        return False


def verify_sha256(file_path: Path, expected_sha256: str) -> bool:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    actual = h.hexdigest().lower()
    expected = expected_sha256.lower().strip()
    if actual != expected:
        print(f"  [ERROR] SHA256 mismatch for {file_path}!\n    Expected: {expected}\n    Actual:   {actual}", file=sys.stderr)
        return False
    return True


def extract_archive(archive_file: Path, dest_dir: Path) -> bool:
    print(f"  [EXTRACT] {archive_file} -> {dest_dir}...")
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        try:
            if archive_file.name.endswith(".zip"):
                import zipfile
                with zipfile.ZipFile(archive_file, "r") as z:
                    z.extractall(tmp_path)
            else:
                subprocess.run(
                    ["tar", "-xf", str(archive_file), "-C", str(tmp_path)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
        except Exception as e:
            print(f"  [ERROR] Failed to extract {archive_file}: {e}", file=sys.stderr)
            return False

        items = list(tmp_path.iterdir())
        if len(items) == 1 and items[0].is_dir():
            src_root = items[0]
        else:
            src_root = tmp_path

        for item in src_root.iterdir():
            target = dest_dir / item.name
            if target.exists():
                if target.is_dir():
                    shutil.rmtree(target)
                else:
                    target.unlink()
            shutil.move(str(item), str(target))

    return True


def setup_sources_symlink(source_id: str, local_path: Path, sources_dir: Path) -> None:
    sources_dir.mkdir(parents=True, exist_ok=True)
    link = sources_dir / source_id
    if link.is_symlink():
        if link.resolve() == local_path.resolve():
            return
        link.unlink()
    elif link.exists():
        if link.is_dir():
            shutil.rmtree(link)
        else:
            link.unlink()
    os.symlink(local_path, link)


def fetch_single_source(
    source_id: str,
    source_meta: Dict[str, Any],
    root_dir: Path,
    force: bool = False,
    verify_only: bool = False,
) -> bool:
    local_path = (root_dir / source_meta["local_path"]).resolve()
    upstream_type = source_meta.get("upstream_type")
    upstream_url = source_meta.get("upstream_url")
    git_commit = source_meta.get("git_commit")
    archive_sha256 = source_meta.get("archive_sha256")

    print(f"=== [{source_id}] (Type: {upstream_type}) ===")
    print(f"  Local Path: {local_path}")

    if upstream_type == "git":
        if not upstream_url or not git_commit:
            print(f"  [ERROR] git source requires upstream_url and git_commit", file=sys.stderr)
            return False

        git_dir = local_path / ".git"
        if git_dir.is_dir():
            # Check current commit
            r = subprocess.run(["git", "-C", str(local_path), "rev-parse", "HEAD"], capture_output=True, text=True)
            current_commit = r.stdout.strip()
            if current_commit == git_commit:
                print(f"  [OK] Valid git repo at exact commit {git_commit}")
                setup_sources_symlink(source_id, local_path, root_dir / "sources")
                return True
            else:
                if verify_only:
                    print(f"  [MISMATCH] Current {current_commit} != Expected {git_commit}", file=sys.stderr)
                    return False
                print(f"  [CHECKOUT] Checking out target commit {git_commit}...")
                # Fetch and checkout
                subprocess.run(["git", "-C", str(local_path), "fetch", "origin"], check=False)
                res = subprocess.run(["git", "-C", str(local_path), "checkout", git_commit], capture_output=True, text=True)
                if res.returncode == 0:
                    print(f"  [OK] Checked out {git_commit}")
                    setup_sources_symlink(source_id, local_path, root_dir / "sources")
                    return True
                print(f"  [WARN] Failed to checkout {git_commit}: {res.stderr.strip()}; re-cloning...", file=sys.stderr)

        if verify_only:
            print(f"  [MISSING] Source not found at {local_path}", file=sys.stderr)
            return False

        if local_path.exists() and force:
            shutil.rmtree(local_path)

        local_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"  [CLONE] git clone {upstream_url} -> {local_path}")
        clone_res = subprocess.run(["git", "clone", upstream_url, str(local_path)], capture_output=True, text=True)
        if clone_res.returncode != 0:
            print(f"  [ERROR] git clone failed: {clone_res.stderr.strip()}", file=sys.stderr)
            return False

        print(f"  [CHECKOUT] git checkout {git_commit}")
        co_res = subprocess.run(["git", "-C", str(local_path), "checkout", git_commit], capture_output=True, text=True)
        if co_res.returncode != 0:
            print(f"  [ERROR] git checkout failed: {co_res.stderr.strip()}", file=sys.stderr)
            return False

        setup_sources_symlink(source_id, local_path, root_dir / "sources")
        print(f"  [SUCCESS] Successfully fetched and checked out {source_id}")
        return True

    elif upstream_type == "archive":
        if not upstream_url:
            print(f"  [ERROR] archive source requires upstream_url", file=sys.stderr)
            return False

        if local_path.is_dir() and any(local_path.iterdir()) and not force:
            print(f"  [OK] Archive source already extracted at {local_path}")
            setup_sources_symlink(source_id, local_path, root_dir / "sources")
            return True

        if verify_only:
            print(f"  [MISSING] Archive source not present at {local_path}", file=sys.stderr)
            return False

        if local_path.exists() and force:
            shutil.rmtree(local_path)

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tf:
            tmp_archive = Path(tf.name)

        try:
            if not download_url(upstream_url, tmp_archive):
                return False

            if archive_sha256:
                if not verify_sha256(tmp_archive, archive_sha256):
                    return False

            if not extract_archive(tmp_archive, local_path):
                return False

            setup_sources_symlink(source_id, local_path, root_dir / "sources")
            print(f"  [SUCCESS] Successfully downloaded and extracted {source_id}")
            return True
        finally:
            if tmp_archive.exists():
                tmp_archive.unlink()

    else:
        print(f"  [ERROR] Unsupported upstream_type: {upstream_type}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sources-yaml",
        type=Path,
        default=SOURCES_YAML_DEFAULT,
        help="Path to sources.yaml",
    )
    parser.add_argument(
        "--source",
        type=str,
        help="Fetch/verify a specific source ID",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-fetch/download even if directory exists",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify existing directories and commits without network downloads",
    )
    args = parser.parse_args()

    with open(args.sources_yaml, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    sources = data.get("sources", {})

    target_keys = [args.source] if args.source else sorted(sources.keys())
    if args.source and args.source not in sources:
        print(f"Error: Source '{args.source}' not found in {args.sources_yaml}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {len(target_keys)} sources (verify_only={args.verify_only}, force={args.force})...\n")

    failed: List[str] = []
    for sid in target_keys:
        meta = sources[sid]
        ok = fetch_single_source(sid, meta, ROOT_DIR, force=args.force, verify_only=args.verify_only)
        if not ok:
            failed.append(sid)

    print("\n========================================================")
    print(f"Summary: {len(target_keys) - len(failed)}/{len(target_keys)} succeeded.")
    if failed:
        print(f"Failed sources: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)
    else:
        print("All requested sources are verified and ready.")


if __name__ == "__main__":
    main()
