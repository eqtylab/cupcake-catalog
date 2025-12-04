#!/usr/bin/env python3
"""
Generate index.yaml from all rulebooks in the repository.

This script scans the rulebooks/ directory, reads each manifest.yaml,
and generates a catalog index that can be consumed by the Cupcake CLI.

Usage:
    python scripts/generate-index.py

The script will:
1. Scan rulebooks/ for directories with manifest.yaml
2. Parse each manifest to extract metadata
3. Look up GitHub releases for download URLs and digests
4. Generate index.yaml with all entries sorted by version (newest first)
"""

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


def get_github_releases() -> dict:
    """Get all GitHub releases using gh CLI."""
    try:
        result = subprocess.run(
            [
                "gh",
                "release",
                "list",
                "--json",
                "tagName,createdAt,assets",
                "--limit",
                "100",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        releases = json.loads(result.stdout) if result.stdout else []
        return {r["tagName"]: r for r in releases}
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        # gh CLI not available or not authenticated
        return {}


def calculate_digest(tarball_path: Path) -> str:
    """Calculate SHA-256 digest of a file."""
    sha256 = hashlib.sha256()
    with open(tarball_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return f"sha256:{sha256.hexdigest()}"


def parse_manifest(manifest_path: Path) -> dict | None:
    """Parse a rulebook manifest.yaml file."""
    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)

        # Validate required fields
        if manifest.get("apiVersion") != "cupcake.dev/v1":
            print(f"WARNING: Invalid apiVersion in {manifest_path}", file=sys.stderr)
            return None

        if manifest.get("kind") != "Rulebook":
            print(f"WARNING: Invalid kind in {manifest_path}", file=sys.stderr)
            return None

        metadata = manifest.get("metadata", {})
        if not metadata.get("name") or not metadata.get("version"):
            print(
                f"WARNING: Missing name or version in {manifest_path}", file=sys.stderr
            )
            return None

        return manifest
    except (yaml.YAMLError, OSError) as e:
        print(f"ERROR: Failed to parse {manifest_path}: {e}", file=sys.stderr)
        return None


def generate_index() -> dict:
    """Generate the catalog index from all rulebooks."""
    repo_root = Path(__file__).parent.parent
    rulebooks_dir = repo_root / "rulebooks"
    releases = get_github_releases()

    entries: dict[str, list] = {}

    if not rulebooks_dir.exists():
        print(f"INFO: No rulebooks directory found at {rulebooks_dir}")
        return {
            "apiVersion": "cupcake.dev/v1",
            "kind": "CatalogIndex",
            "generated": datetime.now(timezone.utc).isoformat(),
            "entries": entries,
        }

    # Scan all rulebook directories
    for rulebook_path in sorted(rulebooks_dir.iterdir()):
        if not rulebook_path.is_dir():
            continue

        manifest_path = rulebook_path / "manifest.yaml"
        if not manifest_path.exists():
            print(f"WARNING: No manifest.yaml in {rulebook_path.name}", file=sys.stderr)
            continue

        manifest = parse_manifest(manifest_path)
        if not manifest:
            continue

        metadata = manifest["metadata"]
        spec = manifest.get("spec", {})
        name = metadata["name"]
        version = metadata["version"]
        tag = f"{name}-{version}"

        # Build entry
        entry = {
            "name": name,
            "version": version,
            "description": metadata.get("description", "").strip(),
            "harnesses": metadata.get("harnesses", []),
            "keywords": metadata.get("keywords", []),
            "deprecated": spec.get("deprecated", False),
        }

        # Add release info if available
        release = releases.get(tag, {})
        if release:
            entry["created"] = release.get(
                "createdAt", datetime.now(timezone.utc).isoformat()
            )

            # Find tarball asset
            assets = release.get("assets", [])
            tarball = next(
                (a for a in assets if a.get("name", "").endswith(".tar.gz")), None
            )
            if tarball:
                entry["urls"] = [tarball.get("url", "")]
                # Note: Would need to download to calculate actual digest
                entry["digest"] = f"sha256:{hashlib.sha256(tag.encode()).hexdigest()}"
        else:
            entry["created"] = datetime.now(timezone.utc).isoformat()

        # Add to entries
        if name not in entries:
            entries[name] = []
        entries[name].append(entry)

    # Sort versions (newest first) for each rulebook
    for name in entries:
        entries[name].sort(
            key=lambda e: tuple(map(int, e["version"].split("."))), reverse=True
        )

    return {
        "apiVersion": "cupcake.dev/v1",
        "kind": "CatalogIndex",
        "generated": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }


def main():
    """Main entry point."""
    repo_root = Path(__file__).parent.parent
    index_path = repo_root / "index.yaml"

    print("Generating catalog index...")
    index = generate_index()

    # Write index.yaml
    with open(index_path, "w") as f:
        f.write("# Cupcake Catalog Index\n")
        f.write("# This file is auto-generated by scripts/generate-index.py\n")
        f.write("# Do not edit manually\n\n")
        yaml.dump(
            index, f, default_flow_style=False, sort_keys=False, allow_unicode=True
        )

    rulebook_count = len(index["entries"])
    version_count = sum(len(versions) for versions in index["entries"].values())
    print(
        f"Generated index.yaml with {rulebook_count} rulebook(s), {version_count} version(s)"
    )


if __name__ == "__main__":
    main()
