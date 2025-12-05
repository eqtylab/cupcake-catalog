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


def get_release_tags() -> list[str]:
    """Get all release tags using gh CLI."""
    try:
        result = subprocess.run(
            [
                "gh",
                "release",
                "list",
                "--json",
                "tagName",
                "--limit",
                "100",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        releases = json.loads(result.stdout) if result.stdout else []
        return [r["tagName"] for r in releases]
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        # gh CLI not available or not authenticated
        return []


def get_release_info(tag: str) -> dict | None:
    """Get detailed release info for a specific tag using gh CLI.

    Uses 'gh release view' which provides asset details including
    download URLs and digests.
    """
    try:
        result = subprocess.run(
            [
                "gh",
                "release",
                "view",
                tag,
                "--json",
                "tagName,createdAt,assets",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(result.stdout) if result.stdout else None
    except (subprocess.CalledProcessError, FileNotFoundError, json.JSONDecodeError):
        return None


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

    # Get list of available release tags
    release_tags = set(get_release_tags())
    print(f"Found {len(release_tags)} release(s) on GitHub")

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

        # Add release info if available (using gh release view for full details)
        if tag in release_tags:
            release = get_release_info(tag)
            if release:
                entry["created"] = release.get(
                    "createdAt", datetime.now(timezone.utc).isoformat()
                )

                # Find tarball asset - gh release view provides full asset details
                assets = release.get("assets", [])
                tarball = next(
                    (a for a in assets if a.get("name", "").endswith(".tar.gz")), None
                )
                if tarball:
                    # Use the download URL from the asset
                    entry["urls"] = [tarball.get("url", "")]
                    # Use the digest from GitHub if available, otherwise generate placeholder
                    if tarball.get("digest"):
                        entry["digest"] = tarball["digest"]
                    else:
                        entry["digest"] = (
                            f"sha256:{hashlib.sha256(tag.encode()).hexdigest()}"
                        )
                    print(f"  Found release assets for {tag}")
                else:
                    print(
                        f"  WARNING: No tarball asset found for {tag}", file=sys.stderr
                    )
            else:
                entry["created"] = datetime.now(timezone.utc).isoformat()
                print(
                    f"  WARNING: Could not fetch release info for {tag}",
                    file=sys.stderr,
                )
        else:
            entry["created"] = datetime.now(timezone.utc).isoformat()
            print(f"  INFO: No release found for {tag} (will be created on merge)")

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
