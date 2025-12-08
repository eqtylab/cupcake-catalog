#!/usr/bin/env python3
"""
Validate a rulebook's manifest.yaml and structure.

This script validates:
1. manifest.yaml schema compliance
2. Required files exist (README.md)
3. Policy directories exist for declared harnesses
4. system/evaluate.rego exists at rulebook root (shared entrypoint)

Usage:
    python scripts/validate-rulebook.py rulebooks/my-rulebook

Exit codes:
    0 - Validation passed
    1 - Validation failed
"""

import re
import sys
from pathlib import Path

import yaml

# JSON Schema-like validation (simplified)
VALID_HARNESSES = {"claude", "cursor", "opencode", "factory"}
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")
VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+")


class ValidationError(Exception):
    """Validation error with message."""

    pass


def validate_manifest(manifest: dict, rulebook_path: Path) -> list[str]:
    """Validate manifest.yaml contents. Returns list of errors."""
    errors = []

    # Check apiVersion
    if manifest.get("apiVersion") != "cupcake.dev/v1":
        errors.append(
            f"apiVersion must be 'cupcake.dev/v1', got '{manifest.get('apiVersion')}'"
        )

    # Check kind
    if manifest.get("kind") != "Rulebook":
        errors.append(f"kind must be 'Rulebook', got '{manifest.get('kind')}'")

    # Check metadata
    metadata = manifest.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("metadata is required and must be an object")
        return errors  # Can't continue without metadata

    # Check name
    name = metadata.get("name")
    if not name:
        errors.append("metadata.name is required")
    elif not NAME_PATTERN.match(name):
        errors.append(
            f"metadata.name must be lowercase alphanumeric with hyphens, got '{name}'"
        )
    elif name != rulebook_path.name:
        errors.append(
            f"metadata.name '{name}' must match directory name '{rulebook_path.name}'"
        )

    # Check version
    version = metadata.get("version")
    if not version:
        errors.append("metadata.version is required")
    elif not VERSION_PATTERN.match(str(version)):
        errors.append(f"metadata.version must be semver (e.g., 1.0.0), got '{version}'")

    # Check description
    description = metadata.get("description")
    if not description:
        errors.append("metadata.description is required")
    elif len(str(description).strip()) < 10:
        errors.append("metadata.description must be at least 10 characters")

    # Check harnesses
    harnesses = metadata.get("harnesses")
    if not harnesses:
        errors.append("metadata.harnesses is required")
    elif not isinstance(harnesses, list):
        errors.append("metadata.harnesses must be an array")
    elif len(harnesses) == 0:
        errors.append("metadata.harnesses must contain at least one harness")
    else:
        for harness in harnesses:
            if harness not in VALID_HARNESSES:
                errors.append(
                    f"Invalid harness '{harness}'. Valid: {sorted(VALID_HARNESSES)}"
                )

    # Check maintainers (optional but validate if present)
    maintainers = metadata.get("maintainers", [])
    if maintainers and isinstance(maintainers, list):
        for i, m in enumerate(maintainers):
            if not isinstance(m, dict):
                errors.append(f"metadata.maintainers[{i}] must be an object")
            elif not m.get("name"):
                errors.append(f"metadata.maintainers[{i}].name is required")

    return errors


def validate_structure(rulebook_path: Path, harnesses: list[str]) -> list[str]:
    """Validate rulebook directory structure. Returns list of errors."""
    errors = []

    # Check README.md exists
    readme_path = rulebook_path / "README.md"
    if not readme_path.exists():
        errors.append("README.md is required")

    # Check policies directory
    policies_dir = rulebook_path / "policies"
    if not policies_dir.exists():
        errors.append("policies/ directory is required")
        return errors  # Can't continue without policies

    # Check system/evaluate.rego at root level (shared across all harnesses)
    evaluate_path = rulebook_path / "system" / "evaluate.rego"
    if not evaluate_path.exists():
        errors.append("Missing system/evaluate.rego at rulebook root")

    # Check each declared harness has a policy directory
    for harness in harnesses:
        harness_dir = policies_dir / harness
        if not harness_dir.exists():
            errors.append(f"Missing policies/{harness}/ directory for declared harness")
            continue

        # Check that harness directory has at least one .rego file
        rego_files = list(harness_dir.glob("*.rego"))
        if not rego_files:
            errors.append(f"No .rego policy files in policies/{harness}/")

    return errors


def validate_rulebook(rulebook_path: Path) -> tuple[list[str], list[str]]:
    """
    Validate a rulebook.

    Returns:
        Tuple of (errors, warnings)
    """
    errors = []
    warnings = []

    # Check manifest exists
    manifest_path = rulebook_path / "manifest.yaml"
    if not manifest_path.exists():
        return [f"manifest.yaml not found in {rulebook_path}"], []

    # Parse manifest
    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"Invalid YAML in manifest.yaml: {e}"], []

    if not manifest:
        return ["manifest.yaml is empty"], []

    # Validate manifest
    errors.extend(validate_manifest(manifest, rulebook_path))

    # Get harnesses for structure validation
    harnesses = manifest.get("metadata", {}).get("harnesses", [])
    if harnesses and isinstance(harnesses, list):
        errors.extend(validate_structure(rulebook_path, harnesses))

    # Check for optional files (warnings only)
    if not (rulebook_path / "CHANGELOG.md").exists():
        warnings.append("CHANGELOG.md is recommended for tracking version history")

    return errors, warnings


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: validate-rulebook.py <rulebook-path>", file=sys.stderr)
        sys.exit(1)

    rulebook_path = Path(sys.argv[1])

    if not rulebook_path.exists():
        print(f"ERROR: Path does not exist: {rulebook_path}", file=sys.stderr)
        sys.exit(1)

    if not rulebook_path.is_dir():
        print(f"ERROR: Path is not a directory: {rulebook_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Validating rulebook: {rulebook_path.name}")
    print("-" * 40)

    errors, warnings = validate_rulebook(rulebook_path)

    # Print warnings
    for warning in warnings:
        print(f"WARNING: {warning}")

    # Print errors
    for error in errors:
        print(f"ERROR: {error}")

    print("-" * 40)

    if errors:
        print(f"FAILED: {len(errors)} error(s), {len(warnings)} warning(s)")
        sys.exit(1)
    else:
        print(f"PASSED: 0 errors, {len(warnings)} warning(s)")
        sys.exit(0)


if __name__ == "__main__":
    main()
