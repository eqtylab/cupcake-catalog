#!/usr/bin/env python3
"""
Validate that all Rego policies use the correct namespace.

Catalog policies MUST use the namespace pattern:
    cupcake.catalog.<rulebook_name>.policies.*
    cupcake.catalog.<rulebook_name>.system

This script validates:
1. All .rego files have package declarations
2. Package names follow the catalog namespace convention
3. No conflicts with reserved namespaces (cupcake.policies, cupcake.global)

Usage:
    python scripts/validate-namespace.py rulebooks/my-rulebook

Exit codes:
    0 - All namespaces valid
    1 - Namespace violations found
"""

import re
import sys
from pathlib import Path

import yaml

# Pattern to extract package declaration
PACKAGE_PATTERN = re.compile(r"^\s*package\s+([\w.]+)", re.MULTILINE)

# Reserved namespace prefixes that catalog policies must NOT use
RESERVED_PREFIXES = [
    "cupcake.policies",
    "cupcake.global",
    "cupcake.system",
    "cupcake.helpers",
]


def get_rulebook_name(rulebook_path: Path) -> str | None:
    """Get the rulebook name from manifest.yaml."""
    manifest_path = rulebook_path / "manifest.yaml"
    if not manifest_path.exists():
        return None

    try:
        with open(manifest_path) as f:
            manifest = yaml.safe_load(f)
        return manifest.get("metadata", {}).get("name")
    except (yaml.YAMLError, OSError):
        return None


def normalize_name(name: str) -> str:
    """Convert rulebook name to Rego-compatible format (hyphens to underscores)."""
    return name.replace("-", "_")


def validate_policy_file(
    policy_path: Path, expected_prefix: str, rulebook_path: Path
) -> list[str]:
    """Validate a single policy file's namespace. Returns list of errors."""
    errors = []

    try:
        content = policy_path.read_text()
    except OSError as e:
        return [f"Cannot read {policy_path}: {e}"]

    # Find package declaration
    match = PACKAGE_PATTERN.search(content)
    if not match:
        errors.append(
            f"{policy_path.relative_to(rulebook_path)}: No package declaration found"
        )
        return errors

    package = match.group(1)

    # Check for reserved namespace violation
    for reserved in RESERVED_PREFIXES:
        if package.startswith(reserved):
            errors.append(
                f"{policy_path.relative_to(rulebook_path)}: "
                f"Package '{package}' uses reserved namespace '{reserved}'. "
                f"Use '{expected_prefix}.*' instead."
            )
            return errors

    # Check for correct catalog namespace
    if not package.startswith(expected_prefix):
        # Allow system packages
        system_prefix = expected_prefix.replace(".policies", ".system")
        if not package.startswith(system_prefix) and not package.startswith(
            expected_prefix.rsplit(".", 1)[0] + ".system"
        ):
            errors.append(
                f"{policy_path.relative_to(rulebook_path)}: "
                f"Package '{package}' must start with '{expected_prefix}' or '{system_prefix}'"
            )

    return errors


def validate_namespace(rulebook_path: Path) -> list[str]:
    """Validate all policy files in a rulebook. Returns list of errors."""
    errors = []

    # Get rulebook name
    name = get_rulebook_name(rulebook_path)
    if not name:
        return ["Cannot determine rulebook name from manifest.yaml"]

    normalized_name = normalize_name(name)
    expected_prefix = f"cupcake.catalog.{normalized_name}.policies"

    # Find all .rego files
    policies_dir = rulebook_path / "policies"
    if not policies_dir.exists():
        return ["No policies/ directory found"]

    rego_files = list(policies_dir.rglob("*.rego"))
    if not rego_files:
        return ["No .rego files found in policies/"]

    # Validate each file
    for policy_path in rego_files:
        errors.extend(validate_policy_file(policy_path, expected_prefix, rulebook_path))

    return errors


def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: validate-namespace.py <rulebook-path>", file=sys.stderr)
        sys.exit(1)

    rulebook_path = Path(sys.argv[1])

    if not rulebook_path.exists():
        print(f"ERROR: Path does not exist: {rulebook_path}", file=sys.stderr)
        sys.exit(1)

    if not rulebook_path.is_dir():
        print(f"ERROR: Path is not a directory: {rulebook_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Validating namespaces: {rulebook_path.name}")
    print("-" * 40)

    errors = validate_namespace(rulebook_path)

    for error in errors:
        print(f"ERROR: {error}")

    print("-" * 40)

    if errors:
        print(f"FAILED: {len(errors)} namespace violation(s)")
        sys.exit(1)
    else:
        print("PASSED: All namespaces valid")
        sys.exit(0)


if __name__ == "__main__":
    main()
