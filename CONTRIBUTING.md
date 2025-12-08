# Contributing to Cupcake Catalog

Thank you for your interest in contributing to Cupcake Catalog! This guide will help you create and submit rulebooks.

## Table of Contents

1. [Creating a Rulebook](#creating-a-rulebook)
2. [Manifest Schema](#manifest-schema)
3. [Policy Structure](#policy-structure)
4. [Namespace Convention](#namespace-convention)
5. [Validation](#validation)
6. [Pull Request Process](#pull-request-process)
7. [Release Process](#release-process)

---

## Creating a Rulebook

### Directory Structure

Each rulebook lives in `rulebooks/<name>/` with this structure:

```
rulebooks/my-rulebook/
├── manifest.yaml               # Required: Metadata
├── README.md                   # Required: Documentation
├── CHANGELOG.md                # Recommended: Version history
├── rulebook.yml                # Optional: Signals, actions, builtins
├── system/
│   └── evaluate.rego           # Required: Shared aggregation entrypoint
├── helpers/                    # Optional: Shared helper functions
│   └── *.rego
└── policies/
    ├── claude/                 # Policies for Claude Code
    │   └── *.rego              # Your policy files (flat structure)
    ├── cursor/                 # Policies for Cursor
    │   └── *.rego
    ├── opencode/               # Policies for OpenCode
    │   └── *.rego
    └── factory/                # Policies for Factory
        └── *.rego
```

Key points:
- `system/evaluate.rego` is at the **rulebook root** (shared across all harnesses)
- `helpers/` contains shared Rego functions used by policies
- Policy files go **directly** in `policies/<harness>/` (no `builtins/` subdirectory)

### Naming Rules

- Rulebook names must be lowercase alphanumeric with hyphens
- Valid: `security-hardened`, `git-workflow`, `python-dev`
- Invalid: `Security_Hardened`, `myRulebook`, `my rulebook`

---

## Manifest Schema

The `manifest.yaml` file defines your rulebook's metadata:

```yaml
# manifest.yaml
apiVersion: cupcake.dev/v1
kind: Rulebook

metadata:
  # Required fields
  name: my-rulebook              # Unique identifier
  version: 1.0.0                 # Semantic version
  description: |
    A brief description of what this rulebook does.
    Can be multiple lines.

  # Supported harnesses (at least one required)
  harnesses:
    - claude
    - cursor
    - opencode
    - factory

  # Optional fields
  keywords:
    - security
    - workflow

  license: Apache-2.0

  maintainers:
    - name: Your Name
      email: you@example.com
      url: https://github.com/yourusername

  homepage: https://github.com/eqtylab/cupcake-catalog
  repository: https://github.com/eqtylab/cupcake-catalog

spec:
  # Minimum Cupcake version required
  cupcakeVersion: ">=0.5.0"

  # Deprecation (optional)
  deprecated: false
  deprecationWarning: ""
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `apiVersion` | Yes | Must be `cupcake.dev/v1` |
| `kind` | Yes | Must be `Rulebook` |
| `metadata.name` | Yes | Lowercase alphanumeric with hyphens |
| `metadata.version` | Yes | Semantic version (e.g., `1.2.3`) |
| `metadata.description` | Yes | At least 10 characters |
| `metadata.harnesses` | Yes | Array with at least one of: `claude`, `cursor`, `opencode`, `factory` |
| `metadata.keywords` | No | Array of searchable keywords |
| `metadata.license` | No | SPDX license identifier |
| `metadata.maintainers` | No | Array of maintainer objects |
| `spec.cupcakeVersion` | No | Semver range for compatibility |
| `spec.deprecated` | No | Boolean to mark as deprecated |

---

## Policy Structure

### The Aggregation Entrypoint

Each rulebook needs a single `system/evaluate.rego` file at the **root level** that aggregates decisions across all harnesses:

```rego
# system/evaluate.rego

# METADATA
# scope: package
# custom:
#   entrypoint: true
package cupcake.catalog.my_rulebook.system

import rego.v1

evaluate := {
    "halts": collect_verbs("halt"),
    "denials": collect_verbs("deny"),
    "blocks": collect_verbs("block"),
    "asks": collect_verbs("ask"),
    "allow_overrides": collect_verbs("allow_override"),
    "add_context": collect_verbs("add_context"),
}

collect_verbs(verb_name) := result if {
    verb_sets := [value |
        walk(data.cupcake.catalog.my_rulebook.policies, [path, value])
        path[count(path) - 1] == verb_name
    ]
    all_decisions := [decision |
        some verb_set in verb_sets
        some decision in verb_set
    ]
    result := all_decisions
}

default collect_verbs(_) := []
```

**Important**: Replace `my_rulebook` with your rulebook name (underscores, not hyphens).

### Policy Files

Individual policies go **directly** in `policies/<harness>/`:

```rego
# policies/claude/dangerous_commands.rego

# METADATA
# scope: package
# title: Block Dangerous Commands
# custom:
#   severity: CRITICAL
#   id: MY-SEC-001
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["Bash"]
package cupcake.catalog.my_rulebook.policies.dangerous_commands

import rego.v1

deny contains decision if {
    input.hook_event_name == "PreToolUse"
    input.tool_name == "Bash"
    contains(input.tool_input.command, "rm -rf /")
    
    decision := {
        "rule_id": "MY-SEC-001",
        "reason": "Blocked dangerous recursive delete command",
        "severity": "CRITICAL",
    }
}
```

### Helper Functions

Shared helper functions go in `helpers/` at the rulebook root:

```rego
# helpers/commands.rego
package cupcake.catalog.my_rulebook.helpers.commands

import rego.v1

# Check if command contains a specific verb
has_verb(command, verb) if {
    pattern := concat("", ["(^|\\s)", verb, "(\\s|$)"])
    regex.match(pattern, command)
}
```

Import helpers in your policies:

```rego
import data.cupcake.catalog.my_rulebook.helpers.commands

deny contains decision if {
    commands.has_verb(input.tool_input.command, "rm")
    # ...
}
```

### Decision Verbs

Use these verbs in your policies (priority order):

| Verb | Priority | Description |
|------|----------|-------------|
| `halt` | Highest | Critical security violation, stops immediately |
| `deny` | High | Blocks the operation with an error |
| `block` | High | Alternative to deny |
| `ask` | Medium | Prompts user for confirmation |
| `allow_override` | Low | Explicitly permits an operation |
| `add_context` | Info | Injects context into the conversation |

### Decision Object Fields

```rego
decision := {
    "rule_id": "MY-SEC-001",      # Required: Unique identifier
    "reason": "Why this fired",   # Required: Human-readable explanation
    "severity": "HIGH",           # Required: CRITICAL, HIGH, MEDIUM, LOW
    "question": "Confirm?",       # Required for ask verb only
}
```

---

## Namespace Convention

**All files MUST use these namespace patterns:**

| Directory | Namespace Pattern | Example |
|-----------|-------------------|---------|
| `policies/<harness>/` | `cupcake.catalog.<name>.policies.<policy>` | `cupcake.catalog.my_rulebook.policies.dangerous_commands` |
| `helpers/` | `cupcake.catalog.<name>.helpers.<helper>` | `cupcake.catalog.my_rulebook.helpers.commands` |
| `system/` | `cupcake.catalog.<name>.system` | `cupcake.catalog.my_rulebook.system` |

For a rulebook named `my-rulebook`:
- System: `cupcake.catalog.my_rulebook.system`
- Helpers: `cupcake.catalog.my_rulebook.helpers.*`
- Policies: `cupcake.catalog.my_rulebook.policies.*`

**Note**: Use underscores in package names (Rego requirement), not hyphens.

### Why Namespaces Matter

1. **No conflicts** between different rulebooks
2. **Clear attribution** in decision traces
3. **Safe upgrades** that don't affect user policies

---

## Validation

Before submitting, validate your rulebook locally:

```bash
# Validate manifest and structure
cupcake catalog lint rulebooks/my-rulebook

# Check Rego syntax
opa fmt --diff rulebooks/my-rulebook/policies/
opa check rulebooks/my-rulebook/policies/

# Run policy tests (if you have them)
opa test rulebooks/my-rulebook/policies/ -v
```

### Validation Checks

The PR validation workflow checks:

1. **Manifest schema** - Valid YAML, required fields present
2. **Rego syntax** - All `.rego` files parse correctly
3. **Namespace compliance** - Packages use correct `cupcake.catalog.<name>.*` patterns
4. **Harness directories** - Policy files exist for declared harnesses
5. **System entrypoint** - `system/evaluate.rego` exists at rulebook root
6. **Version bump** - Version increased from previous release

---

## Pull Request Process

### Before Opening a PR

1. **Fork** this repository
2. **Create a branch**: `git checkout -b add-my-rulebook`
3. **Create your rulebook** in `rulebooks/<name>/`
4. **Validate locally**: `cupcake catalog lint rulebooks/<name>`
5. **Commit**: `git commit -m "feat: add my-rulebook rulebook"`

### PR Requirements

- [ ] Rulebook is in `rulebooks/<name>/` directory
- [ ] `manifest.yaml` is valid and complete
- [ ] `README.md` documents the rulebook
- [ ] Policies exist for all declared harnesses
- [ ] All validation checks pass
- [ ] Version is appropriate (new rulebook = 0.1.0 or 1.0.0)

### Review Process

1. **Automated checks** run on PR creation
2. **Maintainer review** for security and quality
3. **Feedback addressed** if any
4. **Merge** to main branch
5. **Automatic release** creates GitHub release and updates index

---

## Release Process

Releases are automated via GitHub Actions:

1. **PR merged** to `main` branch
2. **release.yml** workflow triggers
3. **Tarball created**: `<name>-<version>.tar.gz`
4. **GitHub release** created with tag `<name>-<version>`
5. **index.yaml** regenerated and committed
6. **GitHub Pages** updated with new index

### Version Bumping

- **Patch** (1.0.0 → 1.0.1): Bug fixes, documentation
- **Minor** (1.0.0 → 1.1.0): New policies, new harness support
- **Major** (1.0.0 → 2.0.0): Breaking changes, removed policies

---

## Best Practices

### Policy Design

1. **Include comprehensive metadata** with routing directives
2. **Use clear, actionable reason messages**
3. **Include rule_id** for traceability
4. **Handle edge cases** gracefully
5. **Document configuration options** in README

### Security

1. **Use canonical paths** (`input.resolved_file_path`) to prevent symlink bypass
2. **Use word-boundary matching** for command detection
3. **Be conservative** - deny by default, allow explicitly
4. **Test thoroughly** with malicious inputs

### Documentation

1. **Explain what the rulebook does** and why
2. **List all policies** with their purposes
3. **Document configuration options** if using `rulebook.yml`
4. **Provide examples** of blocked and allowed operations
5. **Include a changelog** for version history

---

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/eqtylab/cupcake-catalog/discussions)
- **Bugs**: Open an [Issue](https://github.com/eqtylab/cupcake-catalog/issues)
- **Security**: Email security@eqtylab.io

Thank you for contributing to Cupcake Catalog!
