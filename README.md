# Cupcake Catalog

The official registry of rulebooks for [Cupcake](https://github.com/eqtylab/cupcake), the policy engine for AI coding agents.

## What is Cupcake Catalog?

Cupcake Catalog is a centralized registry for discovering, sharing, and installing policy rulebooks. Instead of writing Rego policies from scratch, you can install battle-tested rulebooks with a single command.

**Key Benefits:**

- **For Users**: Instantly adopt security policies without Rego expertise
- **For Organizations**: Share rulebooks across teams and projects
- **For the Community**: Contribute and collaborate on open-source policies

## Quick Start

### Prerequisites

- [Cupcake](https://github.com/eqtylab/cupcake) v0.5.0 or later
- A project with `.cupcake/` initialized

### Browse Available Rulebooks

```bash
# Search all rulebooks
cupcake catalog search

# Filter by harness
cupcake catalog search --harness claude

# Show details of a specific rulebook
cupcake catalog show security-hardened
```

### Install a Rulebook

```bash
# Install the latest version
cupcake catalog install security-hardened

# Install a specific version
cupcake catalog install security-hardened@1.0.0

# List installed rulebooks
cupcake catalog list
```

### Upgrade and Manage

```bash
# Upgrade a rulebook to latest
cupcake catalog upgrade security-hardened

# Upgrade all installed rulebooks
cupcake catalog upgrade

# Remove a rulebook
cupcake catalog uninstall security-hardened
```

## How It Works

Catalog rulebooks are installed as **overlays** in `.cupcake/catalog/`. They never modify your existing configuration:

```
.cupcake/
├── rulebook.yml           # Your config (untouched)
├── policies/              # Your policies (untouched)
├── catalog/               # Installed catalog rulebooks
│   └── security-hardened/
│       ├── manifest.yaml
│       ├── rulebook.yml
│       ├── system/
│       │   └── evaluate.rego   # Shared entrypoint
│       ├── helpers/
│       │   └── commands.rego   # Shared helpers
│       └── policies/
│           ├── claude/         # Harness-specific policies
│           ├── cursor/
│           ├── opencode/
│           └── factory/
└── catalog.lock           # Version tracking
```

### Policy Load Order

Cupcake evaluates policies in this order:

1. **Global** (`~/.config/cupcake/`) - Organization-wide, highest priority
2. **Catalog** (`.cupcake/catalog/`) - Installed rulebooks
3. **Project** (`.cupcake/policies/`) - Your custom policies

Your project policies can override catalog defaults. Global policies cannot be overridden.

### Namespace Isolation

Catalog policies use isolated namespaces to prevent conflicts:

```
cupcake.catalog.<rulebook_name>.policies.*   # Policy rules
cupcake.catalog.<rulebook_name>.helpers.*    # Shared helpers
cupcake.catalog.<rulebook_name>.system       # Aggregation entrypoint
```

This means:

- No collisions between rulebooks
- Clear attribution in decision traces
- Safe upgrades that don't affect your policies

## Available Rulebooks

| Rulebook                                            | Description                        | Harnesses                         |
| --------------------------------------------------- | ---------------------------------- | --------------------------------- |
| [security-hardened](./rulebooks/security-hardened/) | Production-ready security policies | Claude, Cursor, OpenCode, Factory |
| [git-workflow](./rulebooks/git-workflow/)           | Git best practices enforcement     | All                               |

[Browse all rulebooks](https://catalog.cupcake.dev)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for:

- How to create a new rulebook
- Manifest schema reference
- Validation requirements
- The PR review process

### Quick Contribution Guide

1. Fork this repository
2. Create your rulebook in `rulebooks/<name>/`
3. Run `cupcake catalog lint rulebooks/<name>` to validate
4. Open a pull request

## Custom Registries

Organizations can host private registries:

```bash
# Add a private registry
cupcake catalog repo add internal https://registry.mycompany.com/index.yaml

# Install from specific registry
cupcake catalog install internal/security-compliance

# List configured registries
cupcake catalog repo list
```

## Documentation

- [Getting Started Guide](https://cupcake.dev/docs/catalog/getting-started)
- [CLI Reference](https://cupcake.dev/docs/catalog/cli-reference)
- [Rulebook Author Guide](https://cupcake.dev/docs/catalog/authoring)
- [API Reference](https://cupcake.dev/docs/catalog/api)

## Security

- All downloads are verified against SHA-256 digests
- Catalog policies cannot override your project policies
- Version locking ensures reproducible installations
- All rulebooks go through PR review before publication

Report security issues to security@eqtylab.io

## License

This repository is licensed under the [Apache License 2.0](./LICENSE).

Individual rulebooks may have their own licenses specified in their `manifest.yaml`.
