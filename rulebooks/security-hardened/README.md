# security-hardened

Production-ready security policies that protect against common dangerous operations while maintaining developer productivity.

## Overview

This rulebook provides a comprehensive set of security policies designed for production environments. It blocks dangerous commands, prevents bypass of safety mechanisms, and requires confirmation for potentially destructive operations.

## Installation

```bash
cupcake catalog install security-hardened
```

## What's Included

### Policies

| Policy               | Description                                                                  | Severity |
| -------------------- | ---------------------------------------------------------------------------- | -------- |
| `dangerous_commands` | Blocks commands like `rm -rf /`, `mkfs`, `dd if=/dev/zero`                   | CRITICAL |
| `dangerous_flags`    | Blocks dangerous flags like `--no-verify`, `--force` on destructive commands | HIGH     |
| `destructive_git`    | Requires confirmation for `git reset --hard`, `git push --force`             | MEDIUM   |

### Decision Types

- **halt**: Used for critical security violations (CRITICAL severity)
- **deny**: Used for high-risk operations (HIGH severity)
- **ask**: Used for potentially destructive but sometimes necessary operations (MEDIUM severity)

## Supported Harnesses

- Claude Code
- Cursor
- OpenCode
- Factory

## Configuration

This rulebook works out of the box with sensible defaults. You can customize behavior by overriding in your `.cupcake/rulebook.yml`:

```yaml
# .cupcake/rulebook.yml
# Your settings take precedence over catalog defaults
builtins:
  # Add your own protected paths
  protected_paths:
    enabled: true
    paths:
      - "/production/"
      - "secrets/"
```

## Policies Explained

### dangerous_commands (CRITICAL)

Blocks commands that can cause catastrophic system damage:

- `rm -rf /` and variations (`rm -rf /*`, `rm -rf ~`)
- Disk formatting (`mkfs`, `fdisk`)
- Disk wiping (`dd if=/dev/zero`)
- Fork bombs (`:(){:|:&};:`)
- System shutdown/reboot
- chmod 777 on sensitive directories

**Example blocked commands:**

```bash
rm -rf /                    # Blocked: Recursive delete of root
sudo mkfs.ext4 /dev/sda1   # Blocked: Disk formatting
dd if=/dev/zero of=/dev/sda # Blocked: Disk wiping
chmod -R 777 /              # Blocked: Dangerous permissions
```

### dangerous_flags (HIGH)

Blocks dangerous flags that bypass safety mechanisms:

- `--no-verify` on git operations
- `--force` on package removal
- `--skip-lock` on package managers
- `-y` combined with system-wide operations

**Example blocked commands:**

```bash
git commit --no-verify      # Blocked: Bypasses git hooks
npm install --ignore-scripts --force  # Blocked: Dangerous combination
apt remove -y --force-yes   # Blocked: Force remove without confirmation
```

### destructive_git (MEDIUM)

Requires user confirmation for potentially destructive git operations:

- `git reset --hard`
- `git push --force` / `git push -f`
- `git clean -fd`
- `git checkout -- .`

**Example interactions:**

```bash
git reset --hard HEAD~5     # Ask: "This will discard 5 commits. Continue?"
git push --force            # Ask: "Force push can overwrite remote history. Continue?"
```

## Rule IDs

All decisions include a `rule_id` for traceability:

| Rule ID           | Policy             | Severity |
| ----------------- | ------------------ | -------- |
| `CATALOG-SEC-001` | dangerous_commands | CRITICAL |
| `CATALOG-SEC-002` | dangerous_flags    | HIGH     |
| `CATALOG-SEC-003` | destructive_git    | MEDIUM   |

## Customization

### Disabling Specific Rules

You can override specific behaviors in your project's policies:

```rego
# .cupcake/policies/claude/overrides/allow_force_push.rego
package cupcake.policies.overrides

import rego.v1

# Allow force push for this specific repository
allow_override contains decision if {
    input.tool_name == "Bash"
    contains(input.tool_input.command, "git push --force")
    # Only for specific branch
    contains(input.tool_input.command, "feature/")

    decision := {
        "rule_id": "OVERRIDE-FORCE-PUSH",
        "reason": "Force push allowed for feature branches",
        "severity": "LOW",
    }
}
```

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history.

## License

Apache-2.0
