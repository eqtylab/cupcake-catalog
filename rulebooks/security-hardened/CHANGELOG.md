# Changelog

All notable changes to the `security-hardened` rulebook will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-04

### Added

- Initial release
- `dangerous_commands` policy - blocks catastrophic commands (CRITICAL)
  - `rm -rf /` and variations
  - Disk formatting commands (`mkfs`, `fdisk`)
  - Disk wiping commands (`dd if=/dev/zero`)
  - Fork bombs
  - System shutdown/reboot commands
  - Dangerous chmod operations
- `dangerous_flags` policy - blocks dangerous flag combinations (HIGH)
  - `--no-verify` on git operations
  - `--force` on package removal
  - Dangerous npm/yarn flags
- `destructive_git` policy - requires confirmation for risky git operations (MEDIUM)
  - `git reset --hard`
  - `git push --force`
  - `git clean -fd`
- Support for all harnesses: Claude, Cursor, OpenCode, Factory
- Helper library for secure command analysis
