# METADATA
# scope: package
# title: Block Dangerous Flags (Cursor)
# authors: ["Cupcake Catalog"]
# custom:
#   severity: HIGH
#   id: CATALOG-SEC-002
#   routing:
#     required_events: ["beforeShellExecution"]
package cupcake.catalog.security_hardened.policies.dangerous_flags

import data.cupcake.catalog.security_hardened.helpers.commands
import rego.v1

# Block git --no-verify
deny contains decision if {
	input.hook_event_name == "beforeShellExecution"

	cmd := lower(input.command)

	commands.has_verb(cmd, "git")
	commands.has_flag(cmd, "--no-verify")

	decision := {
		"rule_id": "CATALOG-SEC-002",
		"reason": "Blocked --no-verify flag on git command - this bypasses important safety hooks",
		"severity": "HIGH",
	}
}

# Block git -n (short for --no-verify)
deny contains decision if {
	input.hook_event_name == "beforeShellExecution"

	cmd := lower(input.command)

	commands.has_verb(cmd, "git")
	git_commands_with_n := {"commit", "push"}
	commands.has_any_verb(cmd, git_commands_with_n)
	commands.has_flag(cmd, "-n")

	decision := {
		"rule_id": "CATALOG-SEC-002",
		"reason": "Blocked -n flag on git command - this bypasses safety hooks",
		"severity": "HIGH",
	}
}

# Block npm/yarn with dangerous flag combinations
deny contains decision if {
	input.hook_event_name == "beforeShellExecution"

	cmd := lower(input.command)

	npm_commands := {"npm", "yarn", "pnpm"}
	commands.has_any_verb(cmd, npm_commands)
	commands.has_flag(cmd, "--ignore-scripts")
	commands.has_flag(cmd, "--force")

	decision := {
		"rule_id": "CATALOG-SEC-002",
		"reason": "Blocked dangerous npm/yarn flag combination (--ignore-scripts --force)",
		"severity": "HIGH",
	}
}

# Block apt/yum with force flags
deny contains decision if {
	input.hook_event_name == "beforeShellExecution"

	cmd := lower(input.command)

	pkg_managers := {"apt", "apt-get", "yum", "dnf"}
	commands.has_any_verb(cmd, pkg_managers)
	commands.has_verb(cmd, "remove")

	force_flags := {"--force-yes", "--allow-remove-essential"}
	commands.has_any_flag(cmd, force_flags)

	decision := {
		"rule_id": "CATALOG-SEC-002",
		"reason": "Blocked dangerous package removal with force flags",
		"severity": "HIGH",
	}
}

# Block pip with --trusted-host on unknown domains
deny contains decision if {
	input.hook_event_name == "beforeShellExecution"

	cmd := lower(input.command)

	commands.has_verb(cmd, "pip")
	commands.has_flag(cmd, "--trusted-host")

	not contains(cmd, "pypi.org")
	not contains(cmd, "pypi.python.org")
	not contains(cmd, "files.pythonhosted.org")

	decision := {
		"rule_id": "CATALOG-SEC-002",
		"reason": "Blocked pip --trusted-host for unknown domain - potential security risk",
		"severity": "HIGH",
	}
}

# Block curl/wget piped to bash with insecure flags
deny contains decision if {
	input.hook_event_name == "beforeShellExecution"

	cmd := lower(input.command)

	download_tools := {"curl", "wget"}
	commands.has_any_verb(cmd, download_tools)

	insecure_flags := {"--insecure", "-k", "--no-check-certificate"}
	commands.has_any_flag(cmd, insecure_flags)

	contains(cmd, "| bash")

	decision := {
		"rule_id": "CATALOG-SEC-002",
		"reason": "Blocked insecure download piped to shell - this is a major security risk",
		"severity": "HIGH",
	}
}
