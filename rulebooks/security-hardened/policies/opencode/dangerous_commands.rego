# METADATA
# scope: package
# title: Block Dangerous Commands
# authors: ["Cupcake Catalog"]
# custom:
#   severity: CRITICAL
#   id: CATALOG-SEC-001
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["Bash"]
package cupcake.catalog.security_hardened.policies.dangerous_commands

import data.cupcake.catalog.security_hardened.helpers.commands
import rego.v1

# Block recursive delete of root or home
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	# Match rm -rf with dangerous targets
	commands.has_verb(cmd, "rm")
	contains(cmd, "-r")
	contains(cmd, "-f")

	# Check for dangerous targets
	dangerous_rm_targets := [
		` /`,
		` /*`,
		` ~/`,
		` ~/*`,
		`"/"`,
		`'/'`,
	]
	some target in dangerous_rm_targets
	contains(cmd, target)

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked dangerous recursive delete command that could destroy the filesystem",
		"severity": "CRITICAL",
	}
}

# Block disk formatting commands
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	format_commands := {"mkfs", "fdisk", "parted", "gdisk"}
	commands.has_any_verb(cmd, format_commands)

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked disk formatting command - this could destroy data",
		"severity": "CRITICAL",
	}
}

# Block disk wiping commands
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "dd")
	contains(cmd, "if=/dev/zero")

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked disk wiping command (dd with /dev/zero)",
		"severity": "CRITICAL",
	}
}

# Block dd writing to block devices
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "dd")
	contains(cmd, "of=/dev/")

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked dd command writing to block device",
		"severity": "CRITICAL",
	}
}

# Block fork bombs
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := input.tool_input.command

	# Common fork bomb patterns
	fork_bomb_patterns := [
		":(){ :|:& };:",
		":(){ :|: & };:",
		"./$0|./$0&",
	]
	some pattern in fork_bomb_patterns
	contains(cmd, pattern)

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked fork bomb - this would crash the system",
		"severity": "CRITICAL",
	}
}

# Block system shutdown/reboot
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	shutdown_commands := {"shutdown", "reboot", "poweroff", "halt", "init 0", "init 6"}
	commands.has_any_verb(cmd, shutdown_commands)

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked system shutdown/reboot command",
		"severity": "CRITICAL",
	}
}

# Block dangerous chmod on system directories
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "chmod")
	contains(cmd, "777")

	# Check for dangerous target paths
	dangerous_chmod_targets := ["/", "/etc", "/usr", "/bin", "/sbin", "/var"]
	some target in dangerous_chmod_targets
	contains(cmd, target)

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked chmod 777 on system directory - this is a security risk",
		"severity": "CRITICAL",
	}
}

# Block recursive chmod 777
halt contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "chmod")
	contains(cmd, "-r")
	contains(cmd, "777")

	decision := {
		"rule_id": "CATALOG-SEC-001",
		"reason": "Blocked recursive chmod 777 - this is a major security risk",
		"severity": "CRITICAL",
	}
}
