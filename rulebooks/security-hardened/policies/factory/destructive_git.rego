# METADATA
# scope: package
# title: Require Confirmation for Destructive Git Operations
# authors: ["Cupcake Catalog"]
# custom:
#   severity: MEDIUM
#   id: CATALOG-SEC-003
#   routing:
#     required_events: ["PreToolUse"]
#     required_tools: ["Bash"]
package cupcake.catalog.security_hardened.policies.destructive_git

import data.cupcake.catalog.security_hardened.helpers.commands
import rego.v1

# Ask before git reset --hard
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "git")
	commands.has_verb(cmd, "reset")
	commands.has_flag(cmd, "--hard")

	decision := {
		"rule_id": "CATALOG-SEC-003",
		"reason": "git reset --hard will discard uncommitted changes permanently",
		"question": "This will permanently discard all uncommitted changes. Are you sure you want to continue?",
		"severity": "MEDIUM",
	}
}

# Ask before git push --force
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "git")
	commands.has_verb(cmd, "push")

	force_flags := {"--force", "-f", "--force-with-lease"}
	commands.has_any_flag(cmd, force_flags)

	decision := {
		"rule_id": "CATALOG-SEC-003",
		"reason": "Force pushing can overwrite remote history and affect other collaborators",
		"question": "Force push can overwrite remote history. Other collaborators may lose their work. Continue?",
		"severity": "MEDIUM",
	}
}

# Ask before git clean -fd (removes untracked files)
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "git")
	commands.has_verb(cmd, "clean")
	commands.has_flag(cmd, "-f")

	# Only ask if also removing directories or all untracked
	contains(cmd, "-d")

	decision := {
		"rule_id": "CATALOG-SEC-003",
		"reason": "git clean -fd will permanently delete untracked files and directories",
		"question": "This will permanently delete all untracked files and directories. Continue?",
		"severity": "MEDIUM",
	}
}

# Ask before git checkout -- . (discards all changes)
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "git")
	commands.has_verb(cmd, "checkout")
	contains(cmd, "-- .")

	decision := {
		"rule_id": "CATALOG-SEC-003",
		"reason": "git checkout -- . will discard all unstaged changes",
		"question": "This will discard all unstaged changes in the working directory. Continue?",
		"severity": "MEDIUM",
	}
}

# Ask before git stash drop/clear
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "git")
	commands.has_verb(cmd, "stash")

	drop_commands := {"drop", "clear"}
	commands.has_any_verb(cmd, drop_commands)

	decision := {
		"rule_id": "CATALOG-SEC-003",
		"reason": "This will permanently delete stashed changes",
		"question": "Stashed changes will be permanently deleted. Continue?",
		"severity": "MEDIUM",
	}
}

# Ask before git branch -D (force delete)
ask contains decision if {
	input.hook_event_name == "PreToolUse"
	input.tool_name == "Bash"

	cmd := lower(input.tool_input.command)

	commands.has_verb(cmd, "git")
	commands.has_verb(cmd, "branch")
	commands.has_flag(cmd, "-D")

	decision := {
		"rule_id": "CATALOG-SEC-003",
		"reason": "Force deleting a branch may cause loss of unmerged commits",
		"question": "This will force delete the branch, potentially losing unmerged commits. Continue?",
		"severity": "MEDIUM",
	}
}
