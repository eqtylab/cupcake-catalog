# METADATA
# scope: package
# description: Helper functions for secure command analysis
package cupcake.catalog.security_hardened.helpers.commands

import rego.v1

# Check if command contains a specific verb with proper word boundary anchoring
# This prevents bypass via extra whitespace: "git  commit" or "  git commit"
has_verb(command, verb) if {
	pattern := concat("", ["(^|\\s)", verb, "(\\s|$)"])
	regex.match(pattern, command)
}

# Check if command contains ANY of the verbs from a set
has_any_verb(command, verb_set) if {
	some verb in verb_set
	has_verb(command, verb)
}

# Check if command contains a specific flag
has_flag(command, flag) if {
	# Match flag with word boundaries
	pattern := concat("", ["(^|\\s)", flag, "(\\s|$|=)"])
	regex.match(pattern, command)
}

# Check if command has any of the specified flags
has_any_flag(command, flag_set) if {
	some flag in flag_set
	has_flag(command, flag)
}

# Detect output redirection operators
has_output_redirect(command) if {
	redirect_patterns := [
		`\s>\s`,
		`\s>>\s`,
		`\s\|\s`,
		`(^|\s)tee(\s|$)`,
	]
	some pattern in redirect_patterns
	regex.match(pattern, command)
}

# Check if command targets root filesystem
targets_root(command) if {
	root_patterns := [
		`\s/\s`,
		`\s/$`,
		`^/\s`,
		`^/$`,
		`\s/\*`,
	]
	some pattern in root_patterns
	regex.match(pattern, command)
}

# Check if command uses sudo
uses_sudo(command) if {
	has_verb(command, "sudo")
}
