# METADATA
# scope: package
# custom:
#   entrypoint: true
package cupcake.catalog.security_hardened.system

import rego.v1

# Aggregation entrypoint for catalog policies
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
		walk(data.cupcake.catalog.security_hardened.policies, [path, value])
		path[count(path) - 1] == verb_name
	]
	all_decisions := [decision |
		some verb_set in verb_sets
		some decision in verb_set
	]
	result := all_decisions
}

default collect_verbs(_) := []
