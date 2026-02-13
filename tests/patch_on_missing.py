#!/usr/bin/env python3
"""Patch on_missing strategy for a specific path in a SCMM YAML policy."""
import sys
import yaml

if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <policy.yaml> <path> <strategy>", file=sys.stderr)
    sys.exit(1)

policy_file, target_path, strategy = sys.argv[1], sys.argv[2], sys.argv[3]

with open(policy_file) as f:
    pol = yaml.safe_load(f)

found = False
for rule in pol.get("filesystem", {}).get("rules", []):
    if rule["path"] == target_path:
        rule["on_missing"] = strategy
        found = True

if not found:
    print(f"Warning: path '{target_path}' not found in policy", file=sys.stderr)
    sys.exit(1)

with open(policy_file, "w") as f:
    yaml.dump(pol, f, default_flow_style=False, sort_keys=False)
