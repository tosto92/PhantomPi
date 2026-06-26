#!/usr/bin/env bash
set -euo pipefail

script="implant/scripts/pivot-conntrack.sh"

test -x "$script"
bash -n "$script"
"$script" --help | grep -q "Usage: pivot-conntrack"
