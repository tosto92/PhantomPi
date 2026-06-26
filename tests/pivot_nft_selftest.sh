#!/usr/bin/env bash
set -euo pipefail

script="implant/scripts/pivot-nft.sh"

test -x "$script"
bash -n "$script"
"$script" --help | grep -q "Usage: pivot-nft"
