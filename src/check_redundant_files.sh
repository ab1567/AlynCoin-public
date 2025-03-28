#!/bin/bash

echo "🔍 Checking usage of Possibly Redundant files/folders..."

declare -a TARGETS=("libSTARK" "XKCP-master" "backup" "backup_old_stark" "master.zip" "generated" "keys")

for target in "${TARGETS[@]}"; do
    echo -e "\n===== Searching for '$target' ====="
    grep -r --color=always "$target" ~/AlynCoin/ || echo "✅ No usage found for '$target'"
done

echo -e "\n✅ Scan complete."
