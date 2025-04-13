#!/bin/bash

echo "🔁 Replacing deprecated Blockchain singleton calls..."

# Replace getInstanceNoDB with correct call
find ./src -type f \( -name "*.cpp" -o -name "*.h" \) -exec sed -i 's|Blockchain::getInstanceNoDB()|Blockchain::getInstance(8333, "", false)|g' {} +

# Replace getInstanceNoNetwork with correct call
find ./src -type f \( -name "*.cpp" -o -name "*.h" \) -exec sed -i 's|Blockchain::getInstanceNoNetwork()|Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), false)|g' {} +

# Replace Network::getExistingInstance()->getBlockchain() with proper Blockchain::getInstance
find ./src -type f \( -name "*.cpp" -o -name "*.h" \) -exec sed -i 's|Network::getExistingInstance()->getBlockchain()|Blockchain::getInstance(8333, DBPaths::getBlockchainDB(), true)|g' {} +

echo "✅ Replacement complete!"
