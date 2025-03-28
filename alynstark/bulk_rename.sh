#!/bin/bash
echo "Renaming Winterfell to AlynSTARK..."

# Rename crate and dependencies in Cargo.toml
find . -name "Cargo.toml" -exec sed -i 's/winterfell/alynstark/g; s/winter-/alyn-/g' {} +

# Rename Rust imports and references in .rs files
find . -name "*.rs" -exec sed -i 's/winterfell/alynstark/g; s/winter_/alyn_/g; s/winter-/alyn-/g' {} +

echo "✅ Renaming Completed!"
