#!/bin/bash

# Define root directory
ROOT_DIR="/root/AlynCoin"

echo "Starting batch cleanup of unused imports and variables..."

##########################################
# 1. Remove unused imports (alloc::vec, Debug, FieldElement, etc.)
##########################################
echo "Removing unused imports..."

find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/use alloc::vec/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/use alloc::vec::Vec/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/use core::fmt::Debug/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/FieldElement/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/BaseElement/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/Hasher/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/Assertion/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/DeserializeOwned/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/Box;/d' {} +
find $ROOT_DIR -type f -name "*.rs" -exec sed -i '/String;/d' {} +

##########################################
# 2. Comment unused constant GENERATOR
##########################################
echo "Commenting unused constants..."
sed -i 's/const GENERATOR/\/\/ const GENERATOR/' $ROOT_DIR/alyn-math/src/fields/f64/mod.rs

##########################################
# 3. Replace unused variables with _var
##########################################
echo "Renaming unused variables..."
# Replace 'for l in' -> 'for _ in'
find $ROOT_DIR -type f -name "fft.rs" -exec sed -i 's/for l in/for _ in/' {} +
# Replace 'frame:' with '_frame:'
find $ROOT_DIR -type f -name "transition.rs" -exec sed -i 's/frame:/_frame:/' {} +

##########################################
# 4. Optional cargo fix pass
##########################################
echo "Running cargo fix pass..."
cd $ROOT_DIR/src/rust
cargo fix --allow-dirty --allow-staged --lib -p alyn-utils
cargo fix --allow-dirty --allow-staged --lib -p alyn-math
cargo fix --allow-dirty --allow-staged --lib -p alyn-crypto
cargo fix --allow-dirty --allow-staged --lib -p alyn-air

echo "Cleanup completed successfully ✅"
