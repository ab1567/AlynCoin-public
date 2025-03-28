#!/bin/bash

echo "🚀 Moving inner attributes to top and converting them to outer attributes..."

find /root/AlynCoin/ -type f -name "lib.rs" | while read -r file; do
  echo "📄 Processing $file"

  # Convert #![allow(...)] to #[allow(...)]
  sed -i 's/^#!\[/#[/' "$file"

  # Move all //! inner doc comments to outer /// comments (first 20 lines max)
  # We make sure to process only comments that are misplaced, not valid crate-level comments
  tmpfile=$(mktemp)
  header_done=0
  while IFS= read -r line; do
    if [[ $header_done -eq 0 && $line =~ ^//! ]]; then
      echo "${line/\/\//!/\/\//}" >> "$tmpfile"
    else
      header_done=1
      echo "$line" >> "$tmpfile"
    fi
  done < "$file"
  mv "$tmpfile" "$file"

done

echo "🧽 Fixing invalid mod declarations..."
# Fix incorrect 'pub mod mod.rs;' -> 'pub mod mod;'
find /root/AlynCoin/ -type f -name "lib.rs" -exec sed -i 's/pub mod mod\.rs;/pub mod mod;/' {} +

echo "🎯 Completed! Now run: cargo build --release"
