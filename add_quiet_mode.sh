#!/bin/bash

echo "🔧 Fixing quietPrint/debugPrint string concatenation issues..."

find src -type f \( -name "*.cpp" -o -name "*.h" \) -print0 | while IFS= read -r -d '' file; do
  sed -i -E 's/(quietPrint|debugPrint)\(([^;]*?)<<([^;]*?)\);/\1(\2 + \3);/g' "$file"
done

echo "✅ Fixed concatenation issues."
