#!/bin/bash

# Generate GitHub Actions matrix from OIDC providers configuration
# Usage: ./scripts/generate-provider-matrix.sh [config-file]

set -e

CONFIG_FILE="${1:-oidc-providers.json}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: $CONFIG_FILE not found" >&2
    exit 1
fi

echo "Generating GitHub Actions matrix from $CONFIG_FILE..."

# Extract enabled providers and create matrix
MATRIX=$(jq -r '.providers[] | select(.enabled == true) | "\(.name)|\(.url)|\(.description)"' "$CONFIG_FILE" | while IFS='|' read -r name url description; do
    echo "  - name: \"$name\""
    echo "    url: \"$url\""
    echo "    description: \"$description\""
done)

# Output the matrix in GitHub Actions format
echo "matrix:"
echo "  include:"
echo "$MATRIX"

echo ""
echo "Matrix generated successfully!"
echo "Total enabled providers: $(jq '.providers | map(select(.enabled == true)) | length' "$CONFIG_FILE")"
