#!/bin/bash

# Download and print attestation.json from the most recent successful workflow run
# Usage: ./download_attestation.sh <repository> <workflow_file> [branch] [--no-verify]
# Example: ./download_attestation.sh kipz/bbc-tech-news-oracle attest-bbc.yml main
# Example: ./download_attestation.sh kipz/bbc-tech-news-oracle attest-bbc.yml main --no-verify

set -e


# Parse arguments
VERIFY=true
ARGS=()

for arg in "$@"; do
    case $arg in
        --no-verify)
            VERIFY=false
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done

# Check for required arguments
if [ ${#ARGS[@]} -lt 3 ] || [ ${#ARGS[@]} -gt 4 ]; then
    echo "Error: Invalid number of arguments"
    echo "Usage: $0 <attestation_file> <repository> <workflow_file> [branch] [--no-verify]"
    echo "Example: $0 attestation.json kipz/bbc-tech-news-oracle attest-bbc.yml main"
    echo "Example: $0 attestation.json kipz/bbc-tech-news-oracle attest-bbc.yml main --no-verify"
    echo "Branch defaults to 'main' if not specified"
    echo "Use --no-verify to skip attestation verification"
    exit 1
fi

# Configuration from command line arguments
ATTESTATION_FILE="${ARGS[0]}"
ATTESTATION_FILE_NAME=$(basename "$ATTESTATION_FILE")
REPO="${ARGS[1]}"
WORKFLOW_FILE="${ARGS[2]}"
BRANCH="${ARGS[3]:-main}"
PREVIOUS_ATTESTATION_FILE="previous_attestation.json"
PREVIOUS_ATTESTATION_DETAILS_FILE="previous_attestation_details.json"

echo "Looking for successful workflow runs in $REPO on branch '$BRANCH'..."

# Get the most recent successful workflow run for the specified branch
echo "Fetching workflow runs for $WORKFLOW_FILE..."
# Use CALLER_TOKEN if available (from GitHub Actions environment)
if [ -n "$CALLER_TOKEN" ]; then
    echo "Using CALLER_TOKEN for CLI authentication..."
    set +e  # Temporarily disable exit on error
    RUN_ID=$(GH_TOKEN="$CALLER_TOKEN" gh run list --workflow="$WORKFLOW_FILE" --status=success --branch="$BRANCH" --limit=1 --json databaseId --jq '.[0].databaseId' --repo "$REPO" 2>&1)
    EXIT_CODE=$?
    echo "Command output: $RUN_ID" >&2
    echo "Exit code: $EXIT_CODE" >&2
    set -e  # Re-enable exit on error
else
    echo "No CALLER_TOKEN found, using default authentication..."
    set +e  # Temporarily disable exit on error
    RUN_ID=$(gh run list --workflow="$WORKFLOW_FILE" --status=success --branch="$BRANCH" --limit=1 --json databaseId --jq '.[0].databaseId' --repo "$REPO" 2>&1)
    EXIT_CODE=$?
    echo "Command output: $RUN_ID" >&2
    echo "Exit code: $EXIT_CODE" >&2
    set -e  # Re-enable exit on error

fi

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Error: Failed to access repository $REPO" >&2
    echo "Command output: $RUN_ID" >&2
    echo "Exit code: $EXIT_CODE" >&2
    echo "This might be because:" >&2
    echo "  - The repository is private and you don't have access" >&2
    echo "  - The GitHub CLI is not authenticated" >&2
    echo "  - The workflow file '$WORKFLOW_FILE' doesn't exist" >&2
    echo "  - The repository doesn't exist" >&2
    echo "" >&2
    echo "Try running: gh auth login" >&2
    echo "Or use a repository you have access to" >&2
    exit 1
fi

if [ "$RUN_ID" = "null" ] || [ -z "$RUN_ID" ]; then
    echo "No successful workflow runs found" >&2
    exit 2
fi

echo "Using workflow run ID: $RUN_ID"

# Get artifact ID for attestation.json
if [ -n "$CALLER_TOKEN" ]; then
    ARTIFACT=$(GH_TOKEN="$CALLER_TOKEN" gh api "/repos/$REPO/actions/runs/$RUN_ID/artifacts" --jq '.artifacts[] | select(.name == "'"$ATTESTATION_FILE_NAME"'")')
    ARTIFACT_ID=$(echo "$ARTIFACT" | jq -r '.id')
    DIGEST=$(echo "$ARTIFACT" | jq -r '.digest')
else
    ARTIFACT=$(gh api "/repos/$REPO/actions/runs/$RUN_ID/artifacts" --jq '.artifacts[] | select(.name == "'"$ATTESTATION_FILE_NAME"'")')
    ARTIFACT_ID=$(echo "$ARTIFACT" | jq -r '.id')
    DIGEST=$(echo "$ARTIFACT" | jq -r '.digest')
fi

if [ -z "$ARTIFACT_ID" ]; then
    echo "$ATTESTATION_FILE_NAME artifact not found" >&2
    exit 2
fi

echo "Found $ATTESTATION_FILE_NAME artifact ID: $ARTIFACT_ID"

# Download the artifact
ARTIFACT_URL="/repos/$REPO/actions/artifacts/$ARTIFACT_ID/zip"
echo "Downloading artifact..."
if [ -n "$CALLER_TOKEN" ]; then
    GH_TOKEN="$CALLER_TOKEN" gh api "$ARTIFACT_URL" > attestation.zip
else
    gh api "$ARTIFACT_URL" > attestation.zip
fi

# Extract and save the JSON
echo "Extracting $ATTESTATION_FILE_NAME..."
unzip -p attestation.zip "$ATTESTATION_FILE_NAME" > "$PREVIOUS_ATTESTATION_FILE"

# Extract commit SHA from attestation
echo "Extracting commit SHA from attestation..."
COMMIT_SHA=$(jq -r '.payload.commit_sha' "$PREVIOUS_ATTESTATION_FILE")
echo "Found commit SHA: $COMMIT_SHA"

# Clean up
rm -f attestation.zip

if [ "$VERIFY" = true ]; then
    echo "🔍 Starting attestation verification..."
    
    # Create a temporary directory for verification
    VERIFY_DIR="verify_attestation_$$"
    REPO="kipz/url-oracle"
    echo "Creating verification directory: $VERIFY_DIR"
    mkdir -p "$VERIFY_DIR"
    cd "$VERIFY_DIR"

    # Checkout repository at the specific commit
    echo "Checking out repository at commit $COMMIT_SHA..."
    git clone "https://github.com/$REPO.git" .

    # Check if the commit exists in the repository
    if git cat-file -e "$COMMIT_SHA" 2>/dev/null; then
        echo "Commit $COMMIT_SHA found in repository"
        git checkout "$COMMIT_SHA"
    else
        echo "⚠️  Warning: Commit $COMMIT_SHA not found in repository $REPO" >&2
        echo "This might be because the attestation is from a different repository or the commit has been removed" >&2
        echo "Skipping verification..." >&2
        cd ..
        rm -rf "$VERIFY_DIR"
        echo "🔍 Verification skipped - commit not found" >&2
        echo "📋 Summary: Attestation verification SKIPPED" >&2
        echo "Done!" >&2
        exit 0
    fi

    # Run verification
    echo "Running attestation verification..."
    if go run cmd/verify_attestation/main.go cmd/verify_attestation/verifier.go --attestation-file "../$PREVIOUS_ATTESTATION_FILE"; then
        echo "✅ Attestation verification successful!"
        VERIFICATION_RESULT="SUCCESS"
    else
        echo "❌ Attestation verification failed!" >&2
        VERIFICATION_RESULT="FAILED"
    fi
    # Create previous attestation details file (Digest, Run URL, Filename)
    echo "Creating previous attestation details file..."
    echo "{\"digest\":\"$DIGEST\",\"artifact_url\":\"$ARTIFACT_URL\"}" > "$PREVIOUS_ATTESTATION_DETAILS_FILE"
    cp "$PREVIOUS_ATTESTATION_DETAILS_FILE" "../$PREVIOUS_ATTESTATION_DETAILS_FILE"
    

    # Clean up verification directory
    cd ..
    rm -rf "$VERIFY_DIR"

    echo "🔍 Verification completed for commit $COMMIT_SHA"
    echo "📋 Summary: Attestation verification $VERIFICATION_RESULT"
    if [ "$VERIFICATION_RESULT" = "FAILED" ]; then
        exit 1
    fi
else
    echo "🔍 Verification skipped (--no-verify flag used)"
    echo "📋 Summary: Attestation downloaded successfully"
fi

echo "Done!"
