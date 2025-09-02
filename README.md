# URL Oracle

A Go-based GitHub Action that creates cryptographically verifiable attestations for URL content monitoring. This action can be used in any GitHub workflow to generate and verify attestations when the content of specified URLs changes.

## Overview

The URL Oracle is a Go application that monitors specified URLs and creates new attestations only when content changes are detected. Each attestation is cryptographically signed using OpenPubkey, providing verifiable proof of:
- When the content was fetched
- What the content digest was
- Which commit generated the attestation
- That the attestation was created by this specific oracle

## Architecture

The URL Oracle is implemented as a **Go-based application** that:
- **Runs directly**: Executes Go binaries in GitHub Actions workflows
- **Self-contained**: Includes all necessary Go modules and dependencies
- **Multi-command**: Supports different operations via separate Go programs
- **Cross-repository**: Can be used from any GitHub repository via reusable workflows

## GitHub Action Usage

The URL Oracle is used via **reusable workflows** rather than direct action calls. This approach provides better maintainability and cross-repository compatibility.

### Available Workflows

The URL Oracle provides two reusable workflows:

#### 1. Create Attestation Workflow
Creates a new OpenPubkey attestation for the specified URL.

```yaml
- name: Create Attestation
  uses: kipz/url-oracle/.github/workflows/create-attestation.yml@main
  with:
    url: 'https://example.com/api/data'
  secrets:
    token: ${{ secrets.GITHUB_TOKEN }}
```

#### 2. Verify Attestation Workflow
Verifies the authenticity and integrity of an attestation.

```yaml
- name: Verify Attestation
  uses: kipz/url-oracle/.github/workflows/verify-attestation.yml@main
  secrets:
    token: ${{ secrets.GITHUB_TOKEN }}
```

## Workflow Inputs

### Create Attestation Workflow

| Input | Required | Description | Default |
|-------|----------|-------------|---------|
| `url` | Yes | URL to fetch and witness | - |
| `secrets.token` | Yes | GitHub token for repository access | - |

### Verify Attestation Workflow

| Input | Required | Description | Default |
|-------|----------|-------------|---------|
| `secrets.token` | Yes | GitHub token for repository access | - |

**Note**: The verify workflow expects an `attestation.json` artifact to be available from a previous workflow run.

## Attestation Verification

The verification process performs **8 comprehensive checks**:

### 1. PK Token Verification
- Verifies the OpenPubkey token is issued by the expected provider
- Ensures the token is valid and not expired

### 2. Signed Message Verification
- Verifies the message signature using the public key in the PK Token
- Ensures the attestation hasn't been tampered with

### 3. Payload Digest Verification
- Compares the signed message with the attestation payload digest
- Ensures the payload matches what was originally signed

### 4. Oracle Digest Verification
- Recreates the attestation payload and generates a digest
- Compares with the signed message to ensure consistency

### 5. Commit SHA Verification
- Verifies the attestation's commit SHA matches the current repository
- Prevents replay attacks using old attestations from different commits

### 6. Workflow Reference Verification
- Verifies the PK token's `job_workflow_ref` matches the expected workflow
- Ensures the attestation was created by the correct workflow

### 7. Workflow SHA Verification
- Verifies the PK token's `job_workflow_sha` matches the expected commit SHA
- Prevents replay attacks using old workflow versions

### 8. Oracle Verification
- Ensures the attestation was created by this specific oracle
- Prevents cross-oracle attestation forgery

## JSON Format

### Attestation Structure

```json
{
  "payload": {
    "commit_sha": "d31fcdc47efb67dd1be443fb11c588fdefbf8360",
    "timestamp": "2025-08-31T13:34:21Z",
    "url": "https://vstoken.actions.githubusercontent.com/.well-known/jwks",
    "content": "{\"keys\":[...]}",
    "content_digest": "a1b2c3d4e5f6...",
    "content_size": 1234,
    "prev_attestation_digest": "f6e5d4c3b2a1..."
  },
  "pk_token": {
    // OpenPubkey PK Token structure
  },
  "signature": "base64-encoded-signature"
}
```

### Payload Fields

| Field | Type | Description |
|-------|------|-------------|
| `commit_sha` | string | Git commit SHA when attestation was created |
| `timestamp` | string | ISO 8601 timestamp of attestation creation |
| `url` | string | The URL that was monitored |
| `content` | string | The actual content retrieved from the URL |
| `content_digest` | string | SHA256 digest of the content |
| `content_size` | number | Size of the content in bytes |
| `prev_attestation_digest` | string | SHA256 digest of the previous attestation (if any) |


## Security Features

### Cryptographic Verification
- **OpenPubkey Integration**: Uses OpenPubkey for cryptographically verifiable attestations
- **Digital Signatures**: Each attestation is digitally signed
- **Digest Verification**: Content integrity verified through SHA256 digesting

### Anti-Replay Protection
- **Commit Binding**: Attestations are bound to specific git commits
- **Timestamp Validation**: Attestations include creation timestamps
- **Oracle Authentication**: Attestations can only be verified by the creating oracle

### Content Change Detection
- **Digest Comparison**: Only creates new attestations when content actually changes
- **Size Validation**: Tracks both content digest and size for comprehensive change detection
- **Metadata Preservation**: Maintains repository and creation context

## Artifact Management

### Attestation Artifacts

The Create Attestation workflow automatically uploads the generated attestation as a job artifact named `attestation.json` with a 30-day retention period. Other workflows can download this artifact using the `actions/download-artifact@v4` action.

### Previous Attestation Integration

The system automatically attempts to fetch and verify against previous attestations from the same workflow, creating a chain of attestations that can be used to detect content changes and maintain historical integrity.

## Downloading Attestation Artifacts

When using the Create Attestation workflow, the generated attestation is automatically uploaded as a job artifact. Other workflows can download this artifact using the following pattern:

```yaml
- name: Download attestation artifact
  uses: actions/download-artifact@v4
  with:
    name: attestation.json
    path: .

- name: Use attestation
  run: |
    echo "Attestation downloaded to: $(pwd)/attestation.json"
    # Process the attestation file as needed
```

**Note**: The artifact is retained for 30 days and can be downloaded by any workflow that has access to the repository.

### Go Programs
- **`cmd/generate_attestation/main.go`**: Generates OpenPubkey attestations (used by both workflows)
- **`cmd/verify_attestation/main.go`**: Verifies attestation authenticity
- **`cmd/verify_attestation/verifier.go`**: Core verification logic

### Build Process
1. **Go modules** manage dependencies
2. **Direct execution** in GitHub Actions workflows
3. **Cross-platform** Go binaries
4. **Reusable workflows** for easy integration

## Development

### Local Testing

Test the Go programs locally:
```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Test attestation generation
go run cmd/generate_attestation/main.go --url https://example.com --attestation-file test.json

# Test attestation verification
go run cmd/verify_attestation/main.go cmd/verify_attestation/verifier.go --attestation-file test.json
```

### Go Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build binaries (optional)
go build -o generate-attestation ./cmd/generate_attestation
go build -o verify-attestation ./cmd/verify_attestation
```

## Current Version

The latest version of the URL Oracle is available on the `main` branch and can be used via reusable workflows.
