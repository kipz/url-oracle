# URL Oracle

A Docker-based GitHub Action that creates cryptographically verifiable attestations for URL content monitoring. This action can be used in any GitHub workflow to generate and verify attestations when the content of specified URLs changes.

## Overview

The URL Oracle is a self-contained Docker action that monitors specified URLs and creates new attestations only when content changes are detected. Each attestation is cryptographically signed using OpenPubkey, providing verifiable proof of:
- When the content was fetched
- What the content hash was
- Which commit generated the attestation
- That the attestation was created by this specific oracle

## Architecture

The URL Oracle is implemented as a **Docker-based GitHub Action** that:
- **Builds on-demand**: GitHub builds the Docker image when the action is used
- **Self-contained**: Includes all necessary Go binaries and dependencies
- **Multi-command**: Supports different operations via the `command` input
- **Cross-repository**: Can be used from any GitHub repository

## GitHub Action Usage

### Basic Usage

```yaml
- name: Generate Attestation
  uses: kipz/url-oracle@6d49cfdbab7c408ff41b2ddceb1dea9342db0c19
  with:
    command: generate_attestation
    url: 'https://vstoken.actions.githubusercontent.com/.well-known/jwks'
    commit_sha: ${{ github.sha }}
    timestamp: ${{ github.event_time }}
```

### Available Commands

The action supports three main commands:

#### 1. `generate_attestation`
Creates a new OpenPubkey attestation for the specified URL.

```yaml
- name: Generate Attestation
  uses: kipz/url-oracle@6d49cfdbab7c408ff41b2ddceb1dea9342db0c19
  with:
    command: generate_attestation
    url: 'https://example.com/api/data'
    commit_sha: ${{ github.sha }}
    timestamp: ${{ github.event_time }}
```

#### 2. `verify_attestation`
Verifies the authenticity and integrity of an attestation.

```yaml
- name: Verify Attestation
  uses: kipz/url-oracle@6d49cfdbab7c408ff41b2ddceb1dea9342db0c19
  with:
    command: verify_attestation
    attestation_file: 'attestation.json'
    commit_sha: ${{ github.sha }}
```

## Action Inputs

| Input | Required | Description | Default |
|-------|----------|-------------|---------|
| `command` | No | Command to execute | `generate_attestation` |
| `url` | No | URL to fetch and witness | - |
| `commit_sha` | No | Current commit SHA | - |
| `timestamp` | No | Timestamp for attestation | - |
| `attestation_file` | No | Attestation file to verify (relative to workspace) | - |

## Attestation Verification

The verification process performs **6 comprehensive checks**:

### 1. PK Token Verification
- Verifies the OpenPubkey token is issued by the expected provider
- Ensures the token is valid and not expired

### 2. Signed Message Verification
- Verifies the message signature using the public key in the PK Token
- Ensures the attestation hasn't been tampered with

### 3. Payload Hash Verification
- Compares the signed message with the attestation payload hash
- Ensures the payload matches what was originally signed

### 4. Program Hash Verification
- Recreates the attestation payload and generates a hash
- Compares with the signed message to ensure consistency

### 5. Commit SHA Verification
- Verifies the attestation's commit SHA matches the current repository
- Prevents replay attacks using old attestations from different commits

### 6. Oracle Verification
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
    "content_hash": "a1b2c3d4e5f6...",
    "content_size": 1234,
    "metadata": {
      "repository": "kipz/url-oracle"
    }
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
| `content_hash` | string | SHA256 hash of the content |
| `content_size` | number | Size of the content in bytes |
| `metadata` | object | Additional metadata (repository, etc.) |


## Security Features

### Cryptographic Verification
- **OpenPubkey Integration**: Uses OpenPubkey for cryptographically verifiable attestations
- **Digital Signatures**: Each attestation is digitally signed
- **Hash Verification**: Content integrity verified through SHA256 hashing

### Anti-Replay Protection
- **Commit Binding**: Attestations are bound to specific git commits
- **Timestamp Validation**: Attestations include creation timestamps
- **Oracle Authentication**: Attestations can only be verified by the creating oracle

### Content Change Detection
- **Hash Comparison**: Only creates new attestations when content actually changes
- **Size Validation**: Tracks both content hash and size for comprehensive change detection
- **Metadata Preservation**: Maintains repository and creation context

## Reusable Workflows

The URL Oracle provides two reusable workflows that can be called from other repositories:

### 1. Create Attestation Workflow
```yaml
- name: Create Attestation
  uses: kipz/url-oracle/.github/workflows/create-attestation.yml@main
  with:
    url: 'https://example.com/api/data'
```

**Outputs**: The generated attestation is automatically uploaded as a job artifact named `attestation.json` with a 30-day retention period. Other workflows can download this artifact using the `actions/download-artifact@v4` action.

### 2. Verify Attestation Workflow
```yaml
- name: Verify Attestation
  uses: kipz/url-oracle/.github/workflows/verify-attestation.yml@main
```

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

### Go Binaries
- **`generate-attestation`**: Generates OpenPubkey attestations
- **`verify-attestation`**: Verifies attestation authenticity

### Build Process
1. **Multi-stage Docker build** compiles Go binaries
2. **Alpine-based runtime** for minimal image size
3. **Non-root user** for security
4. **Entrypoint script** routes commands to appropriate binaries

## Development

### Local Testing

Build and test the Docker image locally:
```bash
# Build the image
docker build -t url-oracle .

# Test different commands
docker run --rm url-oracle generate_attestation --help
docker run --rm url-oracle verify_attestation --help
```

### Go Development

```bash
# Install dependencies
go mod download

# Run tests
go test ./...

# Build binaries
go build -o generate-attestation ./cmd/generate_attestation
go build -o verify-attestation ./cmd/verify_attestation
```

## Current Version

The latest version of the URL Oracle is available at commit SHA:
```
6d49cfdbab7c408ff41b2ddceb1dea9342db0c19
```
