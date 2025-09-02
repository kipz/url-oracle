package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"url-oracle/attestation"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
)

func main() {
	var (
		attestationFile = flag.String("attestation-file", "", "Output attestationfile path")
		url             = flag.String("url", "", "Some URL (e.g., https://vstoken.actions.githubusercontent.com/.well-known/jwks)")
	)
	flag.Parse()

	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		fmt.Println("Error: Missing ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		os.Exit(1)
	}
	if *attestationFile == "" || *url == "" {
		fmt.Println("Error: attestation-file and url flags are required")
		flag.Usage()
		os.Exit(1)
	}
	fmt.Println("📥 Downloading content from URL...")
	contentBytes, contentHash, contentSize, err := attestation.DownloadContent(*url)
	if err != nil {
		fmt.Printf("❌ Error: Failed to download content from %s: %v\n", *url, err)
		os.Exit(1)
	}

	fmt.Printf("✅ Downloaded content: %d bytes, hash: %s\n", contentSize, contentHash)

	fmt.Println("🔍 Creating attestation payload...")
	contentStr := base64.StdEncoding.EncodeToString(contentBytes)

	fmt.Println("🔍 Generating OpenPubkey token...")
	token, err := generateOpenPubkeyAttestation(*url, contentStr, contentHash, contentSize, reqURL, reqTok)
	if err != nil {
		fmt.Printf("❌ Error: OpenPubkey token generation failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("💾 Saving attestation...")
	if err := saveAttestation(token, *attestationFile); err != nil {
		fmt.Printf("❌ Error saving attestation: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Attestation generated successfully!")
	fmt.Printf("   Commit SHA: %s...\n", token.Payload.CommitSHA[:8])
}

func generateOpenPubkeyAttestation(url, content, contentHash string, contentSize int64, reqURL, reqTok string) (*attestation.Attestation, error) {
	ctx := context.Background()

	// Create GitHub Actions OIDC provider
	provider := providers.NewGithubOp(reqURL, reqTok)

	// Create OpenPubkey client
	opkClient, err := client.New(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenPubkey client: %w", err)
	}

	// Authenticate and generate PK token
	pkToken, err := opkClient.Auth(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate and generate PK token: %w", err)
	}

	// Extract commit SHA and timestamp from ID token payload
	commitSHA, timestamp, err := extractClaimsFromIDToken(pkToken)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
	}

	// Create attestation payload with extracted values
	payload, err := attestation.CreateAttestationPayload(commitSHA, timestamp, url, content, contentHash, contentSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation payload: %w", err)
	}

	// hash payload for signing
	hash, err := payload.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation hash: %w", err)
	}

	// sign payload
	msg := []byte(hash)
	signedMsg, err := pkToken.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Create the attestation structure with real OpenPubkey token
	attestation := &attestation.Attestation{
		Payload:   *payload,
		PKToken:   pkToken,
		Signature: signedMsg,
	}

	return attestation, nil
}

// extractClaimsFromIDToken extracts job_workflow_sha and iat claims from the PK token payload
func extractClaimsFromIDToken(pkToken *pktoken.PKToken) (commitSHA, timestamp string, err error) {
	// Parse the PK token payload to extract GitHub Actions claims
	var claims struct {
		JobWorkflowSHA string `json:"job_workflow_sha"`
		IAT            int64  `json:"iat"`
	}

	if err := json.Unmarshal(pkToken.Payload, &claims); err != nil {
		return "", "", fmt.Errorf("failed to parse PK token payload: %w", err)
	}

	if claims.JobWorkflowSHA == "" {
		return "", "", fmt.Errorf("job_workflow_sha claim not found in ID token")
	}

	if claims.IAT == 0 {
		return "", "", fmt.Errorf("iat claim not found in ID token")
	}

	// Convert IAT (issued at) timestamp to ISO 8601 format
	timestamp = time.Unix(claims.IAT, 0).UTC().Format(time.RFC3339)

	return claims.JobWorkflowSHA, timestamp, nil
}

func saveAttestation(attestation *attestation.Attestation, outputFile string) error {
	// Ensure output directory exists
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Serialize attestation
	data, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attestation: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write attestation file: %w", err)
	}

	fmt.Printf("💾 Attestation saved to: %s\n", outputFile)
	return nil
}
