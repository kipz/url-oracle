package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"url-oracle/attestation"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
)

// fetchPreviousAttestation attempts to fetch a previous attestation using the workflow reference
func fetchPreviousAttestation(workflowRef string) (*attestation.Attestation, error) {
	// Parse owner, repo, workflow file from workflowRef (format: owner/repo/.github/workflows/filename.yml@ref)
	// Example: kipz/url-oracle/.github/workflows/create-attestation.yml@refs/heads/main
	parts := strings.Split(workflowRef, "@")
	if len(parts) < 2 {
		fmt.Printf("⚠️  Warning: Unexpected workflow_ref format: %s\n", workflowRef)
		return nil, fmt.Errorf("unexpected workflow_ref format: %s", workflowRef)
	}
	workflowPath := parts[0]
	branchRef := parts[1]

	parts = strings.Split(workflowPath, "/")
	if len(parts) != 5 {
		fmt.Printf("⚠️  Warning: Unexpected workflow_ref format: %s\n", workflowRef)
		return nil, fmt.Errorf("unexpected workflow_ref format: %s", workflowRef)
	}
	owner := parts[0]
	repo := parts[1]
	workflowFile := parts[4]
	repoFull := owner + "/" + repo

	parts = strings.Split(branchRef, "/")
	if len(parts) != 3 {
		fmt.Printf("⚠️  Warning: Unexpected branch_ref format: %s\n", branchRef)
		return nil, fmt.Errorf("unexpected branch_ref format: %s", branchRef)
	}
	branch := parts[2]

	// Call scripts/download_attestation.sh to fetch a previous attestation (if any)
	scriptPath := "scripts/download_attestation.sh"
	cmd := exec.Command("bash", scriptPath, repoFull, workflowFile, branch)
	// Ensure GH_TOKEN is passed to the script if present in the environment
	cmd.Env = append(os.Environ(), fmt.Sprintf("GH_TOKEN=%s", os.Getenv("GH_TOKEN")))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	fmt.Printf("🔎 Attempting to fetch previous attestation using %s %s %s %s...\n", scriptPath, repoFull, workflowFile, branch)
	if err := cmd.Run(); err != nil {
		// If the exit code is 2, this means the artifact was not found, which is not a fatal error.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			fmt.Printf("⚠️  Warning: Previous attestation artifact not found (exit code 2): %v\n", err)
			return nil, nil
		} else {
			fmt.Printf("⚠️  Warning: Could not fetch previous attestation: %v\n", err)
			return nil, fmt.Errorf("failed to fetch previous attestation: %w", err)
		}
	}
	// Load previous_attestation.json and return it
	prevAttestationPath := "previous_attestation.json"
	if _, err := os.Stat(prevAttestationPath); err == nil {
		prevAttestation, err := attestation.LoadAttestation(prevAttestationPath)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to load previous attestation: %v\n", err)
			return nil, fmt.Errorf("failed to load previous attestation: %w", err)
		}
		fmt.Printf("✅ Loaded previous attestation from %s\n", prevAttestationPath)
		return prevAttestation, nil
	}
	return nil, fmt.Errorf("previous attestation not found")
}

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

	fmt.Println("🔍 Generating OpenPubkey token...")
	token, err := generateOpenPubkeyAttestation(*url, contentBytes, contentHash, contentSize, reqURL, reqTok)
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

func generateOpenPubkeyAttestation(url string, content, contentHash []byte, contentSize int64, reqURL, reqTok string) (*attestation.Attestation, error) {
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
	commitSHA, timestamp, workflowRef, err := extractClaimsFromIDToken(pkToken)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
	}

	// Use the workflow_ref extracted from the pkToken claims to call the GH api to retrieve the attestation.json uploaded on the most recent successful job run.
	prevAttestation, err := fetchPreviousAttestation(workflowRef)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch previous attestation: %w", err)
	}

	// Create attestation payload with extracted values
	payload, err := attestation.CreateAttestationPayload(prevAttestation, commitSHA, timestamp, url, content, contentHash, contentSize)
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
func extractClaimsFromIDToken(pkToken *pktoken.PKToken) (commitSHA, timestamp, workflowRef string, err error) {
	// Parse the PK token payload to extract GitHub Actions claims
	var claims struct {
		JobWorkflowSHA string `json:"job_workflow_sha"`
		IAT            int64  `json:"iat"`
		WorkflowRef    string `json:"workflow_ref"`
	}

	if err := json.Unmarshal(pkToken.Payload, &claims); err != nil {
		return "", "", "", fmt.Errorf("failed to parse PK token payload: %w", err)
	}

	if claims.JobWorkflowSHA == "" {
		return "", "", "", fmt.Errorf("job_workflow_sha claim not found in ID token")
	}

	if claims.IAT == 0 {
		return "", "", "", fmt.Errorf("iat claim not found in ID token")
	}
	if claims.WorkflowRef == "" {
		return "", "", "", fmt.Errorf("workflow_ref claim not found in ID token")
	}

	// Convert IAT (issued at) timestamp to ISO 8601 format
	timestamp = time.Unix(claims.IAT, 0).UTC().Format(time.RFC3339)

	return claims.JobWorkflowSHA, timestamp, claims.WorkflowRef, nil
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
