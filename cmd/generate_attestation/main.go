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
	"url-oracle/attestation"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
)

// Define previous attestation details filename to avoid typos
const previousAttestationDetailsFile = "previous_attestation_details.json"

// fetchPreviousAttestationDetails attempts to fetch a previous attestation details using the workflow reference
func fetchPreviousAttestationDetails(claims *attestation.IDTokenClaims, attestationFileName string) (*attestation.AttestationDetails, error) {
	// Parse owner, repo, workflow file from workflowRef (format: owner/repo/.github/workflows/filename.yml@ref)
	// Example: kipz/url-oracle/.github/workflows/create-attestation.yml@refs/heads/main
	parts := strings.Split(claims.WorkflowRef, "@")
	if len(parts) < 2 {
		fmt.Printf("⚠️  Warning: Unexpected workflow_ref format: %s\n", claims.WorkflowRef)
		return nil, fmt.Errorf("unexpected workflow_ref format: %s", claims.WorkflowRef)
	}
	workflowPath := parts[0]
	branchRef := parts[1]

	parts = strings.Split(workflowPath, "/")
	if len(parts) != 5 {
		fmt.Printf("⚠️  Warning: Unexpected workflow_ref format: %s\n", claims.WorkflowRef)
		return nil, fmt.Errorf("unexpected workflow_ref format: %s", claims.WorkflowRef)
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
	cmd := exec.Command("bash", scriptPath, attestationFileName, repoFull, workflowFile, branch)
	cmd.Env = append(os.Environ(), fmt.Sprintf("CALLER_TOKEN=%s", os.Getenv("CALLER_TOKEN")))
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
	// Load previous attestation file and return it
	prevAttestationDetailsPath := previousAttestationDetailsFile
	if _, err := os.Stat(prevAttestationDetailsPath); err == nil {
		details, err := attestation.LoadAttestationDetails(prevAttestationDetailsPath)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to load previous attestation details: %v\n", err)
			return nil, fmt.Errorf("failed to load previous attestation details: %w", err)
		}
		fmt.Printf("✅ Loaded previous attestation from %s\n", prevAttestationDetailsPath)
		return details, nil
	}
	return nil, fmt.Errorf("previous attestation details not found")
}

func main() {
	var (
		attestationFile = flag.String("attestation-file", "", "Output attestationfile path")
		url             = flag.String("url", "", "Some URL (e.g., https://vstoken.actions.githubusercontent.com/.well-known/jwks)")
		skipPrevious    = flag.Bool("skip-previous", false, "Skip attempting to fetch and reference previous attestation")
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
	attestationFileName := filepath.Base(*attestationFile)
	fmt.Println("📥 Downloading content from URL...")
	contentBytes, contentDigest, contentSize, err := attestation.DownloadContent(*url)
	if err != nil {
		fmt.Printf("❌ Error: Failed to download content from %s: %v\n", *url, err)
		os.Exit(1)
	}

	fmt.Printf("✅ Downloaded content: %d bytes, digest: %s\n", contentSize, contentDigest)

	fmt.Println("🔍 Creating attestation payload...")

	fmt.Println("🔍 Generating OpenPubkey token...")

	token, err := createAttestation(attestationFileName, *url, contentBytes, contentDigest, contentSize, reqURL, reqTok, *skipPrevious)
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

func createAttestation(attestationFileName string, url string, content []byte, contentDigest string, contentSize int64, reqURL, reqTok string, skipPrevious bool) (*attestation.Attestation, error) {
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
	claims, err := attestation.ExtractClaimsFromIDToken(pkToken)
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from ID token: %w", err)
	}

	// Fetch previous attestation (if not skipped)
	var prevAttestationDetails *attestation.AttestationDetails
	if !skipPrevious {
		prevAttestationDetails, err = fetchPreviousAttestationDetails(claims, attestationFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch previous attestation: %w", err)
		}
	} else {
		fmt.Println("⏭️  Skipping previous attestation fetch (--skip-previous flag set)")
	}

	// Create attestation payload with extracted values
	payload, err := attestation.CreateAttestationPayload(claims.Timestamp, claims.JobWorkflowSHA, prevAttestationDetails, url, content, contentDigest, contentSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation payload: %w", err)
	}

	// digest payload for signing
	digest, err := payload.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation digest: %w", err)
	}

	// sign payload
	msg := []byte(digest)
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
