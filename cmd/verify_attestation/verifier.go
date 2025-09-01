package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	attest "url-oracle/attestation"

	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

// VerificationResult contains the results of attestation verification
type VerificationResult struct {
	PKTokenVerified       bool
	SignedMessageVerified bool
	PayloadHashVerified   bool
	ProgramHashVerified   bool
	CommitSHAVerified     bool
	OracleVerified        bool
	Errors                []string
}

// VerifyAttestation performs all verification steps on an attestation
func VerifyAttestation(attestationFile string, reqURL, reqTok string, currentCommitSHA string) (*VerificationResult, error) {
	result := &VerificationResult{
		Errors: make([]string, 0),
	}

	// Create GitHub Actions URL provider
	provider := providers.NewGithubOp(reqURL, reqTok)

	// Load attestation
	attestation, err := attest.LoadAttestation(attestationFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation: %w", err)
	}

	// Verify that PK Token is issued by the OP you wish to use
	pktVerifier, err := verifier.New(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create PK Token verifier: %w", err)
	}

	err = pktVerifier.VerifyPKToken(context.Background(), attestation.PKToken)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("PK Token verification failed: %v", err))
	} else {
		result.PKTokenVerified = true
	}

	// Check that the message verifies under the user's public key in the PK Token
	msg, err := attestation.PKToken.VerifySignedMessage(attestation.Signature)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Signed message verification failed: %v", err))
	} else {
		result.SignedMessageVerified = true
	}

	// Check that msg is the same as the attestation payload hash
	hash, err := attestation.Payload.Hash()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to generate attestation payload hash: %v", err))
	} else if !bytes.Equal(msg, hash) {
		result.Errors = append(result.Errors, "Attestation payload hash does not match signed message")
	} else {
		result.PayloadHashVerified = true
	}

	// Check that the attestation payload is valid
	toverify := attest.CreateAttestationPayload(
		attestation.Payload.CommitSHA,
		attestation.Payload.Timestamp,
		attestation.Payload.Url,
		attestation.Payload.Content,
		attestation.Payload.ContentHash,
		attestation.Payload.ContentSize,
	)

	hashToVerify, err := toverify.Hash()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to generate program hash: %v", err))
	} else if !bytes.Equal(msg, hashToVerify) {
		result.Errors = append(result.Errors, "Program generated hash does not match signed message")
	} else {
		result.ProgramHashVerified = true
	}

	// Verify commit SHA matches current repository
	commitSHAVerified, err := verifyCommitSHA(attestation.Payload.CommitSHA, currentCommitSHA)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Commit SHA verification failed: %v", err))
	} else if commitSHAVerified {
		result.CommitSHAVerified = true
	} else {
		result.Errors = append(result.Errors, "Commit SHA does not match current repository")
	}

	// Verify attestation was created by this oracle
	oracleVerified, err := verifyOracle(attestation.Payload.Metadata)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Oracle verification failed: %v", err))
	} else if oracleVerified {
		result.OracleVerified = true
	} else {
		result.Errors = append(result.Errors, "Attestation was not created by this oracle")
	}

	return result, nil
}

// IsVerificationSuccessful checks if all verification steps passed
func (vr *VerificationResult) IsVerificationSuccessful() bool {
	return vr.PKTokenVerified &&
		vr.SignedMessageVerified &&
		vr.PayloadHashVerified &&
		vr.ProgramHashVerified &&
		vr.CommitSHAVerified &&
		vr.OracleVerified
}

// GetSummary returns a summary of verification results
func (vr *VerificationResult) GetSummary() string {
	if vr.IsVerificationSuccessful() {
		return "✅ All verification steps passed successfully"
	}

	summary := "❌ Verification failed:\n"
	for _, err := range vr.Errors {
		summary += fmt.Sprintf("  - %s\n", err)
	}
	return summary
}

// verifyCommitSHA checks if the attestation commit SHA matches the current repository commit SHA
func verifyCommitSHA(attestationCommitSHA string, currentCommitSHA string) (bool, error) {
	// Compare commit SHAs
	if attestationCommitSHA == currentCommitSHA {
		return true, nil
	}

	return false, nil
}

// verifyOracle checks if the attestation was created by this oracle (same org/repo)
func verifyOracle(attestationMetadata map[string]string) (bool, error) {
	// Get current repository from environment
	currentRepo := os.Getenv("GITHUB_REPOSITORY")
	if currentRepo == "" {
		// Fallback to git remote origin
		cmd := exec.Command("git", "remote", "get-url", "origin")
		output, err := cmd.Output()
		if err != nil {
			return false, fmt.Errorf("failed to get git remote origin: %w", err)
		}

		// Extract org/repo from git URL
		remoteURL := strings.TrimSpace(string(output))
		if strings.Contains(remoteURL, "github.com") {
			parts := strings.Split(remoteURL, "github.com/")
			if len(parts) > 1 {
				currentRepo = strings.TrimSuffix(parts[1], ".git")
			}
		}
	}

	if currentRepo == "" {
		return false, fmt.Errorf("could not determine current repository")
	}

	// Check if attestation metadata contains the same repository
	attestationRepo, exists := attestationMetadata["repository"]
	if !exists {
		return false, fmt.Errorf("attestation missing repository metadata")
	}

	if attestationRepo == currentRepo {
		return true, nil
	}

	return false, nil
}
