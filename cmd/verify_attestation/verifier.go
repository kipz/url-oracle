package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	attest "url-oracle/attestation"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

// VerificationResult contains the results of attestation verification
type VerificationResult struct {
	PKTokenVerified       bool
	SignedMessageVerified bool
	PayloadHashVerified   bool
	ProgramHashVerified   bool
	WorkflowRefVerified   bool
	WorkflowSHAVerified   bool
	Errors                []string
}

// VerifyAttestation performs all verification steps on an attestation
func VerifyAttestation(attestationFile string, reqURL, reqTok string) (*VerificationResult, error) {
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
	toverify, err := attest.CreateAttestationPayload(
		attestation,
		attestation.Payload.CommitSHA,
		attestation.Payload.Timestamp,
		attestation.Payload.Url,
		attestation.Payload.Content,
		attestation.Payload.ContentDigest,
		attestation.Payload.ContentSize,
	)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to create attestation payload: %v", err))
	}

	hashToVerify, err := toverify.Hash()
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to generate program hash: %v", err))
	} else if !bytes.Equal(msg, hashToVerify) {
		result.Errors = append(result.Errors, "Program generated hash does not match signed message")
	} else {
		result.ProgramHashVerified = true
	}

	// Verify PK token workflow reference matches expected workflow
	workflowRefVerified, err := verifyWorkflowRef(attestation.PKToken)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Workflow reference verification failed: %v", err))
	} else if workflowRefVerified {
		result.WorkflowRefVerified = true
	} else {
		result.Errors = append(result.Errors, "PK token workflow reference does not match expected workflow")
	}

	// Verify PK token workflow SHA matches commit SHA
	workflowSHAVerified, err := verifyWorkflowSHA(attestation.PKToken, attestation.Payload.CommitSHA)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Workflow SHA verification failed: %v", err))
	} else if workflowSHAVerified {
		result.WorkflowSHAVerified = true
	} else {
		result.Errors = append(result.Errors, "PK token workflow SHA does not match commit SHA")
	}

	return result, nil
}

// IsVerificationSuccessful checks if all verification steps passed
func (vr *VerificationResult) IsVerificationSuccessful() bool {
	return vr.PKTokenVerified &&
		vr.SignedMessageVerified &&
		vr.PayloadHashVerified &&
		vr.ProgramHashVerified &&
		vr.WorkflowRefVerified &&
		vr.WorkflowSHAVerified
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

// verifyWorkflowRef checks if the PK token's job_workflow_ref matches the expected workflow
func verifyWorkflowRef(pkToken *pktoken.PKToken) (bool, error) {
	// Parse the PK token payload to extract GitHub Actions claims
	var claims struct {
		JobWorkflowRef string `json:"job_workflow_ref"`
	}

	if err := json.Unmarshal(pkToken.Payload, &claims); err != nil {
		return false, fmt.Errorf("failed to parse PK token payload: %w", err)
	}

	expectedWorkflowRef := "kipz/url-oracle/.github/workflows/create-attestation.yml@refs/heads/main"

	if claims.JobWorkflowRef == expectedWorkflowRef {
		return true, nil
	}

	return false, nil
}

// verifyWorkflowSHA checks if the PK token's job_workflow_sha matches the expected commit SHA
func verifyWorkflowSHA(pkToken *pktoken.PKToken, expectedCommitSHA string) (bool, error) {
	// Parse the PK token payload to extract GitHub Actions claims
	var claims struct {
		JobWorkflowSHA string `json:"job_workflow_sha"`
	}

	if err := json.Unmarshal(pkToken.Payload, &claims); err != nil {
		return false, fmt.Errorf("failed to parse PK token payload: %w", err)
	}

	if claims.JobWorkflowSHA == expectedCommitSHA {
		return true, nil
	}

	return false, nil
}
