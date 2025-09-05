package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		attestationFile = flag.String("attestation-file", "", "Path to attestation file to verify")
	)
	flag.Parse()

	if *attestationFile == "" {
		fmt.Println("Error: attestation-file flag is required")
		flag.Usage()
		os.Exit(1)
	}

	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		fmt.Println("Error: Missing ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		os.Exit(1)
	}

	// Get expected workflow reference from environment variable
	expectedWorkflowRef := os.Getenv("EXPECTED_WORKFLOW_REF")

	fmt.Println("🔍 Loading attestation...")

	// Perform verification using the extracted logic
	result, err := VerifyAttestation(*attestationFile, reqURL, reqTok, expectedWorkflowRef)
	if err != nil {
		fmt.Printf("❌ Error during verification: %v\n", err)
		os.Exit(1)
	}

	// Print verification results
	fmt.Println("🔍 Verification Results:")
	fmt.Printf("  PK Token: %s\n", getStatusIcon(result.PKTokenVerified))
	fmt.Printf("  Signed Message: %s\n", getStatusIcon(result.SignedMessageVerified))
	fmt.Printf("  Payload Digest: %s\n", getStatusIcon(result.PayloadDigestVerified))
	fmt.Printf("  Oracle Digest: %s\n", getStatusIcon(result.OracleDigestVerified))
	fmt.Printf("  Workflow Reference: %s\n", getStatusIcon(result.WorkflowRefVerified))
	fmt.Printf("  Workflow SHA: %s\n", getStatusIcon(result.WorkflowSHAVerified))

	fmt.Println()
	fmt.Println(result.GetSummary())

	// Exit with appropriate code
	if result.IsVerificationSuccessful() {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

// getStatusIcon returns an appropriate icon for the verification status
func getStatusIcon(success bool) string {
	if success {
		return "✅"
	}
	return "❌"
}
