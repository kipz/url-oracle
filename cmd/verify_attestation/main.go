package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		attestationFile = flag.String("attestation-file", "", "Path to attestation file to verify")
		commitSHA       = flag.String("commit-sha", "", "Commit SHA of this program")
	)
	flag.Parse()

	if *attestationFile == "" {
		fmt.Println("Error: attestation-file flag is required")
		flag.Usage()
		os.Exit(1)
	}

	if *commitSHA == "" {
		fmt.Println("Error: commit-sha flag is required")
		flag.Usage()
		os.Exit(1)
	}

	reqURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	reqTok := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqTok == "" {
		fmt.Println("Error: Missing ACTIONS_ID_TOKEN_REQUEST_URL or ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		os.Exit(1)
	}

	fmt.Println("🔍 Loading attestation...")

	// Perform verification using the extracted logic
	result, err := VerifyAttestation(*attestationFile, reqURL, reqTok, *commitSHA)
	if err != nil {
		fmt.Printf("❌ Error during verification: %v\n", err)
		os.Exit(1)
	}

	// Print verification results
	fmt.Println("🔍 Verification Results:")
	fmt.Printf("  PK Token: %s\n", getStatusIcon(result.PKTokenVerified))
	fmt.Printf("  Signed Message: %s\n", getStatusIcon(result.SignedMessageVerified))
	fmt.Printf("  Payload Hash: %s\n", getStatusIcon(result.PayloadHashVerified))
	fmt.Printf("  Program Hash: %s\n", getStatusIcon(result.ProgramHashVerified))
	fmt.Printf("  Commit SHA: %s\n", getStatusIcon(result.CommitSHAVerified))
	fmt.Printf("  Workflow Reference: %s\n", getStatusIcon(result.WorkflowRefVerified))
	fmt.Printf("  Workflow SHA: %s\n", getStatusIcon(result.WorkflowSHAVerified))

	fmt.Println()
	fmt.Println(result.GetSummary())

	// Exit with appropriate code
	if result.IsVerificationSuccessful() {
		fmt.Println("✅ Attestation verified successfully")
		os.Exit(0)
	} else {
		fmt.Println("❌ Attestation verification failed")
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
