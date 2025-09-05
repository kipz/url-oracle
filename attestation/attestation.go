package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
)

const (
	githubIssuer = "https://token.actions.githubusercontent.com"
)

// AttestationPayload represents the attestation data (protected by the signature)
type AttestationPayload struct {
	CommitSHA           string              `json:"commit_sha"`
	Timestamp           string              `json:"timestamp"`
	Url                 string              `json:"url"`
	Content             []byte              `json:"content"`
	ContentDigest       string              `json:"content_digest"`
	ContentSize         int64               `json:"content_size"`
	PreviousAttestation *AttestationDetails `json:"previous_attestation"`
}

// AttestationDetails represents the details of the previous attestation
type AttestationDetails struct {
	Digest      string `json:"digest"`
	ArtifactURL string `json:"artifact_url"` // stable for max 30 days
}

// Attestation represents the complete attestation
type Attestation struct {
	Payload   AttestationPayload `json:"payload"`
	PKToken   *pktoken.PKToken   `json:"pk_token"`
	Signature []byte             `json:"signature"`
}

// Hash generates a SHA256 digest of the attestation payload
func (ap *AttestationPayload) Hash() ([]byte, error) {
	// Create a deterministic representation of the attestation
	data, err := json.Marshal(ap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %w", err)
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}

func LoadAttestation(attestationFile string) (*Attestation, error) {
	data, err := os.ReadFile(attestationFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file: %w", err)
	}

	var attestation Attestation
	if err := json.Unmarshal(data, &attestation); err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	return &attestation, nil
}

func LoadAttestationDetails(attestationDetailsFile string) (*AttestationDetails, error) {
	data, err := os.ReadFile(attestationDetailsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation details file: %w", err)
	}

	var attestationDetails AttestationDetails
	if err := json.Unmarshal(data, &attestationDetails); err != nil {
		return nil, fmt.Errorf("failed to parse attestation details: %w", err)
	}

	return &attestationDetails, nil
}

// CreateAttestationPayload creates a new attestation payload with the given parameters
func CreateAttestationPayload(timestamp string, commitSHA string, previousAttestation *AttestationDetails, url string, content []byte, contentDigest string, contentSize int64) (*AttestationPayload, error) {
	return &AttestationPayload{
		CommitSHA:           commitSHA,
		Timestamp:           timestamp,
		Url:                 url,
		Content:             content,
		ContentDigest:       contentDigest,
		ContentSize:         contentSize,
		PreviousAttestation: previousAttestation,
	}, nil
}

// DownloadContent downloads content from a URL and returns the content, digest, and size
func DownloadContent(url string) ([]byte, string, int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to download content from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to read response body: %w", err)
	}

	// Calculate SHA256 digest
	digest := sha256.Sum256(content)
	// hex encode
	digestStr := "sha256:" + hex.EncodeToString(digest[:])
	return content, digestStr, int64(len(content)), nil
}

// CheckContentChanges checks if content has changed by comparing with a previous attestation
func CheckContentChanges(currentDigest string, previousAttestationFile string) (bool, error) {
	// If no previous attestation file provided, assume changes
	if previousAttestationFile == "" {
		return true, nil
	}

	// Load previous attestation
	prevAttestation, err := LoadAttestation(previousAttestationFile)
	if err != nil {
		// If we can't load the previous attestation, assume changes
		return true, nil
	}

	// Compare content digests
	if prevAttestation.Payload.ContentDigest != currentDigest {
		return false, nil
	}

	return true, nil
}

func GetJWKSContent() ([]byte, error) {
	jwks, err := discover.GetJwksByIssuer(context.TODO(), githubIssuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}
	return jwks, nil
}

type IDTokenClaims struct {
	JobWorkflowSHA string `json:"job_workflow_sha"`
	IAT            int64  `json:"iat"`
	WorkflowRef    string `json:"workflow_ref"`
	RunID          string `json:"run_id"`
	Timestamp      string `json:"timestamp"`
}

// extractClaimsFromIDToken extracts job_workflow_sha and iat claims from the PK token payload
func ExtractClaimsFromIDToken(pkToken *pktoken.PKToken) (claims *IDTokenClaims, err error) {
	claims = &IDTokenClaims{}

	if err := json.Unmarshal(pkToken.Payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse PK token payload: %w", err)
	}

	if claims.JobWorkflowSHA == "" {
		return nil, fmt.Errorf("job_workflow_sha claim not found in ID token")
	}

	if claims.IAT == 0 {
		return nil, fmt.Errorf("iat claim not found in ID token")
	}
	if claims.WorkflowRef == "" {
		return nil, fmt.Errorf("workflow_ref claim not found in ID token")
	}

	// Convert IAT (issued at) timestamp to ISO 8601 format
	claims.Timestamp = time.Unix(claims.IAT, 0).UTC().Format(time.RFC3339)
	return claims, nil
}
