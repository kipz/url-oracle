package attestation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	"github.com/openpubkey/openpubkey/pktoken"
)

// AttestationPayload represents the attestation data
type AttestationPayload struct {
	CommitSHA string            `json:"commit_sha"`
	Timestamp string            `json:"timestamp"`
	Url       string            `json:"url"`
	Content   string            `json:"content"`
	Metadata  map[string]string `json:"metadata"`
}

// Attestation represents the complete attestation
type Attestation struct {
	Payload   AttestationPayload `json:"payload"`
	PKToken   *pktoken.PKToken   `json:"pk_token"`
	Signature []byte             `json:"signature"`
}

// Hash generates a SHA256 hash of the attestation payload
func (ap *AttestationPayload) Hash() ([]byte, error) {
	// Create a deterministic representation of the attestation
	data, err := json.Marshal(ap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation: %w", err)
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
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

// CreateAttestationPayload creates a new attestation payload with the given parameters
func CreateAttestationPayload(commitSHA, timestamp, url string, content string) *AttestationPayload {
	return &AttestationPayload{
		CommitSHA: commitSHA,
		Timestamp: timestamp,
		Url:       url,
		Content:   content,
		Metadata: map[string]string{
			"repository": os.Getenv("GITHUB_REPOSITORY"),
		},
	}
}
