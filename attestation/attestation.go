package attestation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
)

const (
	githubIssuer = "https://token.actions.githubusercontent.com"
)

// AttestationPayload represents the attestation data
type AttestationPayload struct {
	CommitSHA             string `json:"commit_sha"`
	Timestamp             string `json:"timestamp"`
	Url                   string `json:"url"`
	Content               []byte `json:"content"`
	ContentDigest         []byte `json:"content_digest"`
	ContentSize           int64  `json:"content_size"`
	PrevAttestationDigest []byte `json:"prev_attestation_digest"`
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

// CreateAttestationPayload creates a new attestation payload with the given parameters
func CreateAttestationPayload(previousAttestationDigest []byte, commitSHA, timestamp, url string, content []byte, contentDigest []byte, contentSize int64) (*AttestationPayload, error) {
	return &AttestationPayload{
		CommitSHA:             commitSHA,
		Timestamp:             timestamp,
		Url:                   url,
		Content:               content,
		ContentDigest:         contentDigest,
		ContentSize:           contentSize,
		PrevAttestationDigest: previousAttestationDigest,
	}, nil
}

// DownloadContent downloads content from a URL and returns the content, digest, and size
func DownloadContent(url string) ([]byte, []byte, int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to download content from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, 0, fmt.Errorf("HTTP request failed with status: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to read response body: %w", err)
	}

	// Calculate SHA256 digest
	digest := sha256.Sum256(content)

	return content, digest[:], int64(len(content)), nil
}

// CheckContentChanges checks if content has changed by comparing with a previous attestation
func CheckContentChanges(currentDigest []byte, previousAttestationFile string) (bool, error) {
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
	if bytes.Equal(prevAttestation.Payload.ContentDigest, currentDigest) {
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
