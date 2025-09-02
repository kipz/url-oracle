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
	JWKS                  []byte `json:"jwks"`
	PrevAttestationDigest []byte `json:"prev_attestation_digest"`
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
func CreateAttestationPayload(prevAttestation *Attestation, commitSHA, timestamp, url string, content []byte, contentDigest []byte, contentSize int64) (*AttestationPayload, error) {
	jwks, err := GetJWKSContent()
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	var prevDigest []byte
	if prevAttestation != nil {
		prevDigest, err = prevAttestation.Payload.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to hash previous attestation: %w", err)
		}
	}

	return &AttestationPayload{
		CommitSHA:             commitSHA,
		Timestamp:             timestamp,
		Url:                   url,
		Content:               content,
		ContentDigest:         contentDigest,
		ContentSize:           contentSize,
		JWKS:                  jwks,
		PrevAttestationDigest: prevDigest,
	}, nil
}

// DownloadContent downloads content from a URL and returns the content, hash, and size
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

	// Calculate SHA256 hash
	hash := sha256.Sum256(content)

	return content, hash[:], int64(len(content)), nil
}

// CheckContentChanges checks if content has changed by comparing with a previous attestation
func CheckContentChanges(currentHash []byte, previousAttestationFile string) (bool, error) {
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
	if bytes.Equal(prevAttestation.Payload.ContentDigest, currentHash) {
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
