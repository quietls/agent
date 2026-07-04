package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"math"
	"sync"
	"time"
)

// canonicalPayload defines the exact field order for HMAC signing.
// encoding/json marshals struct fields in declaration order, which must match
// the field order the backend uses when signing commands.
type canonicalPayload struct {
	CommandID   string         `json:"command_id"`
	ExecutionID string         `json:"execution_id"`
	Parameters  map[string]any `json:"parameters"`
	Timestamp   int64          `json:"timestamp"`
	Nonce       string         `json:"nonce"`
}

// CommandFields holds the fields needed for HMAC computation.
type CommandFields struct {
	CommandID   string
	ExecutionID string
	Parameters  map[string]any
	Timestamp   int64
	Nonce       string
	Signature   string
}

// ComputeSignature computes an HMAC-SHA256 signature for the given command fields.
func ComputeSignature(cmd CommandFields, secret string) string {
	payload := canonicalPayload{
		CommandID:   cmd.CommandID,
		ExecutionID: cmd.ExecutionID,
		Parameters:  cmd.Parameters,
		Timestamp:   cmd.Timestamp,
		Nonce:       cmd.Nonce,
	}

	if payload.Parameters == nil {
		payload.Parameters = map[string]any{}
	}

	data, _ := json.Marshal(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature verifies an HMAC-SHA256 signature using timing-safe comparison.
func VerifySignature(cmd CommandFields, secret string) bool {
	expected := ComputeSignature(cmd, secret)

	expectedBytes, err := hex.DecodeString(expected)
	if err != nil {
		return false
	}

	actualBytes, err := hex.DecodeString(cmd.Signature)
	if err != nil {
		return false
	}

	if len(expectedBytes) != len(actualBytes) {
		return false
	}

	return subtle.ConstantTimeCompare(expectedBytes, actualBytes) == 1
}

// IsTimestampValid checks if a unix timestamp is within maxAgeSeconds of the current time.
func IsTimestampValid(timestamp int64, maxAgeSeconds int) bool {
	now := time.Now().Unix()
	diff := math.Abs(float64(now - timestamp))
	return diff <= float64(maxAgeSeconds)
}

// NonceStore tracks recently seen nonces to prevent replay attacks.
// It uses an LRU eviction strategy based on a ring buffer.
type NonceStore struct {
	mu      sync.Mutex
	seen    map[string]struct{}
	order   []string
	maxSize int
}

// NewNonceStore creates a new NonceStore with the given max capacity.
func NewNonceStore(maxSize int) *NonceStore {
	if maxSize <= 0 {
		maxSize = 10000
	}
	return &NonceStore{
		seen:    make(map[string]struct{}),
		order:   make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

// Check returns true if the nonce is unique (not seen before), false if duplicate.
// If unique, it adds the nonce to the store.
func (s *NonceStore) Check(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.seen[nonce]; exists {
		return false
	}

	if len(s.order) >= s.maxSize {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.seen, oldest)
	}

	s.seen[nonce] = struct{}{}
	s.order = append(s.order, nonce)
	return true
}
