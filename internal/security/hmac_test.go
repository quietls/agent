package security

import (
	"testing"
	"time"
)

func makeTestCommand() CommandFields {
	return CommandFields{
		CommandID:   "cert.scan",
		ExecutionID: "exec_123",
		Parameters:  map[string]any{},
		Timestamp:   time.Now().Unix(),
		Nonce:       "n_abc",
	}
}

func TestComputeSignature_Deterministic(t *testing.T) {
	cmd := makeTestCommand()
	secret := "test-secret-key"

	sig1 := ComputeSignature(cmd, secret)
	sig2 := ComputeSignature(cmd, secret)

	if sig1 != sig2 {
		t.Errorf("signatures should be deterministic: got %s and %s", sig1, sig2)
	}
}

func TestComputeSignature_DifferentSecrets(t *testing.T) {
	cmd := makeTestCommand()

	sig1 := ComputeSignature(cmd, "secret-a")
	sig2 := ComputeSignature(cmd, "secret-b")

	if sig1 == sig2 {
		t.Error("different secrets should produce different signatures")
	}
}

func TestComputeSignature_DifferentParameters(t *testing.T) {
	secret := "test-secret-key"

	cmd1 := makeTestCommand()
	cmd1.Parameters = map[string]any{"a": float64(1)}

	cmd2 := makeTestCommand()
	cmd2.Parameters = map[string]any{"a": float64(2)}

	sig1 := ComputeSignature(cmd1, secret)
	sig2 := ComputeSignature(cmd2, secret)

	if sig1 == sig2 {
		t.Error("different parameters should produce different signatures")
	}
}

func TestVerifySignature_Valid(t *testing.T) {
	secret := "test-secret-key"
	cmd := makeTestCommand()
	cmd.Signature = ComputeSignature(cmd, secret)

	if !VerifySignature(cmd, secret) {
		t.Error("valid signature should verify")
	}
}

func TestVerifySignature_WrongSecret(t *testing.T) {
	cmd := makeTestCommand()
	cmd.Signature = ComputeSignature(cmd, "correct-secret")

	if VerifySignature(cmd, "wrong-secret") {
		t.Error("wrong secret should fail verification")
	}
}

func TestVerifySignature_TamperedParameters(t *testing.T) {
	secret := "test-secret-key"
	cmd := makeTestCommand()
	cmd.Signature = ComputeSignature(cmd, secret)

	cmd.Parameters = map[string]any{"tampered": true}

	if VerifySignature(cmd, secret) {
		t.Error("tampered parameters should fail verification")
	}
}

func TestVerifySignature_InvalidHex(t *testing.T) {
	secret := "test-secret-key"
	cmd := makeTestCommand()
	cmd.Signature = "not-valid-hex"

	if VerifySignature(cmd, secret) {
		t.Error("invalid hex signature should fail verification")
	}
}

func TestIsTimestampValid_Current(t *testing.T) {
	now := time.Now().Unix()
	if !IsTimestampValid(now, 60) {
		t.Error("current timestamp should be valid")
	}
}

func TestIsTimestampValid_Expired(t *testing.T) {
	old := time.Now().Unix() - 120
	if IsTimestampValid(old, 60) {
		t.Error("old timestamp should be invalid")
	}
}

func TestIsTimestampValid_Future(t *testing.T) {
	future := time.Now().Unix() + 120
	if IsTimestampValid(future, 60) {
		t.Error("far future timestamp should be invalid")
	}
}

func TestIsTimestampValid_WithinTolerance(t *testing.T) {
	nearPast := time.Now().Unix() - 30
	if !IsTimestampValid(nearPast, 60) {
		t.Error("near-past timestamp should be valid")
	}
}

func TestNonceStore_UniqueNonces(t *testing.T) {
	store := NewNonceStore(100)

	if !store.Check("n_1") {
		t.Error("first nonce should be accepted")
	}
	if !store.Check("n_2") {
		t.Error("second unique nonce should be accepted")
	}
}

func TestNonceStore_DuplicateNonces(t *testing.T) {
	store := NewNonceStore(100)

	if !store.Check("n_1") {
		t.Error("first check should accept")
	}
	if store.Check("n_1") {
		t.Error("duplicate nonce should be rejected")
	}
}

func TestNonceStore_EvictsOldEntries(t *testing.T) {
	store := NewNonceStore(3)

	store.Check("n_1")
	store.Check("n_2")
	store.Check("n_3")
	store.Check("n_4") // evicts n_1

	if !store.Check("n_1") {
		t.Error("evicted nonce should be accepted again")
	}
	if store.Check("n_4") {
		t.Error("n_4 should still be in store")
	}
}
