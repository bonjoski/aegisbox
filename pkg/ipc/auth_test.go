package ipc

import (
	"testing"
	"time"
)

func TestTokenStore_Lifecycle(t *testing.T) {
	store := NewTokenStore(100 * time.Millisecond)

	token, err := store.IssueToken(1234, "v1.0.0", "darwin")
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	if len(token) != 64 {
		t.Errorf("expected 64-char hex token, got length %d", len(token))
	}

	// Positive validation
	if !store.ValidateToken(token) {
		t.Errorf("expected token to validate successfully")
	}

	// Invalid token length
	if store.ValidateToken("invalid-short-token") {
		t.Errorf("expected short token to fail validation")
	}

	// Fake 64-char token
	fakeToken := "0000000000000000000000000000000000000000000000000000000000000000"
	if store.ValidateToken(fakeToken) {
		t.Errorf("expected fake token to fail validation")
	}

	// Expiry test
	time.Sleep(150 * time.Millisecond)
	if store.ValidateToken(token) {
		t.Errorf("expected token to be expired after TTL")
	}
}

func TestTokenStore_Revocation(t *testing.T) {
	store := NewTokenStore(10 * time.Minute)
	token, _ := store.IssueToken(5678, "v1.0.0", "darwin")

	if !store.ValidateToken(token) {
		t.Fatalf("token should be valid before revocation")
	}

	store.RevokeToken(token)

	if store.ValidateToken(token) {
		t.Errorf("token should be invalid after revocation")
	}
}
