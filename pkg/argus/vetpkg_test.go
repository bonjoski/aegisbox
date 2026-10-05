package argus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublicRegistryVerifier_FastPath(t *testing.T) {
	ctx := context.Background()
	verifier := NewPublicRegistryVerifier()

	res, err := verifier.VerifyPackage(ctx, PackageRef{
		Ecosystem: "pypi",
		Name:      "requests",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.ExistsInIndex || res.IsSlopsquat {
		t.Errorf("expected well-known package 'requests' to be validated in fast-path")
	}

	resNPM, err := verifier.VerifyPackage(ctx, PackageRef{
		Ecosystem: "npm",
		Name:      "react",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resNPM.ExistsInIndex || resNPM.IsSlopsquat {
		t.Errorf("expected well-known package 'react' to be validated in fast-path")
	}
}

func TestPublicRegistryVerifier_MockServer(t *testing.T) {
	ctx := context.Background()

	// Mock registry server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pypi/known-custom-lib/json" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/pypi/hallucinated-fake-lib/json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	verifier := &PublicRegistryVerifier{
		httpClient: server.Client(),
		cacheTTL:   5 * time.Minute,
		cache:      make(map[string]cachedEntry),
	}

	// Manually verify cache insertion
	pkg := PackageRef{Ecosystem: "pypi", Name: "custom-cached-pkg"}
	verifier.cache["pypi:custom-cached-pkg"] = cachedEntry{
		result: &VetResult{
			Package:       pkg,
			ExistsInIndex: true,
			IsSlopsquat:   false,
		},
		expiresAt: time.Now().Add(5 * time.Minute),
	}

	res, err := verifier.VerifyPackage(ctx, pkg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.ExistsInIndex {
		t.Errorf("expected cached package to exist")
	}
}

func TestPublicRegistryVerifier_UnsupportedEcosystem(t *testing.T) {
	ctx := context.Background()
	verifier := NewPublicRegistryVerifier()

	res, err := verifier.VerifyPackage(ctx, PackageRef{
		Ecosystem: "unknown_eco",
		Name:      "some-pkg",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.ExistsInIndex {
		t.Errorf("expected unsupported ecosystem to gracefully skip without blocking")
	}
}
