package certs

import (
	"testing"
)

func TestValidateCertPath_AllowedRoots(t *testing.T) {
	cases := []string{
		"/etc/ssl/cert.pem",
		"/etc/nginx/ssl/example.com.crt",
		"/etc/apache2/ssl/example.com.crt",
		"/etc/letsencrypt/live/example.com/fullchain.pem",
	}
	for _, p := range cases {
		if err := ValidateCertPath(p, nil); err != nil {
			t.Errorf("ValidateCertPath(%q) should succeed, got: %v", p, err)
		}
	}
}

func TestValidateCertPath_ExplicitAllowlist(t *testing.T) {
	if err := ValidateCertPath("/custom/path/cert.pem", []string{"/custom/path/cert.pem"}); err != nil {
		t.Errorf("explicit allowlist should succeed: %v", err)
	}
}

func TestValidateCertPath_RejectsRelative(t *testing.T) {
	if err := ValidateCertPath("etc/ssl/cert.pem", nil); err == nil {
		t.Error("expected relative path to be rejected")
	}
}

func TestValidateCertPath_RejectsTraversal(t *testing.T) {
	if err := ValidateCertPath("/etc/ssl/../shadow", nil); err == nil {
		t.Error("expected traversal to be rejected")
	}
}

func TestValidateCertPath_RejectsOutsideRoots(t *testing.T) {
	if err := ValidateCertPath("/etc/passwd", nil); err == nil {
		t.Error("expected path outside SSL roots to be rejected")
	}
}
