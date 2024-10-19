// /security/certificates/cert_loader_test.go
package certificates

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTLSCertificate_ValidPaths(t *testing.T) {
	cwd, _ := os.Getwd()

	if strings.Contains(cwd, "core/security") {
		// Move two levels up to the project root
		cwd = filepath.Dir(filepath.Dir(cwd))
	}

	certPath := filepath.Join(cwd, "tests", "core", "security", "test-cert.pem")
	keyPath := filepath.Join(cwd, "tests", "core", "security", "test-key.pem")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("certificate file not found: %v", err)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("key file not found: %v", err)
	}

	// Test loading the certificate and key
	cert, err := LoadTLSCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cert.Leaf == nil {
		t.Error("expected a loaded certificate, but got nil")
	}
}

func TestLoadTLSCertificate_InvalidPaths(t *testing.T) {
	cwd, _ := os.Getwd()

	if strings.Contains(cwd, "core/security") {
		cwd = filepath.Dir(filepath.Dir(cwd))
	}
	invalidCertPath := filepath.Join(cwd, "tests", "core", "security", "invalid", "invalid-cert-path.pem")
	invalidKeyPath := filepath.Join(cwd, "tests", "core", "security", "invalid", "invalid-key-path.pem")

	_, err := LoadTLSCertificate(invalidCertPath, invalidKeyPath)
	if err == nil {
		t.Error("expected error for invalid paths, got none")
	}
}

func TestLoadTLSCertificate_CorruptedFile(t *testing.T) {
	certFile, err := os.CreateTemp("", "corrupt-cert-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())
	_, err = certFile.Write([]byte(`invalid certificate data`))
	if err != nil {
		t.Fatalf("failed to write to temp cert file: %v", err)
	}

	keyFile, err := os.CreateTemp("", "corrupt-key-*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())
	_, err = keyFile.Write([]byte(`invalid key data`))
	if err != nil {
		t.Fatalf("failed to write to temp key file: %v", err)
	}

	_, err = LoadTLSCertificate(certFile.Name(), keyFile.Name())
	if err == nil {
		t.Error("expected error for corrupted certificate files, got none")
	}
}

func TestCheckFilePermissions(t *testing.T) {
	tempFile, err := os.CreateTemp("", "test-file-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Set permissive permissions
	err = os.Chmod(tempFile.Name(), 0666)
	if err != nil {
		t.Fatalf("failed to change file permissions: %v", err)
	}

	err = checkFilePermissions(tempFile.Name())
	if err == nil {
		t.Error("expected error for overly permissive permissions, got none")
	}

	// Set restrictive permissions
	err = os.Chmod(tempFile.Name(), 0600)
	if err != nil {
		t.Fatalf("failed to change file permissions: %v", err)
	}

	err = checkFilePermissions(tempFile.Name())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}
