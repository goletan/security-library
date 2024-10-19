// /security/utils/file_permissions_test.go
package utils

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestCheckFilePermissions_Valid tests that checkFilePermissions passes for correctly set permissions.
func TestCheckFilePermissions_Valid(t *testing.T) {
	file, err := os.CreateTemp("", "secure-file-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	// Set restrictive permissions: owner read/write only
	err = os.Chmod(file.Name(), 0600)
	if err != nil {
		t.Fatalf("failed to set file permissions: %v", err)
	}

	err = checkFilePermissions(file.Name())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// TestCheckFilePermissions_TooPermissive tests that checkFilePermissions catches overly permissive permissions.
func TestCheckFilePermissions_TooPermissive(t *testing.T) {
	file, err := os.CreateTemp("", "insecure-file-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	// Set overly permissive permissions: group and others can read
	err = os.Chmod(file.Name(), 0644)
	if err != nil {
		t.Fatalf("failed to set file permissions: %v", err)
	}

	err = checkFilePermissions(file.Name())
	if err == nil || err.Error() != fmt.Sprintf("file %s has too permissive permissions", file.Name()) {
		t.Fatalf("expected permissive permissions error, got %v", err)
	}
}

// TestCheckFilePermissions_FileNotExist tests the behavior when the file does not exist.
func TestCheckFilePermissions_FileNotExist(t *testing.T) {
	nonExistentFile := "/tmp/non-existent-file.txt"

	err := checkFilePermissions(nonExistentFile)
	if err == nil || !os.IsNotExist(err) {
		t.Fatalf("expected file not exist error, got %v", err)
	}
}

// TestCheckFilePermissions_WrongOwnership tests that checkFilePermissions detects files not owned by the current user.
func TestCheckFilePermissions_WrongOwnership(t *testing.T) {
	// Skip this test on Windows as ownership checks are not implemented for Windows
	if runtime.GOOS == "windows" {
		t.Skip("Skipping ownership test on Windows")
	}

	// Set the environment variable to simulate the wrong ownership scenario
	os.Setenv("GOLETAN_TEST_MODE", "simulate_wrong_owner")
	defer os.Unsetenv("GOLETAN_TEST_MODE")

	file, err := os.CreateTemp("", "wrong-owner-file-*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(file.Name())

	// Run the check expecting a simulated ownership error
	err = checkFilePermissions(file.Name())
	if err == nil || !strings.Contains(err.Error(), "not owned by the current user") {
		t.Fatalf("expected ownership error, got %v", err)
	}
}
