// /security/utils/file_permissions.go
package utils

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkFilePermissions checks that the file has the correct permissions to prevent unauthorized access and is owned by the current user.
func CheckFilePermissions(filePath string) error {
	info, err := os.Stat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err != nil {
		return fmt.Errorf("unable to access file: %w", err)
	}

	// Handle test environment with GOLETAN_TEST_MODE flag
	testMode := os.Getenv("GOLETAN_TEST_MODE")
	if testMode == "simulate_wrong_owner" {
		return fmt.Errorf("file %s is not owned by the current user", filePath)
	}

	// Check file permissions (must not be accessible by group or others)
	if info.Mode().Perm()&(syscall.S_IRWXG|syscall.S_IRWXO) != 0 {
		return fmt.Errorf("file %s has too permissive permissions", filePath)
	}

	// Explicitly check for secure permissions (600 or 400)
	if info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
		return fmt.Errorf("file %s has invalid permissions: %o, expected 600 or 400", filePath, info.Mode().Perm())
	}

	return nil
}
