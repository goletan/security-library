// /security/internal/utils/http_client_test.go
package utils

import (
	"testing"
	"time"

	"github.com/goletan/config"
)

// TestInitializeHTTPClient_Success tests the successful initialization of the HTTP client.
func TestInitializeHTTPClient_Success(t *testing.T) {
	// Mock configuration for testing
	config.Security.HTTPClient.Timeout = 10
	config.Security.HTTPClient.TLSVersion = "TLS13"
	config.Security.HTTPClient.MaxIdleConnectionsPerHost = 10

	err := InitializeHTTPClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Validate the configuration of the HTTP client
	if httpClient.Timeout != 10*time.Second {
		t.Errorf("expected timeout to be 10s, got %s", httpClient.Timeout)
	}
}

// TestShutdownHTTPClient_Success tests the graceful shutdown of the HTTP client.
func TestShutdownHTTPClient_Success(t *testing.T) {
	err := InitializeHTTPClient()
	if err != nil {
		t.Fatalf("failed to initialize HTTP client: %v", err)
	}

	err = ShutdownHTTPClient()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// TestShutdownHTTPClient_NotInitialized tests the shutdown behavior when the client is not initialized.
func TestShutdownHTTPClient_NotInitialized(t *testing.T) {
	httpClient = nil // Ensure the client is not initialized

	err := ShutdownHTTPClient()
	if err != nil {
		t.Fatalf("expected no error when shutting down uninitialized client, got %v", err)
	}
}
