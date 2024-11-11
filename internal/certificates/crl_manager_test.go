// /security/internal/certificates/crl_manager_test.go
package certificates

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockRoundTripper is a custom RoundTripper that mocks HTTP requests.
type mockRoundTripper struct{}

// RoundTrip implements the RoundTripper interface for mocking.
func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cwd, _ := os.Getwd()

	// Adjust the current working directory if running from a nested directory
	if strings.Contains(cwd, "core/security") {
		cwd = filepath.Dir(filepath.Dir(cwd))
	}

	// Load the CRL from the file system
	crlPath := filepath.Join(cwd, "tests", "core", "security", "crl.der")
	crlBytes, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, errors.New("failed to read CRL file")
	}

	switch req.URL.String() {
	case "http://test-crl-valid.com/crl.pem":
		// Use the loaded CRL bytes from the file
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(crlBytes)),
		}, nil
	case "http://test-crl-revoked.com/crl.pem":
		// Simulate a CRL with a revoked certificate using the same loaded bytes
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(crlBytes)),
		}, nil
	case "http://test-crl-malformed.com/crl.pem":
		// Simulate a malformed CRL response
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte("invalid CRL data"))), // Malformed data
		}, nil
	default:
		// Simulate an error response
		return nil, errors.New("failed to fetch CRL")
	}
}

func init() {
	// Ensure httpClient is properly initialized before setting Transport
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	// Set the custom RoundTripper on the httpClient
	httpClient.Transport = &mockRoundTripper{}
}

// Test CRL fetching and parsing
func TestCheckCRL_ValidCert(t *testing.T) {
	// Mock valid certificate with CRL distribution point
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(12346),
		CRLDistributionPoints: []string{"http://test-crl-valid.com/crl.pem"},
	}

	// Test CheckCRL function
	err := CheckCRL(cert)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

// Test malformed CRL handling
func TestCheckCRL_MalformedCRL(t *testing.T) {
	// Mock certificate with CRL distribution point
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(12347),
		CRLDistributionPoints: []string{"http://test-crl-malformed.com/crl.pem"},
	}

	// Run CheckCRL and expect a parsing error
	err := CheckCRL(cert)
	if err == nil || !strings.Contains(err.Error(), "error parsing CRL") {
		t.Fatalf("expected parsing error, got %v", err)
	}
}
