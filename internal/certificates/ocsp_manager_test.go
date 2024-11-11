// /security/internal/certificates/ocsp_manager_test.go
package certificates

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Dummy private key implementation to avoid nil errors during testing
type dummyPrivateKey struct{}

// mockPublicKey simulates a public key for the x509.Certificate structure.
type mockPublicKey struct{}

var mockOCSPResponse = []byte{
	0x30, 0x82, 0x03, 0x23, // Example header bytes (adjust as needed)
	// ... add more bytes to mimic a real OCSP response
}

func (k *dummyPrivateKey) Public() crypto.PublicKey { return &dummyPrivateKey{} }

func (k *dummyPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("dummy_signature"), nil
}

// Implement the crypto.PublicKey interface for the mock public key.
func (m *mockPublicKey) Public() crypto.PublicKey {
	return m
}

// LoadPrivateKeyFromFile loads a private key from a PEM file and returns it as a crypto.Signer.
func LoadKeyFromFile(filePath string) (crypto.Signer, error) {
	keyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode the PEM block containing the key
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("failed to parse private key PEM")
	}

	var parsedKey any
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		parsedKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, errors.New("unsupported private key type")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Ensure the key implements crypto.Signer
	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("parsed key does not implement crypto.Signer")
	}

	return signer, nil
}

// loadMockCertsForTesting loads mock certificates for testing OCSP requests.
func loadMockCertsForTesting() (*x509.Certificate, *x509.Certificate, error) {
	cwd, _ := os.Getwd()

	if strings.Contains(cwd, "core/security") {
		cwd = filepath.Dir(filepath.Dir(cwd))
	}

	// Load certificate
	certPath := filepath.Join(cwd, "tests", "core", "security", "ocsp-cert.pem")
	cert, err := LoadCertFromFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load OCSP certificate: %w", err)
	}

	// Load issuer certificate
	issuerPath := filepath.Join(cwd, "tests", "core", "security", "rootCA.pem")
	issuer, err := LoadCertFromFile(issuerPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load issuer certificate: %w", err)
	}

	return cert, issuer, nil
}

// mockOCSPRequestFunc simulates an OCSP request and generates a mock response.
func mockOCSPRequestFunc(url string, contentType string, body io.Reader) (*http.Response, error) {
	// Read and parse the OCSP request from the body
	ocspRequestBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP request body: %w", err)
	}

	ocspReq, err := ocsp.ParseRequest(ocspRequestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP request: %w", err)
	}

	// Load mock certificates for testing the OCSP response
	cert, issuer, err := loadMockCertsForTesting()
	if err != nil {
		return nil, fmt.Errorf("failed to load mock certificates: %w", err)
	}

	cwd, _ := os.Getwd()
	if strings.Contains(cwd, "core/security") {
		cwd = filepath.Dir(filepath.Dir(cwd))
	}

	// Load the private key associated with the issuer certificate
	keyPath := filepath.Join(cwd, "tests", "core", "security", "rootCA.key") // Ensure the correct private key is used
	issuerKey, err := LoadKeyFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load issuer private key: %w", err)
	}

	// Create the OCSP response using the loaded certificates and private key
	ocspResp := ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	// Properly create the OCSP response using the issuer and corresponding key
	respBytes, err := ocsp.CreateResponse(issuer, cert, ocspResp, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP response: %w", err)
	}

	// Return the mock HTTP response with the OCSP response bytes
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(respBytes)),
	}, nil
}

// TestCheckOCSP_Success tests the successful OCSP check scenario.
func TestCheckOCSP_Success(t *testing.T) {
	// Initialize OCSPManager with the mock function
	manager := NewOCSPManager(httpClient, mockOCSPRequestFunc, 24*time.Hour)

	// Load the mock certificate and issuer for testing
	cert, issuer, err := loadMockCertsForTesting()
	if err != nil {
		t.Fatalf("failed to load mock certificates: %v", err)
	}

	// Perform the OCSP check with a valid server and response
	resp, err := manager.CheckOCSP(cert, issuer)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("expected OCSP status Good, got %v", resp.Status)
	}
}

func TestCheckOCSP_NoServer(t *testing.T) {
	// Initialize OCSPManager with the mock function
	manager := NewOCSPManager(httpClient, mockOCSPRequestFunc, 24*time.Hour)

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12346),
		OCSPServer:   []string{},
	}

	issuer := &x509.Certificate{}

	// Test CheckOCSP with no OCSP server specified
	_, err := manager.CheckOCSP(cert, issuer)
	if err == nil || err.Error() != "no OCSP server specified in certificate" {
		t.Fatalf("expected no OCSP server error, got %v", err)
	}
}

func TestCheckOCSP_CachedResponse(t *testing.T) {
	// Initialize OCSPManager with the mock function
	manager := NewOCSPManager(httpClient, mockOCSPRequestFunc, 24*time.Hour)

	// Load the mock certificate and issuer for testing
	cert, issuer, err := loadMockCertsForTesting()
	if err != nil {
		t.Fatalf("failed to load mock certificates: %v", err)
	}

	// Pre-cache a response that matches the expected OCSP response structure
	cachedResp := &ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	}

	// Manually cache the response
	manager.CacheOCSPResponse(cert, cachedResp)

	// Test CheckOCSP retrieves cached response
	resp, err := manager.CheckOCSP(cert, issuer)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("expected cached OCSP status Good, got %v", resp.Status)
	}
}
