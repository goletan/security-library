// /security/mtls/mtls_test.go
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

func TestConfigureMTLS_Success(t *testing.T) {
	os.Setenv("CERT_PATH", "../../test/core/security/valid-cert.pem")
	os.Setenv("KEY_PATH", "../../test/core/security/valid-cert.key")
	os.Setenv("CA_PATH", "../../test/core/security/rootCA.pem")

	// Use the normal function
	tlsConfig, err := ConfigureMTLS()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(tlsConfig.Certificates) == 0 {
		t.Error("expected at least one certificate, but got none")
	}
	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected client auth mode to be RequireAndVerifyClientCert, got %v", tlsConfig.ClientAuth)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected minimum TLS version to be TLS 1.3, got %v", tlsConfig.MinVersion)
	}
}

func TestConfigureMTLS_PeerVerificationError(t *testing.T) {
	os.Setenv("CERT_PATH", "../../test/core/security/valid-cert.pem")
	os.Setenv("KEY_PATH", "../../test/core/security/valid-cert.key")
	os.Setenv("CA_PATH", "../../test/core/security/rootCA.pem")

	// Mock verification function that simulates an error
	mockVerifyPeerCert := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, checkOCSP OCSPChecker, checkCRL CRLChecker) error {
		log.Println("Mock verification function called.")
		return fmt.Errorf("simulated verification error")
	}

	// Use the injected function for testing error handling
	tlsConfig, err := configureMTLSWithVerifier(mockVerifyPeerCert)
	if err != nil {
		t.Fatalf("unexpected error configuring mTLS: %v", err)
	}

	// Manually trigger the VerifyPeerCertificate to ensure it uses the mock
	err = tlsConfig.VerifyPeerCertificate(nil, nil)
	if err == nil || err.Error() != "simulated verification error" {
		t.Fatalf("expected peer verification error, got %v", err)
	}
}

func TestConfigureMTLS_MissingCertPath(t *testing.T) {
	// Set environment variables with a missing certificate path
	os.Unsetenv("CERT_PATH")
	os.Setenv("KEY_PATH", "../../test/core/security/valid-cert.key")
	os.Setenv("CA_PATH", "../../test/core/security/rootCA.pem")

	_, err := ConfigureMTLS()
	if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("expected error due to missing CERT_PATH, got %v", err)
	}
}

func TestConfigureMTLS_InvalidCAPath(t *testing.T) {
	// Set environment variables with an invalid CA path
	os.Setenv("CERT_PATH", "../../test/core/security/valid-cert.pem")
	os.Setenv("KEY_PATH", "../../test/core/security/valid-cert.key")
	os.Setenv("CA_PATH", "invalid-ca-path.pem")

	_, err := ConfigureMTLS()
	if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("expected error due to invalid CA_PATH, got %v", err)
	}
}
