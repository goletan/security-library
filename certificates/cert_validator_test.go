// /security/certificates/cert_validator.go
package certificates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// LoadCertFromFile loads an x509 certificate from a given file path.
func LoadCertFromFile(filePath string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to parse certificate PEM: PEM block not found or incorrect type")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// Mock OCSP and CRL functions
func mockCheckOCSP(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	log.Printf("Checking OCSP for certificate with CN: %s", cert.Subject.CommonName)

	switch cert.Subject.CommonName {
	case "valid-cert":
		log.Println("Mock OCSP Response: Good status for valid-cert")
		return &ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: cert.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}, nil
	case "revoked-cert":
		log.Println("Mock OCSP Response: Revoked status for revoked-cert")
		return &ocsp.Response{
			Status:       ocsp.Revoked,
			SerialNumber: cert.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
			RevokedAt:    time.Now().Add(-time.Hour),
		}, nil
	case "crl-failed-cert":
		// Simulate Good OCSP status to allow the flow to reach the CRL check
		log.Println("Mock OCSP Response: Good status for crl-failed-cert to test CRL check")
		return &ocsp.Response{
			Status:       ocsp.Good,
			SerialNumber: cert.SerialNumber,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(24 * time.Hour),
		}, nil
	default:
		log.Println("Mock OCSP Response: OCSP server error for unknown certificate")
		return nil, errors.New("OCSP server error")
	}
}

func mockCheckCRL(cert *x509.Certificate) error {
	if cert.Subject.CommonName == "crl-failed-cert" {
		return errors.New("certificate is in CRL")
	}
	return nil
}

func TestVerifyPeerCertificate_ValidCert(t *testing.T) {
	cwd, _ := os.Getwd()

	if strings.Contains(cwd, "core/security") {
		cwd = filepath.Dir(filepath.Dir(cwd))
	}

	certPath := filepath.Join(cwd, "tests", "core", "security", "valid-cert.pem")
	cert, err := LoadCertFromFile(certPath)
	if err != nil {
		t.Fatalf("failed to load valid certificate: %v", err)
	}

	rootCAPath := filepath.Join(cwd, "tests", "core", "security", "rootCA.pem")
	issuer, err := LoadCertFromFile(rootCAPath)
	if err != nil {
		t.Fatalf("failed to load issuer certificate: %v", err)
	}
	chain := [][]*x509.Certificate{{cert, issuer}}

	err = VerifyPeerCertificate(nil, chain, mockCheckOCSP, mockCheckCRL)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestVerifyPeerCertificate_RevokedCert(t *testing.T) {
	cwd, _ := os.Getwd()

	if strings.Contains(cwd, "core/security") {
		cwd = filepath.Dir(filepath.Dir(cwd))
	}

	revokedCertPath := filepath.Join(cwd, "tests", "core", "security", "revoked-cert.pem")
	cert, err := LoadCertFromFile(revokedCertPath)
	if err != nil {
		t.Fatalf("failed to load revoked certificate: %v", err)
	}

	rootCAPath := filepath.Join(cwd, "tests", "core", "security", "rootCA.pem")
	issuer, err := LoadCertFromFile(rootCAPath)
	if err != nil {
		t.Fatalf("failed to load issuer certificate: %v", err)
	}
	chain := [][]*x509.Certificate{{cert, issuer}}

	err = VerifyPeerCertificate(nil, chain, mockCheckOCSP, mockCheckCRL)
	if err == nil || err.Error() != "certificate status is not good: 1" {
		t.Fatalf("expected certificate status not good error, got %v", err)
	}
}

func TestVerifyPeerCertificate_CRLFailed(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "crl-failed-cert"}}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "issuer-cert"}}
	chain := [][]*x509.Certificate{{cert, issuer}}

	err := VerifyPeerCertificate(nil, chain, mockCheckOCSP, mockCheckCRL)
	if err == nil || err.Error() != "failed CRL check: certificate is in CRL" {
		t.Fatalf("expected CRL check failed error, got %v", err)
	}
}

func TestVerifyPeerCertificate_OCSPError(t *testing.T) {
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "unknown-cert"}}
	issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "issuer-cert"}}
	chain := [][]*x509.Certificate{{cert, issuer}}

	err := VerifyPeerCertificate(nil, chain, mockCheckOCSP, mockCheckCRL)
	if err == nil || err.Error() != "failed OCSP check: OCSP server error" {
		t.Fatalf("expected OCSP server error, got %v", err)
	}
}
