// /security/certificates/cert_validator.go
package certificates

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

// OCSPChecker defines a function type for checking OCSP status
type OCSPChecker func(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error)

// CRLChecker defines a function type for checking CRL status
type CRLChecker func(cert *x509.Certificate) error

// VerifyPeerCertificate performs OCSP and CRL checks on the peer certificate to ensure it has not been revoked.
func VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, checkOCSP OCSPChecker, checkCRL CRLChecker) error {
	for _, chain := range verifiedChains {
		// The target certificate should be the leaf (first in the chain)
		if len(chain) < 2 {
			return fmt.Errorf("invalid certificate chain: expected at least two certificates (target and issuer)")
		}

		// Use the first certificate as the target and the second as its issuer
		targetCert := chain[0]
		issuerCert := chain[1]

		// Perform OCSP check on the target certificate using the issuer
		ocspStatus, err := checkOCSP(targetCert, issuerCert)
		if err != nil {
			log.Printf("OCSP check failed: %v", err)
			return fmt.Errorf("failed OCSP check: %w", err)
		}

		// Explicitly check for revoked status
		if ocspStatus.Status == ocsp.Revoked {
			log.Printf("Certificate status is revoked: %d", ocspStatus.Status)
			return fmt.Errorf("certificate status is not good: %d", ocspStatus.Status)
		}

		// Perform CRL check if needed
		if err := checkCRL(targetCert); err != nil {
			log.Printf("CRL check failed: %v", err)
			return fmt.Errorf("failed CRL check: %w", err)
		}
	}
	return nil
}

// realCheckOCSP performs a real OCSP check to verify the revocation status of a certificate.
func realCheckOCSP(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
	// Check if the certificate has OCSP server URLs
	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("no OCSP server specified in certificate")
	}

	// Create an OCSP request for the certificate
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Use the first OCSP server URL specified in the certificate
	ocspURL := cert.OCSPServer[0]
	log.Printf("Attempting OCSP check with server URL: %s", ocspURL)

	// Attempt to send the OCSP request to the server
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspRequest))
	if err != nil {
		log.Printf("Error contacting OCSP server: %v", err)
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer resp.Body.Close()

	// Check if the response status code is successful
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned non-OK status: %v", resp.Status)
	}

	// Read and parse the OCSP response
	ocspResponseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspResponse, err := ocsp.ParseResponse(ocspResponseBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	return ocspResponse, nil
}

// Placeholder for CRL checking logic; not implemented here
func realCheckCRL(cert *x509.Certificate) error {
	// Implement CRL check logic if needed
	return nil
}
