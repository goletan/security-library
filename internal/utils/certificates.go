package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// Helper to parse a PEM encoded certificate
func ParsePEMCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	return x509.ParseCertificate(block.Bytes)
}
