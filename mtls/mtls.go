// /security/mtls/mtls.go
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/goletan/config"
)

// VerifyPeerCertFunc defines the signature of the peer certificate verification function with OCSP and CRL checks.
type VerifyPeerCertFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, checkOCSP OCSPChecker, checkCRL CRLChecker) error

// ConfigureMTLS sets up mutual TLS for secure communication between services, including certificate revocation checks.
func ConfigureMTLS() (*tls.Config, error) {
	// Calls the helper function with the default VerifyPeerCertificate function
	return configureMTLSWithVerifier(VerifyPeerCertificate)
}

// configureMTLSWithVerifier is a helper function that accepts a custom verifier for testing.
func configureMTLSWithVerifier(verifyPeerCert VerifyPeerCertFunc) (*tls.Config, error) {
	// Fetch certificate paths from the global configuration
	certPath := config.GlobalConfig.Security.Certificates.ServerCertPath
	keyPath := config.GlobalConfig.Security.Certificates.ServerKeyPath
	caPath := config.GlobalConfig.Security.Certificates.CACertPath

	// Log the paths being used (optional, for debugging)
	log.Printf("Loading certificate and key from paths: cert=%s, key=%s, ca=%s", certPath, keyPath, caPath)

	// Load server certificate and key.
	cert, err := LoadTLSCertificate(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Load CA certificate and create a certificate pool.
	caCertPool, err := LoadCACertificate(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Construct the TLS configuration with enhanced security settings.
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		RootCAs:                  caCertPool,
		ClientCAs:                caCertPool,
		MinVersion:               tls.VersionTLS13,
		ClientAuth:               tls.RequireAndVerifyClientCert,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPeerCert(rawCerts, verifiedChains, realCheckOCSP, realCheckCRL)
		},
	}

	log.Println("mTLS configuration successfully completed with enhanced security and revocation checks.")
	return tlsConfig, nil
}
