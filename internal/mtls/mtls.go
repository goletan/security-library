package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/goletan/security/config"

	"github.com/goletan/observability/shared/logger"
	"github.com/goletan/security/internal/certificates"
	"go.uber.org/zap"
)

// MTLS struct encapsulates the configuration and logger for mTLS.
type MTLS struct {
	cfg           *config.SecurityConfig
	logger        *logger.ZapLogger
	certLoader    *certificates.CertLoader
	certValidator *certificates.CertValidator
}

// NewMTLS initializes a new MTLS instance with the required dependencies.
func NewMTLS(cfg *config.SecurityConfig, log *logger.ZapLogger, certLoader *certificates.CertLoader, certValidator *certificates.CertValidator) *MTLS {
	return &MTLS{
		cfg:           cfg,
		logger:        log,
		certLoader:    certLoader,
		certValidator: certValidator,
	}
}

// ConfigureMTLS sets up mutual TLS for secure communication between services, including certificate revocation checks.
func (m *MTLS) ConfigureMTLS() (*tls.Config, error) {
	// Load the server TLS configuration
	serverCert, err := m.certLoader.LoadTLSCertificate(m.cfg.Security.Certificates.ServerCertPath, m.cfg.Security.Certificates.ServerKeyPath)
	if err != nil {
		m.logger.Error("Failed to load server certificate and key", zap.Error(err))
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Load the CA certificate pool
	caCertPool, _, err := m.certLoader.LoadCACertificate(m.cfg.Security.Certificates.CACertPath)
	if err != nil {
		m.logger.Error("Failed to load CA certificate", zap.Error(err))
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Construct the TLS configuration with enhanced security settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientCAs:    caCertPool,
		RootCAs:      caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			m.logger.Info("Verifying peer certificate")
			return m.certValidator.VerifyPeerCertificate(verifiedChains)
		},
	}

	m.logger.Info("mTLS configuration successfully completed with enhanced security and revocation checks.")
	return tlsConfig, nil
}
