// /security/pkg/security.go
package security

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	config "github.com/goletan/config/pkg"
	"github.com/goletan/security/internal/certificates"
	"github.com/goletan/security/internal/mtls"
	"github.com/goletan/security/internal/types"
	"github.com/goletan/security/internal/utils"
	"go.uber.org/zap"
)

// Security is the main entry point for all security-related operations in Goletan.
type Security struct {
	Cfg           *types.SecurityConfig
	CertLoader    *certificates.CertLoader
	CertValidator *certificates.CertValidator
	CRLManager    *certificates.CRLManager
	OCSPManager   *certificates.OCSPManager
	MTLSHandler   *mtls.MTLS
	Logger        *zap.Logger
}

type SecurityInterface interface {
	SetupMTLS() error
	LoadCertificates() error
	ValidateCertificate(certPath string) error
	CheckOCSPStatus(certPath string) error
	RevokeCertificates(ctx context.Context, cert *x509.Certificate) error
}

// NewSecurity initializes a new Security instance.
func NewSecurity(logger *zap.Logger) (*Security, error) {
	// Load configuration
	var cfg *types.SecurityConfig
	err := config.LoadConfig("Security", &cfg, nil)
	if err != nil {
		logger.Fatal("Failed to load security config", zap.Error(err))
		return nil, err
	}

	// Initialize shared HTTP client
	httpClient, err := utils.InitializeHTTPClient(cfg)
	if err != nil {
		logger.Fatal("Failed to initialize HTTP client", zap.Error(err))
		return nil, err
	}

	// Initialize certificate components
	certLoader := certificates.NewCertLoader(logger, cfg)
	certValidator := certificates.NewCertValidator(logger, cfg, httpClient)
	crlManager := certificates.NewCRLManager(logger, cfg, httpClient)
	ocspManager := certificates.NewOCSPManager(logger, cfg, httpClient, certificates.RealOCSPRequest)

	// Initialize mTLS component
	mtlsHandler := mtls.NewMTLS(logger, certLoader, certValidator)

	// Create Security instance
	security := &Security{
		CertLoader:    certLoader,
		CertValidator: certValidator,
		CRLManager:    crlManager,
		OCSPManager:   ocspManager,
		MTLSHandler:   mtlsHandler,
		Logger:        logger,
	}

	// Perform initial setup if needed (e.g., load certificates)
	if err := security.LoadCertificates(); err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	return security, nil
}

// SetupMTLS sets up mTLS for secure communication.
func (s *Security) SetupMTLS(ctx context.Context) error {
	s.Logger.Info("Setting up mTLS...")
	_, err := s.MTLSHandler.ConfigureMTLS(ctx)
	return err
}

// LoadCertificates loads all necessary certificates for the system.
func (s *Security) LoadCertificates() error {
	s.Logger.Info("Loading certificates...")
	return s.CertLoader.LoadCertificates()
}

// ValidateCertificate validates a given certificate.
func (s *Security) ValidateCertificate(certPath string) error {
	s.Logger.Info("Validating certificate...", zap.String("certPath", certPath))
	return s.CertValidator.ValidateCertificate(certPath)
}

// CheckOCSPStatus checks the OCSP status of a certificate.
func (s *Security) CheckOCSPStatus(certPath string) error {
	s.Logger.Info("Checking OCSP status...", zap.String("certPath", certPath))

	// Read the certificate from the provided path
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate from path %s: %w", certPath, err)
	}

	// Parse the PEM encoded certificate
	cert, err := utils.ParsePEMCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse PEM certificate: %w", err)
	}

	// Assuming you have the issuer certificate as well
	_, issuerCert, err := s.CertLoader.LoadCACertificate(s.Cfg.Security.Certificates.CACertPath)
	if err != nil {
		return fmt.Errorf("failed to load issuer certificate: %w", err)
	}

	// Use the OCSPManager to check OCSP status
	_, err = s.OCSPManager.CheckOCSP(cert, issuerCert)
	return err
}

// RevokeCertificates handles certificate revocation checks using CRL.
func (s *Security) RevokeCertificates(ctx context.Context, cert *x509.Certificate) error {
	s.Logger.Info("Revoke certificates using CRL...")
	return s.CRLManager.CheckCRL(cert)
}
