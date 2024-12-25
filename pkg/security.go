package security

import (
	"crypto/x509"
	"fmt"
	"os"

	"github.com/goletan/observability-library/pkg"
	"github.com/goletan/security-library/config"
	"github.com/goletan/security-library/internal/certificates"
	"github.com/goletan/security-library/internal/mtls"
	"github.com/goletan/security-library/internal/utils"
	"go.uber.org/zap"
)

// Security is a struct that centralizes security-library-related functionalities and dependencies for a software application.
type Security struct {
	Cfg           *config.SecurityConfig
	CertLoader    *certificates.CertLoader
	CertValidator *certificates.CertValidator
	CRLManager    *certificates.CRLManager
	OCSPManager   *certificates.OCSPManager
	MTLSHandler   *mtls.MTLS
	Observability *observability.Observability
}

// NewSecurity initializes a new Security instance.
func NewSecurity(cfg *config.SecurityConfig, obs *observability.Observability) (*Security, error) {
	// Initialize shared HTTP client
	httpClient, err := utils.InitializeHTTPClient(cfg)
	if err != nil {
		obs.Logger.Fatal("Failed to initialize HTTP client", zap.Error(err))
		return nil, err
	}

	// Initialize certificate components
	certLoader := certificates.NewCertLoader(cfg, obs)
	certValidator := certificates.NewCertValidator(cfg, obs, httpClient)
	crlManager := certificates.NewCRLManager(cfg, obs, httpClient)
	ocspManager := certificates.NewOCSPManager(cfg, obs, httpClient, certificates.RealOCSPRequest)

	// Initialize mTLS component
	mtlsHandler := mtls.NewMTLS(cfg, obs, certLoader, certValidator)

	// Create Security instance
	security := &Security{
		Cfg:           cfg,
		CertLoader:    certLoader,
		CertValidator: certValidator,
		CRLManager:    crlManager,
		OCSPManager:   ocspManager,
		MTLSHandler:   mtlsHandler,
		Observability: obs,
	}

	// Perform initial setup if needed (e.g., load certificates)
	if err := security.LoadCertificates(); err != nil {
		return nil, fmt.Errorf("failed to load certificates: %w", err)
	}

	return security, nil
}

// SetupMTLS sets up mTLS for secure communication.
func (s *Security) SetupMTLS() error {
	s.Observability.Logger.Info("Setting up mTLS...")
	_, err := s.MTLSHandler.ConfigureMTLS()
	return err
}

// LoadCertificates loads all necessary certificates for the system.
func (s *Security) LoadCertificates() error {
	s.Observability.Logger.Info("Loading certificates...")
	return s.CertLoader.LoadCertificates()
}

// ValidateCertificate validates a given certificate.
func (s *Security) ValidateCertificate(certPath string) error {
	s.Observability.Logger.Info("Validating certificate...", zap.String("certPath", certPath))
	return s.CertValidator.ValidateCertificate(certPath)
}

// CheckOCSPStatus checks the OCSP status of a certificate.
func (s *Security) CheckOCSPStatus(certPath string) error {
	s.Observability.Logger.Info("Checking OCSP status...", zap.String("certPath", certPath))

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
func (s *Security) RevokeCertificates(cert *x509.Certificate) error {
	s.Observability.Logger.Info("Revoke certificates using CRL...")
	return s.CRLManager.CheckCRL(cert)
}
