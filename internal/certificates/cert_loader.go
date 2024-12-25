package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/goletan/observability-library/pkg"
	"github.com/goletan/security-library/config"
	"github.com/goletan/security-library/internal/utils"
	"go.uber.org/zap"
)

type CertLoader struct {
	cfg *config.SecurityConfig
	obs *observability.Observability
}

// NewCertLoader initializes a new CertLoader with the required configuration and logger-library.
func NewCertLoader(cfg *config.SecurityConfig, obs *observability.Observability) *CertLoader {
	return &CertLoader{
		cfg: cfg,
		obs: obs,
	}
}

// LoadCertificates loads all necessary certificates for the system.
func (cl *CertLoader) LoadCertificates() error {
	cl.obs.Logger.Info("Loading all certificates for the system...")

	// Load the CA Certificate
	_, _, err := cl.LoadCACertificate(cl.cfg.Security.Certificates.CACertPath)
	if err != nil {
		cl.obs.Logger.Error("failed to load CA certificate: %w", zap.Error(err))
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Load the Server Certificate
	_, err = cl.LoadTLSCertificate(cl.cfg.Security.Certificates.ServerCertPath, cl.cfg.Security.Certificates.ServerKeyPath)
	if err != nil {
		cl.obs.Logger.Error("failed to load server certificate and key: %w", zap.Error(err))
		return fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Load the Client Certificate
	_, err = cl.LoadTLSCertificate(cl.cfg.Security.Certificates.ClientCertPath, cl.cfg.Security.Certificates.ClientKeyPath)
	if err != nil {
		cl.obs.Logger.Error("failed to load client certificate and key: %w", zap.Error(err))
		return fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	cl.obs.Logger.Info("All certificates loaded successfully.")
	return nil
}

// LoadTLSCertificate loads a TLS certificate and private key from specified paths with enhanced security-library checks.
func (cl *CertLoader) LoadTLSCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	cl.obs.Logger.Info("Loading certificate and key", zap.String("certPath", certPath), zap.String("keyPath", keyPath))

	if err := cl.checkFilePermissions(certPath); err != nil {
		cl.obs.Logger.Error("certificate file permission check failed: %w", zap.Error(err))
		return nil, fmt.Errorf("certificate file permission check failed: %w", err)
	}
	if err := cl.checkFilePermissions(keyPath); err != nil {
		cl.obs.Logger.Error("key file permission check failed: %w", zap.Error(err))
		return nil, fmt.Errorf("key file permission check failed: %w", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		cl.obs.Logger.Error("error reading certificate file: %w", zap.Error(err))
		return nil, fmt.Errorf("error reading certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		cl.obs.Logger.Error("error reading key file: %w", zap.Error(err))
		return nil, fmt.Errorf("error reading key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		cl.obs.Logger.Error("error loading X509KeyPair: %w", zap.Error(err))
		return nil, fmt.Errorf("error loading X509KeyPair: %w", err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		cl.obs.Logger.Error("error parsing certificate: %w", zap.Error(err))
		return nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	cl.obs.Logger.Info("Certificate and key loaded successfully.")
	return &cert, nil
}

// LoadCACertificate loads the CA certificate from the specified path and returns a certificate pool.
func (cl *CertLoader) LoadCACertificate(caPath string) (*x509.CertPool, *x509.Certificate, error) {
	cl.obs.Logger.Info("Loading CA certificate", zap.String("caPath", caPath))

	if err := cl.checkFilePermissions(caPath); err != nil {
		cl.obs.Logger.Error("CA certificate file permission check failed: %w", zap.Error(err))
		return nil, nil, fmt.Errorf("CA certificate file permission check failed: %w", err)
	}

	caCertPEM, err := os.ReadFile(caPath)
	if err != nil {
		cl.obs.Logger.Error("error reading CA certificate: %w", zap.Error(err))
		return nil, nil, fmt.Errorf("error reading CA certificate: %w", err)
	}

	issuerCert, err := cl.parsePEMCertificate(caCertPEM)
	if err != nil {
		cl.obs.Logger.Error("failed to parse issuer certificate", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		cl.obs.Logger.Error("failed to append CA certificate to pool")
		return nil, nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	cl.obs.Logger.Info("CA certificate loaded and added to pool.")
	return caCertPool, issuerCert, nil
}

// LoadIssuerCertificate loads the CA certificate and returns the specific issuer certificate.
func (cl *CertLoader) LoadIssuerCertificate(caPath string) (*x509.Certificate, error) {
	cl.obs.Logger.Info("Loading issuer certificate", zap.String("caPath", caPath))

	if err := cl.checkFilePermissions(caPath); err != nil {
		cl.obs.Logger.Error("CA certificate file permission check failed: %w", zap.Error(err))
		return nil, fmt.Errorf("CA certificate file permission check failed: %w", err)
	}

	caCertPEM, err := os.ReadFile(caPath)
	if err != nil {
		cl.obs.Logger.Error("error reading CA certificate: %w", zap.Error(err))
		return nil, fmt.Errorf("error reading CA certificate: %w", err)
	}

	issuerCert, err := cl.parsePEMCertificate(caCertPEM)
	if err != nil {
		cl.obs.Logger.Error("failed to parse issuer certificate", zap.Error(err))
		return nil, fmt.Errorf("failed to parse issuer certificate: %w", err)
	}

	cl.obs.Logger.Info("Issuer certificate loaded successfully.")
	return issuerCert, nil
}

// LoadServerTLSConfig loads the server's TLS configuration using paths from the configuration.
func (cl *CertLoader) LoadServerTLSConfig() (*tls.Config, error) {
	cert, err := cl.LoadTLSCertificate(cl.cfg.Security.Certificates.ServerCertPath, cl.cfg.Security.Certificates.ServerKeyPath)
	if err != nil {
		cl.obs.Logger.Error("failed to load server certificate and key: %w", zap.Error(err))
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	caCertPool, _, err := cl.LoadCACertificate(cl.cfg.Security.Certificates.CACertPath)
	if err != nil {
		cl.obs.Logger.Error("error reading CA certificate: %w", zap.Error(err))
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	return cl.setupTLSConfig(cert, caCertPool, tls.RequireAndVerifyClientCert), nil
}

// LoadClientTLSConfig loads the client's TLS configuration using paths from the configuration.
func (cl *CertLoader) LoadClientTLSConfig() (*tls.Config, error) {
	cert, err := cl.LoadTLSCertificate(cl.cfg.Security.Certificates.ClientCertPath, cl.cfg.Security.Certificates.ClientKeyPath)
	if err != nil {
		cl.obs.Logger.Error("failed to load client certificate and key: %w", zap.Error(err))
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	caCertPool, _, err := cl.LoadCACertificate(cl.cfg.Security.Certificates.CACertPath)
	if err != nil {
		cl.obs.Logger.Error("error reading CA certificate: %w", zap.Error(err))
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	return cl.setupTLSConfig(cert, caCertPool, tls.NoClientCert), nil
}

func (cl *CertLoader) setupTLSConfig(cert *tls.Certificate, caCertPool *x509.CertPool, clientAuth tls.ClientAuthType) *tls.Config {
	tlsVersion, err := utils.GetTLSVersion(cl.cfg.Security.Certificates.TLSVersion)
	if err != nil {
		cl.obs.Logger.Warn("Invalid or missing TLS version configuration, defaulting to TLS 1.3")
		tlsVersion = tls.VersionTLS13
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    caCertPool,
		ClientAuth:   clientAuth,
		MinVersion:   tlsVersion,
	}
}

// checkFilePermissions checks that the file has the correct permissions to prevent unauthorized access and is owned by the current user.
func (cl *CertLoader) checkFilePermissions(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cl.obs.Logger.Error("File does not exist", zap.String("filePath", filePath))
			return fmt.Errorf("file does not exist: %w", err)
		}
		cl.obs.Logger.Error("Unable to access file", zap.String("filePath", filePath), zap.Error(err))
		return fmt.Errorf("unable to access file: %w", err)
	}

	// Check file permissions (must not be accessible by group or others)
	if info.Mode().Perm()&(syscall.S_IRWXG|syscall.S_IRWXO) != 0 {
		cl.obs.Logger.Error("File has too permissive permissions", zap.String("filePath", filePath), zap.Uint32("permissions", uint32(info.Mode().Perm())))
		return fmt.Errorf("file %s has too permissive permissions", filePath)
	}

	// Explicitly check for secure permissions (600 or 400)
	if info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
		cl.obs.Logger.Error("File has invalid permissions", zap.String("filePath", filePath), zap.Uint32("permissions", uint32(info.Mode().Perm())), zap.Uint32s("expectedPermissions", []uint32{0600, 0400}))
		return fmt.Errorf("file %s has invalid permissions: %o, expected 600 or 400", filePath, info.Mode().Perm())
	}

	return nil
}

func (cl *CertLoader) parsePEMCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		cl.obs.Logger.Error("failed to decode PEM block containing certificate")
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		cl.obs.Logger.Error("failed to parse certificate: %w", zap.Error(err))
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
