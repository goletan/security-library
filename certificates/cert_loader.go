// /security/certificates/cert_loader.go
package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/goletan/config"
	"github.com/goletan/security/types"
)

var cfg types.SecurityConfig

func init() {
	configPathsEnv := os.Getenv("SECURITY_CONFIG_PATHS")
	var configPaths []string
	if configPathsEnv != "" {
		configPaths = strings.Split(configPathsEnv, ",")
	} else {
		configPaths = []string{"."}
	}

	// Load the configuration
	err := config.LoadConfig("security", configPaths, &cfg, nil)
	if err != nil {
		log.Fatalf("Failed to load security config: %v", err)
	}
}

// LoadTLSCertificate loads a TLS certificate and private key from specified paths with enhanced security checks.
func LoadTLSCertificate(certPath, keyPath string) (tls.Certificate, error) {
	log.Printf("Loading certificate and key from paths: %s, %s", certPath, keyPath)

	if err := checkFilePermissions(certPath); err != nil {
		return tls.Certificate{}, fmt.Errorf("certificate file permission check failed: %w", err)
	}
	if err := checkFilePermissions(keyPath); err != nil {
		return tls.Certificate{}, fmt.Errorf("key file permission check failed: %w", err)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error reading certificate file: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error reading key file: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error loading X509KeyPair: %w", err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("error parsing certificate: %w", err)
	}

	log.Println("Certificate and key loaded successfully.")
	return cert, nil
}

// LoadCACertificate loads the CA certificate from the specified path and returns a certificate pool.
func LoadCACertificate(caPath string) (*x509.CertPool, error) {
	log.Printf("Loading CA certificate from path: %s", caPath)

	if err := checkFilePermissions(caPath); err != nil {
		return nil, fmt.Errorf("CA certificate file permission check failed: %w", err)
	}

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("error reading CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	log.Println("CA certificate loaded and added to pool.")
	return caCertPool, nil
}

// LoadServerTLSConfig loads the server's TLS configuration using paths from the configuration.
func LoadServerTLSConfig() (*tls.Config, error) {
	certs := cfg.Security.Certificates

	cert, err := LoadTLSCertificate(certs.ServerCertPath, certs.ServerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	caCertPool, err := LoadCACertificate(certs.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
		MinVersion:   tls.VersionTLS13,
	}

	return tlsConfig, nil
}

// LoadClientTLSConfig loads the client's TLS configuration using paths from the configuration.
func LoadClientTLSConfig() (*tls.Config, error) {
	certs := cfg.Security.Certificates

	cert, err := LoadTLSCertificate(certs.ClientCertPath, certs.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	caCertPool, err := LoadCACertificate(certs.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false, // Verify server certificate
		MinVersion:         tls.VersionTLS13,
	}

	return tlsConfig, nil
}

// checkFilePermissions checks that the file has the correct permissions to prevent unauthorized access and is owned by the current user.
func checkFilePermissions(filePath string) error {
	info, err := os.Stat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err != nil {
		return fmt.Errorf("unable to access file: %w", err)
	}

	// Check file permissions (must not be accessible by group or others)
	if info.Mode().Perm()&(syscall.S_IRWXG|syscall.S_IRWXO) != 0 {
		return fmt.Errorf("file %s has too permissive permissions", filePath)
	}

	// Explicitly check for secure permissions (600 or 400)
	if info.Mode().Perm() != 0600 && info.Mode().Perm() != 0400 {
		return fmt.Errorf("file %s has invalid permissions: %o, expected 600 or 400", filePath, info.Mode().Perm())
	}

	return nil
}
