package certificates

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	observability "github.com/goletan/observability/pkg"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/goletan/security/config"
	"github.com/goletan/security/internal/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

type CertValidator struct {
	obs         *observability.Observability
	crlCache    map[string]*x509.RevocationList
	cacheMutex  sync.Mutex
	httpClient  *http.Client
	retryPolicy RetryPolicy
}

type RetryPolicy struct {
	MaxRetries int
	Backoff    time.Duration
	Jitter     time.Duration
}

// NewCertValidator initializes a new CertValidator with the provided logger and HTTP client.
func NewCertValidator(cfg *config.SecurityConfig, obs *observability.Observability, httpClient *http.Client) *CertValidator {
	return &CertValidator{
		obs:         obs,
		crlCache:    make(map[string]*x509.RevocationList),
		httpClient:  httpClient,
		retryPolicy: RetryPolicy(cfg.Security.Certificates.RetryPolicy),
	}
}

// ValidateCertificate validates the provided certificate file using OCSP and CRL checks.
func (cv *CertValidator) ValidateCertificate(certPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	cert, err := utils.ParsePEMCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse PEM certificate: %w", err)
	}

	// Check OCSP status
	if err := cv.verifyOCSP(cert, nil); err != nil {
		return fmt.Errorf("failed OCSP validation: %w", err)
	}

	// Check CRL status
	if err := cv.verifyCRL(cert); err != nil {
		return fmt.Errorf("failed CRL validation: %w", err)
	}

	cv.obs.Logger.Info("Certificate validation passed", zap.String("subjectCN", cert.Subject.CommonName))
	return nil
}

// VerifyPeerCertificate performs OCSP and CRL checks on the peer certificate to ensure it has not been revoked.
func (cv *CertValidator) VerifyPeerCertificate(verifiedChains [][]*x509.Certificate) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(verifiedChains))

	for _, chain := range verifiedChains {
		// Run checks concurrently to improve performance
		wg.Add(1)
		go func(chain []*x509.Certificate) {
			defer wg.Done()
			if len(chain) < 2 {
				errChan <- fmt.Errorf("invalid certificate chain: expected at least two certificates (target and issuer)")
				return
			}
			targetCert := chain[0]
			issuerCert := chain[1]

			if err := cv.verifyOCSP(targetCert, issuerCert); err != nil {
				errChan <- fmt.Errorf("OCSP check failed: %w", err)
				return
			}
			if err := cv.verifyCRL(targetCert); err != nil {
				errChan <- fmt.Errorf("CRL check failed: %w", err)
			}
		}(chain)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}
	return nil
}

// verifyOCSP performs an OCSP check using retry logic to verify the revocation status of a certificate.
func (cv *CertValidator) verifyOCSP(cert *x509.Certificate, issuer *x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		return errors.New("no OCSP server specified in certificate")
	}

	ocspURL := cert.OCSPServer[0]
	var resp *http.Response
	var err error

	for attempt := 1; attempt <= cv.retryPolicy.MaxRetries; attempt++ {
		resp, err = cv.sendOCSPRequest(ocspURL, cert, issuer)
		if err == nil {
			break
		}
		cv.obs.Logger.Warn("OCSP request failed, retrying...", zap.String("ocspURL", ocspURL), zap.Int("attempt", attempt), zap.Error(err))
		time.Sleep(cv.retryPolicy.Backoff + time.Duration(attempt)*cv.retryPolicy.Jitter)
	}

	if err != nil {
		return fmt.Errorf("OCSP check failed after retries: %w", err)
	}

	if resp != nil {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				cv.obs.Logger.Error("Error closing OCSP response body", zap.Error(err))
			}
		}(resp.Body)

		ocspBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read OCSP response: %w", err)
		}

		ocspResponse, err := ocsp.ParseResponse(ocspBytes, issuer)
		if err != nil {
			return fmt.Errorf("failed to parse OCSP response: %w", err)
		}

		if ocspResponse.Status == ocsp.Revoked {
			return fmt.Errorf("certificate is revoked: OCSP status revoked")
		}
	}
	return nil
}

// sendOCSPRequest sends an OCSP request and handles the response.
func (cv *CertValidator) sendOCSPRequest(ocspURL string, cert, issuer *x509.Certificate) (*http.Response, error) {
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}
	req, err := http.NewRequest("POST", ocspURL, bytes.NewReader(ocspRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")

	return cv.httpClient.Do(req)
}

// verifyCRL checks the revocation status of a certificate using CRL.
func (cv *CertValidator) verifyCRL(cert *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return errors.New("no CRL distribution points specified in certificate")
	}

	for _, crlURL := range cert.CRLDistributionPoints {
		crl, err := cv.getCRL(crlURL)
		if err != nil {
			cv.obs.Logger.Warn("Failed to get CRL", zap.String("crlURL", crlURL), zap.Error(err))
			continue
		}

		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate is revoked: serial number %s", cert.SerialNumber.String())
			}
		}
	}

	return nil
}

// checkOCSP performs an OCSP check to verify the revocation status of a certificate.
func (cv *CertValidator) checkOCSP(cert *x509.Certificate, issuer *x509.Certificate) (*ocsp.Response, error) {
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
	cv.obs.Logger.Info("Attempting OCSP check with server URL", zap.String("ocspURL", ocspURL))

	// Attempt to send the OCSP request to the server
	resp, err := http.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspRequest))
	if err != nil {
		cv.obs.Logger.Error("Error contacting OCSP server", zap.Error(err))
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			cv.obs.Logger.Error("Error closing OCSP response body", zap.Error(err))
		}
	}(resp.Body)

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

// checkCRL checks the CRL status of a certificate. Currently, this is a placeholder for CRL validation logic.
func (cv *CertValidator) checkCRL(cert *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return errors.New("no CRL distribution points specified in certificate")
	}

	// Iterate over CRL distribution points to find and validate the CRL.
	for _, crlURL := range cert.CRLDistributionPoints {
		cv.obs.Logger.Info("Attempting CRL check", zap.String("crlURL", crlURL))

		// Attempt to fetch or use the cached CRL
		crl, err := cv.getCRL(crlURL)
		if err != nil {
			cv.obs.Logger.Warn("Failed to get CRL", zap.String("crlURL", crlURL), zap.Error(err))
			continue
		}

		// Check if the certificate is in the CRL
		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				cv.obs.Logger.Warn("Certificate is revoked according to CRL", zap.String("crlURL", crlURL))
				return fmt.Errorf("certificate is revoked: serial number %s", cert.SerialNumber.String())
			}
		}
	}

	cv.obs.Logger.Info("CRL check passed, certificate not revoked")
	return nil
}

// getCRL fetches the CRL from the given URL or retrieves it from the cache if available.
func (cv *CertValidator) getCRL(crlURL string) (*x509.RevocationList, error) {
	cv.cacheMutex.Lock()
	defer cv.cacheMutex.Unlock()

	// Check if the CRL is already cached
	if cachedCRL, exists := cv.crlCache[crlURL]; exists {
		cv.obs.Logger.Info("Using cached CRL", zap.String("crlURL", crlURL))
		return cachedCRL, nil
	}

	// Fetch the CRL from the specified URL
	resp, err := http.Get(crlURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from URL %s: %w", crlURL, err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			cv.obs.Logger.Error("Error closing CRL response body", zap.Error(err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned non-OK status: %v", resp.Status)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL: %w", err)
	}

	// Parse the CRL using the new ParseRevocationList method
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	// Cache the CRL with a short lifespan for efficient reuse (e.g., 1 hour)
	crl.NextUpdate = time.Now().Add(1 * time.Hour)
	cv.crlCache[crlURL] = crl

	cv.obs.Logger.Info("Fetched and cached CRL", zap.String("crlURL", crlURL))
	return crl, nil
}
