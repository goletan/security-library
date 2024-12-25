package certificates

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/goletan/observability-library/pkg"
	"github.com/goletan/security-library/config"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
)

// OCSPCacheEntry represents an entry in the OCSP cache
type OCSPCacheEntry struct {
	response *ocsp.Response
	expiry   time.Time
}

// OCSPManager handles OCSP requests and caching.
type OCSPManager struct {
	CacheTTL        time.Duration
	HTTPClient      *http.Client
	OCSPRequestFunc func(*http.Client, string, string, io.Reader) (*http.Response, error)
	obs             *observability.Observability
	cache           sync.Map // Use sync.Map for concurrent access
}

// NewOCSPManager initializes an OCSP manager with the given configuration.
func NewOCSPManager(cfg *config.SecurityConfig, obs *observability.Observability, httpClient *http.Client, ocspRequestFunc func(*http.Client, string, string, io.Reader) (*http.Response, error)) *OCSPManager {
	return &OCSPManager{
		CacheTTL:        cfg.Security.OCSP.TTL,
		HTTPClient:      httpClient,
		OCSPRequestFunc: ocspRequestFunc,
		obs:             obs,
	}
}

// CheckOCSP performs an OCSP check using the issuer's certificate to validate the revocation status.
func (o *OCSPManager) CheckOCSP(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	o.obs.Logger.Info("Checking OCSP for certificate", zap.String("CN", cert.Subject.CommonName))

	// Check if the OCSP response is already cached
	if cachedResponse, found := o.GetCachedOCSPResponse(cert); found {
		o.obs.Logger.Info("Using cached OCSP response", zap.String("serialNumber", cert.SerialNumber.String()))
		return cachedResponse, nil
	}

	// Verify that the OCSP server is specified
	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("no OCSP server specified in certificate")
	}

	// Attempt to create an OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		o.obs.Logger.Error("Error creating OCSP request", zap.Error(err))
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Send the OCSP request with retry logic
	ocspURL := cert.OCSPServer[0]
	ocspResp, err := o.sendOCSPRequestWithRetry(ocspURL, ocspRequest, 3, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}

	// Cache the OCSP response
	o.CacheOCSPResponse(cert, ocspResp)
	return ocspResp, nil
}

// sendOCSPRequestWithRetry sends an OCSP request with retry logic.
func (o *OCSPManager) sendOCSPRequestWithRetry(ocspURL string, request []byte, retries int, backoff time.Duration) (*ocsp.Response, error) {
	var ocspResp *ocsp.Response
	var err error

	for attempt := 1; attempt <= retries; attempt++ {
		o.obs.Logger.Info("Sending OCSP request", zap.String("ocspURL", ocspURL), zap.Int("attempt", attempt))

		httpResp, err := o.OCSPRequestFunc(o.HTTPClient, ocspURL, "application/ocsp-request", bytes.NewReader(request))
		if err != nil {
			o.obs.Logger.Warn("Failed to send OCSP request, retrying...", zap.String("ocspURL", ocspURL), zap.Int("attempt", attempt), zap.Error(err))
			time.Sleep(backoff)
			continue
		}

		ocspResp, err = o.handleOCSPResponse(httpResp)
		if err == nil {
			return ocspResp, nil // Successfully processed OCSP response
		}

		o.obs.Logger.Warn("Encountered error while processing OCSP response, retrying...", zap.String("ocspURL", ocspURL), zap.Int("attempt", attempt), zap.Error(err))
		time.Sleep(backoff)
	}

	return nil, fmt.Errorf("failed to send OCSP request after %d retries: %w", retries, err)
}

// handleOCSPResponse processes the HTTP response and closes the body safely.
func (o *OCSPManager) handleOCSPResponse(httpResp *http.Response) (*ocsp.Response, error) {
	defer func() {
		if err := httpResp.Body.Close(); err != nil {
			o.obs.Logger.Error("Failed to close OCSP response body", zap.Error(err))
		}
	}()

	ocspBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		o.obs.Logger.Error("Failed to read OCSP response", zap.Error(err))
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(ocspBytes, nil)
	if err != nil {
		o.obs.Logger.Error("Failed to parse OCSP response", zap.Error(err))
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	if ocspResp.Status == ocsp.Revoked {
		o.obs.Logger.Warn("Certificate is revoked according to OCSP", zap.String("ocspURL", httpResp.Request.URL.String()))
		return ocspResp, errors.New("certificate is revoked")
	}

	return ocspResp, nil
}

// CacheOCSPResponse stores an OCSP response in cache.
func (o *OCSPManager) CacheOCSPResponse(cert *x509.Certificate, ocspResp *ocsp.Response) {
	entry := OCSPCacheEntry{
		response: ocspResp,
		expiry:   time.Now().Add(o.CacheTTL),
	}
	o.cache.Store(cert.SerialNumber.String(), entry)
	o.obs.Logger.Info("OCSP response cached successfully", zap.String("serialNumber", cert.SerialNumber.String()))
}

// GetCachedOCSPResponse retrieves a cached OCSP response if it exists and is still valid.
func (o *OCSPManager) GetCachedOCSPResponse(cert *x509.Certificate) (*ocsp.Response, bool) {
	value, exists := o.cache.Load(cert.SerialNumber.String())
	if !exists {
		return nil, false
	}

	entry := value.(OCSPCacheEntry)
	if time.Now().After(entry.expiry) {
		// If the OCSP response is expired, remove it from the cache
		o.cache.Delete(cert.SerialNumber.String())
		o.obs.Logger.Info("OCSP response expired and removed from cache", zap.String("serialNumber", cert.SerialNumber.String()))
		return nil, false
	}

	return entry.response, true
}

// RealOCSPRequest sends an OCSP request to the specified OCSP server.
func RealOCSPRequest(client *http.Client, ocspURL string, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", ocspURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request to %s: %w", ocspURL, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCSP server returned non-OK status: %v", resp.Status)
	}

	return resp, nil
}
