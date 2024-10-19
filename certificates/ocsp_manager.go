// /security/certificates/ocsp_manager.go
package certificates

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// Cache structures for OCSP responses
type ocspCacheEntry struct {
	response *ocsp.Response
	expiry   time.Time
}

// OCSPManager handles OCSP requests and caching.
type OCSPManager struct {
	CacheTTL        time.Duration
	HTTPClient      *http.Client
	OCSPRequestFunc func(string, string, io.Reader) (*http.Response, error)
	cache           map[string]ocspCacheEntry
	cacheLock       sync.Mutex
}

var (
	ocspCache = sync.Map{} // Use sync.Map for concurrent access
	cacheTTL  = 24 * time.Hour
)

// NewOCSPManager initializes an OCSP manager with the given configuration.
func NewOCSPManager(httpClient *http.Client, ocspRequestFunc func(string, string, io.Reader) (*http.Response, error), cacheTTL time.Duration) *OCSPManager {
	return &OCSPManager{
		CacheTTL:        cacheTTL,
		HTTPClient:      httpClient,
		OCSPRequestFunc: ocspRequestFunc,
		cache:           make(map[string]ocspCacheEntry),
	}
}

// CheckOCSP performs an OCSP check using the issuer's certificate to validate the revocation status.
func (o *OCSPManager) CheckOCSP(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	log.Printf("Checking OCSP for certificate with CN: %s", cert.Subject.CommonName)
	log.Printf("Issuer CN: %s", issuer.Subject.CommonName)

	// Verify that the OCSP server is specified
	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("no OCSP server specified in certificate")
	}

	// Attempt to create an OCSP request
	ocspRequest, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		log.Printf("Error creating OCSP request: %v", err)
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Send the OCSP request using the configured function
	httpResp, err := o.OCSPRequestFunc(cert.OCSPServer[0], "application/ocsp-request", strings.NewReader(string(ocspRequest)))
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer httpResp.Body.Close()

	ocspBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(ocspBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	o.CacheOCSPResponse(cert, ocspResp)
	return ocspResp, nil
}

// CacheOCSPResponse stores an OCSP response in cache.
func (o *OCSPManager) CacheOCSPResponse(cert *x509.Certificate, ocspResp *ocsp.Response) {
	o.cacheLock.Lock()
	defer o.cacheLock.Unlock()
	o.cache[cert.SerialNumber.String()] = ocspCacheEntry{
		response: ocspResp,
		expiry:   time.Now().Add(o.CacheTTL),
	}
}

// GetCachedOCSPResponse retrieves a cached OCSP response if it exists and is still valid.
func (o *OCSPManager) GetCachedOCSPResponse(cert *x509.Certificate) (*ocsp.Response, bool) {
	o.cacheLock.Lock()
	defer o.cacheLock.Unlock()
	entry, exists := o.cache[cert.SerialNumber.String()]
	if !exists || time.Now().After(entry.expiry) {
		return nil, false
	}
	return entry.response, true
}

// sendOCSPRequest sends an OCSP request and handles the response.
func sendOCSPRequest(url string, request []byte, issuer *x509.Certificate) (*ocsp.Response, error) {
	log.Printf("Sending OCSP request to %s", url)
	httpResp, err := httpClient.Post(url, "application/ocsp-request", strings.NewReader(string(request)))
	if err != nil {
		return nil, fmt.Errorf("failed to send OCSP request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("OCSP server returned non-200 status: %d", httpResp.StatusCode)
	}

	ocspBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(ocspBytes, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP response: %w", err)
	}

	if ocspResp.Status == ocsp.Revoked {
		log.Printf("OCSP status: certificate revoked")
		return ocspResp, errors.New("certificate revoked")
	}

	return ocspResp, nil
}

// CacheOCSPResponse stores an OCSP response in cache
func CacheOCSPResponse(cert *x509.Certificate, ocspResp *ocsp.Response) {
	log.Printf("Caching OCSP response for certificate: %s", cert.SerialNumber)
	ocspCache.Store(cert.SerialNumber.String(), ocspCacheEntry{
		response: ocspResp,
		expiry:   time.Now().Add(cacheTTL),
	})
}

// GetCachedOCSPResponse retrieves a cached OCSP response if it exists and is still valid
func GetCachedOCSPResponse(cert *x509.Certificate) (*ocsp.Response, bool) {
	entry, exists := ocspCache.Load(cert.SerialNumber.String())
	if !exists {
		return nil, false
	}

	cacheEntry := entry.(ocspCacheEntry)
	if time.Now().After(cacheEntry.expiry) {
		ocspCache.Delete(cert.SerialNumber.String())
		return nil, false
	}

	return cacheEntry.response, true
}
