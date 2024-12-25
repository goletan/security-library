package certificates

import (
	"crypto/x509"
	"errors"
	"fmt"
	observability "github.com/goletan/observability-library/pkg"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/goletan/security/config"
	"go.uber.org/zap"
)

type CRLManager struct {
	obs        *observability.Observability
	crlCache   sync.Map
	httpClient *http.Client
	cacheTTL   time.Duration
}

// crlCacheEntry represents an entry in the CRL cache
type crlCacheEntry struct {
	crl    *x509.RevocationList
	expiry time.Time
}

// NewCRLManager initializes a new CRLManager with the given parameters.
func NewCRLManager(cfg *config.SecurityConfig, obs *observability.Observability, httpClient *http.Client) *CRLManager {
	return &CRLManager{
		obs:        obs,
		httpClient: httpClient,
		cacheTTL:   cfg.Security.CRL.TTL,
	}
}

// CheckCRL performs a CRL check to verify the revocation status of the certificate.
func (cm *CRLManager) CheckCRL(cert *x509.Certificate) error {
	for _, url := range cert.CRLDistributionPoints {
		cm.obs.Logger.Info("Checking CRL", zap.String("crlURL", url))

		// Check cache
		crl, found := cm.getCachedCRL(url)
		if !found {
			var err error
			crl, err = cm.fetchCRLWithRetry(url, 3, 2*time.Second) // Use retry logic
			if err != nil {
				cm.obs.Logger.Error("Failed to fetch CRL", zap.String("crlURL", url), zap.Error(err))
				return fmt.Errorf("error fetching CRL: %w", err)
			}
			cm.cacheCRL(url, crl)
		}

		// Check if the certificate is revoked
		if cm.isCertRevoked(crl, cert.SerialNumber) {
			cm.obs.Logger.Warn("Certificate has been revoked", zap.String("crlURL", url), zap.String("serialNumber", cert.SerialNumber.String()))
			return errors.New("certificate has been revoked")
		}
	}
	return nil
}

// fetchCRLWithRetry fetches the CRL from the given URL with retry logic.
func (cm *CRLManager) fetchCRLWithRetry(url string, retries int, backoff time.Duration) (*x509.RevocationList, error) {
	var crl *x509.RevocationList
	var err error

	for attempt := 1; attempt <= retries; attempt++ {
		crl, err = cm.fetchCRL(url)
		if err == nil {
			return crl, nil
		}

		cm.obs.Logger.Warn("Failed to fetch CRL, retrying...", zap.String("crlURL", url), zap.Int("attempt", attempt), zap.Error(err))
		time.Sleep(backoff)
	}

	return nil, fmt.Errorf("failed to fetch CRL after %d retries: %w", retries, err)
}

// fetchCRL fetches the CRL from the given URL.
func (cm *CRLManager) fetchCRL(url string) (*x509.RevocationList, error) {
	resp, err := cm.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error fetching CRL from URL %s: %w", url, err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			cm.obs.Logger.Error("Failed to close CRL response body", zap.Error(err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CRL server returned non-OK status: %v", resp.Status)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading CRL response: %w", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing CRL: %w", err)
	}

	return crl, nil
}

// cacheCRL stores a CRL in the cache.
func (cm *CRLManager) cacheCRL(url string, crl *x509.RevocationList) {
	entry := crlCacheEntry{
		crl:    crl,
		expiry: time.Now().Add(cm.cacheTTL),
	}
	cm.crlCache.Store(url, entry)
	cm.obs.Logger.Info("CRL cached successfully", zap.String("crlURL", url))
}

// getCachedCRL retrieves a cached CRL if it exists and is still valid.
func (cm *CRLManager) getCachedCRL(url string) (*x509.RevocationList, bool) {
	value, exists := cm.crlCache.Load(url)
	if !exists {
		return nil, false
	}

	entry := value.(crlCacheEntry)
	if time.Now().After(entry.expiry) {
		// If the CRL is expired, remove it from the cache
		cm.crlCache.Delete(url)
		cm.obs.Logger.Info("CRL expired and removed from cache", zap.String("crlURL", url))
		return nil, false
	}

	cm.obs.Logger.Info("Using cached CRL", zap.String("crlURL", url))
	return entry.crl, true
}

// isCertRevoked checks if a certificate's serial number is listed in the CRL.
func (cm *CRLManager) isCertRevoked(crl *x509.RevocationList, serialNumber *big.Int) bool {
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}
