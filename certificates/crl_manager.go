// /security/certificates/crl_manager.go
package certificates

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

// Cache structures for CRL responses
type crlCacheEntry struct {
	crl    *x509.RevocationList
	expiry time.Time
}

var (
	crlCache  = make(map[string]crlCacheEntry)
	cacheLock = sync.Mutex{}
)

// CheckCRL performs a CRL check to verify the revocation status of the certificate.
func CheckCRL(cert *x509.Certificate) error {
	for _, url := range cert.CRLDistributionPoints {
		// Check cache first with read lock
		cacheLock.Lock()
		cachedCRL, found := crlCache[url]
		cacheLock.Unlock()

		// Lazy cleanup of expired entries
		if found && time.Now().After(cachedCRL.expiry) {
			cacheLock.Lock()
			delete(crlCache, url)
			cacheLock.Unlock()
			found = false
		}

		// Use cached CRL if available and valid
		if found {
			if isCertRevoked(cachedCRL.crl, cert.SerialNumber) {
				return errors.New("certificate has been revoked")
			}
			continue
		}

		// Fetch CRL using HTTP client
		resp, err := httpClient.Get(url)
		if err != nil {
			return fmt.Errorf("error fetching CRL: %w", err)
		}
		defer resp.Body.Close()

		crlBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("error reading CRL response: %w", err)
		}

		crl, err := x509.ParseRevocationList(crlBytes)
		if err != nil {
			return fmt.Errorf("error parsing CRL: %w", err)
		}

		// Cache the CRL with write lock
		CacheCRLResponse(url, crl)

		// Check if the certificate is revoked
		if isCertRevoked(crl, cert.SerialNumber) {
			return errors.New("certificate has been revoked")
		}
	}
	return nil
}

// CacheCRLResponse stores a CRL in the cache
func CacheCRLResponse(url string, crl *x509.RevocationList) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	crlCache[url] = crlCacheEntry{
		crl:    crl,
		expiry: time.Now().Add(cacheTTL),
	}
}

// GetCachedCRLResponse retrieves a cached CRL if it exists and is still valid
func GetCachedCRLResponse(url string) (*x509.RevocationList, bool) {
	cacheLock.Lock()
	defer cacheLock.Unlock()
	entry, exists := crlCache[url]
	if !exists || time.Now().After(entry.expiry) {
		return nil, false
	}
	return entry.crl, true
}

// isCertRevoked checks if a certificate's serial number is listed in the CRL
func isCertRevoked(crl *x509.RevocationList, serialNumber *big.Int) bool {
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(serialNumber) == 0 {
			return true
		}
	}
	return false
}
