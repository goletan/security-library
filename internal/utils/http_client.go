package utils

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/goletan/security/config"
)

// InitializeHTTPClient configures the HTTP client with enhanced security-library settings.
func InitializeHTTPClient(cfg *config.SecurityConfig) (*http.Client, error) {
	// Fetch TLS version from configuration
	tlsVersion, err := GetTLSVersion(cfg.Security.HTTPClient.TLSVersion)
	if err != nil {
		fmt.Printf("Invalid or missing TLS version configuration, defaulting to TLS 1.3\n")
		tlsVersion = tls.VersionTLS13
	}

	transport := &http.Transport{
		IdleConnTimeout:       10 * time.Second,
		MaxIdleConnsPerHost:   cfg.Security.HTTPClient.MaxIdleConnectionsPerHost,
		MaxConnsPerHost:       100,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tlsVersion,
		},
	}

	// Initialize the HTTP client with timeout and transport settings
	httpClient := &http.Client{
		Timeout:   cfg.Security.HTTPClient.Timeout,
		Transport: transport,
	}

	fmt.Println("HTTP client initialized with secure settings from configuration.")
	return httpClient, nil
}
