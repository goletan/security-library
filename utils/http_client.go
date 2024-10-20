// /security/utils/http_client.go
package security

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/goletan/config"
)

// Shared HTTP client with configuration for graceful shutdown
var httpClient *http.Client

// InitializeHTTPClient configures the shared HTTP client with enhanced security settings.
func InitializeHTTPClient() error {
	// Fetch configuration values with safe defaults
	timeout := time.Duration(config.GlobalConfig.Security.HTTPClient.Timeout) * time.Second
	if timeout == 0 {
		log.Println("Invalid or missing timeout configuration, defaulting to 10 seconds")
		timeout = 10 * time.Second
	}

	// Fetch TLS version from configuration
	tlsVersion, err := getTLSVersion(config.GlobalConfig.Security.HTTPClient.TLSVersion)
	if err != nil {
		log.Printf("Invalid or missing TLS version configuration, defaulting to TLS 1.3")
		tlsVersion = tls.VersionTLS13
	}

	transport := &http.Transport{
		IdleConnTimeout:       10 * time.Second,
		MaxIdleConnsPerHost:   config.GlobalConfig.Security.HTTPClient.MaxIdleConnectionsPerHost,
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
	httpClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}

	log.Println("HTTP client initialized with secure settings from configuration.")
	return nil
}

// ShutdownHTTPClient gracefully closes idle connections of the shared HTTP client.
func ShutdownHTTPClient() error {
	if httpClient == nil {
		log.Println("HTTP client is not initialized, skipping shutdown.")
		return nil
	}

	if transport, ok := httpClient.Transport.(*http.Transport); ok {
		log.Println("Shutting down HTTP client gracefully...")
		transport.CloseIdleConnections()
	} else {
		return fmt.Errorf("failed to access the transport layer for shutdown")
	}

	return nil
}

// Helper function to get TLS version from string
func getTLSVersion(version string) (uint16, error) {
	switch version {
	case "TLS13":
		return tls.VersionTLS13, nil
	case "TLS12":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}
