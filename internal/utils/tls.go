package utils

import (
	"crypto/tls"
	"fmt"
)

// GetTLSVersion takes a string representing the TLS version and returns the appropriate uint16 value.
// Supported values are "TLS10", "TLS11", "TLS12", and "TLS13".
func GetTLSVersion(version string) (uint16, error) {
	switch version {
	case "TLS10":
		return tls.VersionTLS10, nil
	case "TLS11":
		return tls.VersionTLS11, nil
	case "TLS12":
		return tls.VersionTLS12, nil
	case "TLS13":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}
