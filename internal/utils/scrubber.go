// /observability/utils/scrubber.go
package utils

import (
	"fmt"
	"regexp"
	"sync"
)

// Scrubber holds patterns and logic to clean sensitive data.
type Scrubber struct {
	patterns []*regexp.Regexp
	mu       sync.RWMutex
}

// NewScrubber creates a new Scrubber with default sensitive patterns.
func NewScrubber() *Scrubber {
	return &Scrubber{
		patterns: getDefaultPatterns(),
	}
}

// getDefaultPatterns returns the default set of sensitive data patterns.
func getDefaultPatterns() []*regexp.Regexp {

	return []*regexp.Regexp{
		// Sensitive URL segments
		regexp.MustCompile(`(?i)(\/(user|session|auth|token|private|login|logout|register))([\/\w\-%]*)?`),
		// Capture key-value pairs with flexible separators, including embedded sensitive terms.
		regexp.MustCompile(`(?i)(\w*(password|secret|token|apikey|sessionid|key|passphrase|pin|auth|passkeys|log)\w*)\s*[:=]?\s*['"]?([^\s,'"]+)['"]?`),
		// Broaden keyword matching for embedded contexts of sensitive terms.
		regexp.MustCompile(`(?i)(password|secret|token|key|session|auth|passkeys|log)\w*`),
		// Credit card numbers and other card-like patterns
		regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		// IP Addresses
		regexp.MustCompile(`\b((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\b`),
		// Email addresses
		regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
		// UUIDs
		regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`),
		// JWT tokens (base64url format without padding)
		regexp.MustCompile(`(?i)\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b`),
		// Database connection strings (generic)
		regexp.MustCompile(`(?i)(?i)(user|username|password|host|port|database|dbname|db|uri|url|log)=([^;]+)`),
		// Common secret patterns in headers and URLs (like Bearer tokens)
		regexp.MustCompile(`(?i)(bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)`),
		// Social Security Numbers (SSN)
		regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		// Generic hexadecimal keys (API keys, secrets)
		regexp.MustCompile(`(?i)(api|secret|key|token|signature)[\s:=]+[a-fA-F0-9]{32,64}`),
	}
}

// AddPattern adds a new regex pattern for scrubbing sensitive data.
func (s *Scrubber) AddPattern(pattern string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	compiledPattern, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile pattern: %w", err)
	}
	s.patterns = append(s.patterns, compiledPattern)
	return nil
}

// RemovePattern removes a pattern from the scrubber.
func (s *Scrubber) RemovePattern(pattern string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, p := range s.patterns {
		if p.String() == pattern {
			s.patterns = append(s.patterns[:i], s.patterns[i+1:]...)
			break
		}
	}
}

// Scrub sanitizes the input data string by masking sensitive information.
func (s *Scrubber) Scrub(data string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, pattern := range s.patterns {
		data = pattern.ReplaceAllString(data, "[REDACTED]")
	}
	return data
}

// ScrubMap scrubs sensitive data in a map of string keys and values.
func (s *Scrubber) ScrubMap(data map[string]interface{}) map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	scrubbed := make(map[string]interface{})
	for k, v := range data {
		if str, ok := v.(string); ok {
			scrubbed[k] = s.Scrub(str)
		} else {
			scrubbed[k] = v
		}
	}
	return scrubbed
}
