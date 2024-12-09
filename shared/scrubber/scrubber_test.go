package scrubber

import (
	"testing"
)

func TestScrubber_ScrubSensitiveData(t *testing.T) {
	scrubber := NewScrubber()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Scrub Email Addresses",
			input:    "My email is john.doe@example.com",
			expected: "My email is [REDACTED]",
		},
		{
			name:     "Scrub Credit Card Numbers with Dashes",
			input:    "My card number is 1234-5678-9012-3456",
			expected: "My card number is [REDACTED]",
		},
		{
			name:     "Scrub Credit Card Numbers with Spaces",
			input:    "My card number is 1234 5678 9012 3456",
			expected: "My card number is [REDACTED]",
		},
		{
			name:     "Scrub Sensitive Key-Value Pair (Password)",
			input:    "password=mysecret",
			expected: "[REDACTED]",
		},
		{
			name:     "Scrub Sensitive Key-Value Pair (Secret)",
			input:    "secret=topsecretinfo",
			expected: "[REDACTED]",
		},
		{
			name:     "Scrub UUID",
			input:    "This UUID is 123e4567-e89b-12d3-a456-426614174000",
			expected: "This UUID is [REDACTED]",
		},
		{
			name:     "Scrub IP Address",
			input:    "Connect to 192.168.1.1",
			expected: "Connect to [REDACTED]",
		},
		{
			name:     "Scrub API Key",
			input:    "apikey=1234567890abcdef",
			expected: "[REDACTED]",
		},
		{
			name:     "Scrub Session ID",
			input:    "sessionid=abc123",
			expected: "[REDACTED]",
		},
		{
			name:     "Scrub Generic Token",
			input:    "token=secret_token_value",
			expected: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scrubber.Scrub(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestScrubberPatterns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Scrub URL /user", "/user", "[REDACTED]"},
		{"Scrub URL /token", "/token", "[REDACTED]"},
		{"Scrub password", "password=1234", "[REDACTED]"},
		{"Scrub email", "myemail@example.com", "[REDACTED]"},
		{"Scrub credit card", "1234-5678-9012-3456", "[REDACTED]"},
		{"Scrub IP address", "Connect to 192.168.1.1", "Connect to [REDACTED]"},
	}

	scrubber := NewScrubber()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := scrubber.Scrub(tt.input)
			if output != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, output)
			}
		})
	}
}
