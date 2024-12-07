package config

import "time"

type SecurityConfig struct {
	Security struct {
		Certificates struct {
			TLSVersion     string `mapstructure:"tls_version"`
			CACertPath     string `mapstructure:"ca_cert_path"`
			ServerCertPath string `mapstructure:"server_cert_path"`
			ServerKeyPath  string `mapstructure:"server_key_path"`
			ClientCertPath string `mapstructure:"client_cert_path"`
			ClientKeyPath  string `mapstructure:"client_key_path"`
			RetryPolicy    struct {
				MaxRetries int           `mapstructure:"max_retries"`
				Backoff    time.Duration `mapstructure:"backoff"`
				Jitter     time.Duration `mapstructure:"jitter"`
			} `mapstructure:"retry_policy"`
		} `mapstructure:"certificates"`

		HTTPClient struct {
			Timeout                   time.Duration `mapstructure:"timeout"`
			TLSVersion                string        `mapstructure:"tls_version"`
			MaxIdleConnectionsPerHost int           `mapstructure:"max_idle_connections_per_host"`
		} `mapstructure:"http_client"`

		CRL struct {
			TTL time.Duration `mapstructure:"ttl"`
		} `mapstructure:"crl"`

		OCSP struct {
			TTL time.Duration `mapstructure:"ttl"`
		} `mapstructure:"ocsp"`
	} `mapstructure:"security"`
}
