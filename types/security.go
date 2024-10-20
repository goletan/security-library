package types

type SecurityConfig struct {
	Security struct {
		Certificates struct {
			CACertPath     string `mapstructure:"ca_cert_path"`
			ServerCertPath string `mapstructure:"server_cert_path"`
			ServerKeyPath  string `mapstructure:"server_key_path"`
			ClientCertPath string `mapstructure:"client_cert_path"`
			ClientKeyPath  string `mapstructure:"client_key_path"`
		} `mapstructure:"certificates"`
		HTTPClient struct {
			Timeout                   int    `mapstructure:"timeout"`
			TLSVersion                string `mapstructure:"tls_version"`
			MaxIdleConnectionsPerHost int    `mapstructure:"max_idle_connections_per_host"`
		} `mapstructure:"http_client"`
	} `mapstructure:"security"`
}
