// /security/internal/config/config.go
package config

import (
	config "github.com/goletan/config/pkg"
	"github.com/goletan/security/internal/types"
	"go.uber.org/zap"
)

// LoadSecurityConfig loads security-related configuration into a SecurityConfig struct.
func LoadSecurityConfig(logger *zap.Logger) (*types.SecurityConfig, error) {
	cfg := &types.SecurityConfig{}
	if err := config.LoadConfig("Security", cfg, logger); err != nil {
		logger.Error(
			"Failed to load security configuration",
			zap.Error(err),
			zap.Any("context", map[string]interface{}{"step": "config loading"}),
		)
		return nil, err
	}

	return cfg, nil
}
