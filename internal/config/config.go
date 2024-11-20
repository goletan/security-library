package config

import (
	config "github.com/goletan/config/pkg"
	"github.com/goletan/security/internal/types"
	"go.uber.org/zap"
)

var cfg types.SecurityConfig

func LoadSecurityConfig(logger *zap.Logger) (*types.SecurityConfig, error) {
	if err := config.LoadConfig("Security", &cfg, logger); err != nil {
		logger.Error(
			"Failed to load security configuration",
			zap.Error(err),
			zap.Any("context", map[string]interface{}{"step": "config loading"}),
		)
		return nil, err
	}

	return &cfg, nil
}
