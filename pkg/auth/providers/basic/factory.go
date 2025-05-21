package basic

import (
	"fmt"

	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/user"
)

// Factory creates basic authentication providers
type Factory struct {
	userStore     user.Store
	passwordUtils user.PasswordUtils
}

// NewFactory creates a new basic authentication provider factory
func NewFactory(userStore user.Store, passwordUtils user.PasswordUtils) *Factory {
	return &Factory{
		userStore:     userStore,
		passwordUtils: passwordUtils,
	}
}

// Create creates a new basic authentication provider
func (f *Factory) Create(id string, config interface{}) (metadata.Provider, error) {
	// Parse configuration
	var providerConfig *Config
	var ok bool

	if config != nil {
		providerConfig, ok = config.(*Config)
		if !ok {
			// Try to convert from map
			configMap, mapOk := config.(map[string]interface{})
			if !mapOk {
				return nil, fmt.Errorf("invalid configuration type: %T", config)
			}

			// Extract values from map
			providerConfig = DefaultConfig()

			// Account lock threshold
			if val, exists := configMap["account_lock_threshold"]; exists {
				if intVal, intOk := val.(int); intOk {
					providerConfig.AccountLockThreshold = intVal
				}
			}

			// Account lock duration
			if val, exists := configMap["account_lock_duration"]; exists {
				if intVal, intOk := val.(int); intOk {
					providerConfig.AccountLockDuration = intVal
				}
			}

			// Require verified email
			if val, exists := configMap["require_verified_email"]; exists {
				if boolVal, boolOk := val.(bool); boolOk {
					providerConfig.RequireVerifiedEmail = boolVal
				}
			}
		}
	} else {
		providerConfig = DefaultConfig()
	}

	// Create the provider
	return NewProvider(id, f.userStore, f.passwordUtils, providerConfig), nil
}

// GetType returns the type of provider this factory creates
func (f *Factory) GetType() metadata.ProviderType {
	return metadata.ProviderTypeAuth
}

// GetMetadata returns metadata about the providers this factory can create
func (f *Factory) GetMetadata() []metadata.ProviderMetadata {
	return []metadata.ProviderMetadata{
		{
			ID:          "basic",
			Type:        metadata.ProviderTypeAuth,
			Name:        ProviderName,
			Description: ProviderDescription,
			Version:     ProviderVersion,
		},
	}
}

// Register registers this factory with the provider registry
func Register(registry providers.Registry, userStore user.Store, passwordUtils user.PasswordUtils) error {
	factory := NewFactory(userStore, passwordUtils)
	return registry.RegisterAuthProviderFactory("basic", factory)
}