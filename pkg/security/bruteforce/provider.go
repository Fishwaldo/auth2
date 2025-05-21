package bruteforce

import (
	"context"

	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Provider implements the plugin.Provider interface for bruteforce protection
type Provider struct {
	*metadata.BaseProvider
	manager *ProtectionManager
}

// NewProvider creates a new brute force protection provider
func NewProvider(storage Storage, config *Config, notification NotificationService) *Provider {
	manager := NewProtectionManager(storage, config, notification)

	return &Provider{
		BaseProvider: metadata.NewBaseProvider(GetPluginMetadata()),
		manager:      manager,
	}
}

// Initialize initializes the provider with the given configuration
func (p *Provider) Initialize(ctx context.Context, config interface{}) error {
	// The provider is already initialized with the manager in NewProvider
	return nil
}

// Validate checks if the provider is properly configured
func (p *Provider) Validate(ctx context.Context) error {
	// Nothing to validate, as the manager is always valid
	return nil
}

// GetProtectionManager returns the underlying protection manager
func (p *Provider) GetProtectionManager() *ProtectionManager {
	return p.manager
}

// GetAuthIntegration returns an auth integration for the manager
func (p *Provider) GetAuthIntegration() *AuthIntegration {
	return NewAuthIntegration(p.manager)
}

// Stop stops the provider and any background routines
func (p *Provider) Stop() {
	p.manager.Stop()
}