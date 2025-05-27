package webauthn

import (
	"fmt"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/plugin/registry"
)

// Factory creates WebAuthn provider instances
type Factory struct {
	defaultConfig *Config
}

// NewFactory creates a new WebAuthn provider factory
func NewFactory(defaultConfig *Config) *Factory {
	if defaultConfig == nil {
		defaultConfig = DefaultConfig()
	}
	return &Factory{
		defaultConfig: defaultConfig,
	}
}

// Create creates a new WebAuthn provider instance
func (f *Factory) Create(config interface{}) (metadata.Provider, error) {
	var cfg *Config
	
	switch c := config.(type) {
	case *Config:
		cfg = c
	case Config:
		cfg = &c
	case map[string]interface{}:
		// Parse config from map
		cfg = f.defaultConfig
		
		if v, ok := c["rp_display_name"].(string); ok {
			cfg.RPDisplayName = v
		}
		if v, ok := c["rp_id"].(string); ok {
			cfg.RPID = v
		}
		if v, ok := c["rp_origins"].([]string); ok {
			cfg.RPOrigins = v
		} else if v, ok := c["rp_origins"].([]interface{}); ok {
			origins := make([]string, len(v))
			for i, o := range v {
				if s, ok := o.(string); ok {
					origins[i] = s
				}
			}
			cfg.RPOrigins = origins
		}
		
		// Parse security preferences
		if v, ok := c["attestation_preference"].(string); ok {
			cfg.AttestationPreference = AttestationConveyancePreference(v)
		}
		if v, ok := c["user_verification"].(string); ok {
			cfg.UserVerification = UserVerificationRequirement(v)
		}
		if v, ok := c["resident_key_requirement"].(string); ok {
			cfg.ResidentKeyRequirement = ResidentKeyRequirement(v)
		}
		
		// StateStore must be provided
		if v, ok := c["state_store"].(metadata.StateStore); ok {
			cfg.StateStore = v
		}
	case nil:
		cfg = f.defaultConfig
	default:
		return nil, fmt.Errorf("unsupported config type: %T", config)
	}
	
	// Validate state store
	if cfg.StateStore == nil {
		return nil, ErrInvalidConfig("state_store is required")
	}
	
	return New(cfg)
}

// GetType returns the provider type
func (f *Factory) GetType() metadata.ProviderType {
	return metadata.ProviderTypeAuth
}

// GetMetadata returns the provider metadata
func (f *Factory) GetMetadata() metadata.ProviderMetadata {
	return metadata.ProviderMetadata{
		ID:          "webauthn",
		Type:        metadata.ProviderTypeAuth,
		Name:        "WebAuthn",
		Description: "WebAuthn/FIDO2 passwordless authentication and MFA",
		Version:     "1.0.0",
		Author:      "auth2",
	}
}

// Register registers the WebAuthn provider with the registry
func Register(r *registry.Registry, config *Config) error {
	// Create provider instance
	provider, err := New(config)
	if err != nil {
		return err
	}
	
	// Register the provider
	return r.RegisterProvider(provider)
}

// CreateAuthProvider creates a WebAuthn provider as an AuthProvider
func CreateAuthProvider(config *Config) (providers.AuthProvider, error) {
	provider, err := New(config)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// CreateMFAProvider creates a WebAuthn provider as an MFAProvider
func CreateMFAProvider(config *Config) (metadata.MFAProvider, error) {
	provider, err := New(config)
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// CreateDualModeProvider creates a WebAuthn provider that can function as both auth and MFA
func CreateDualModeProvider(config *Config) (*Provider, error) {
	return New(config)
}