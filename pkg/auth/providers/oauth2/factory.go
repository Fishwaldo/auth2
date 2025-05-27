package oauth2

import (
	"fmt"
	"reflect"

	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/mitchellh/mapstructure"
)

// Factory creates OAuth2 provider instances
type Factory struct {
	stateStore metadata.StateStore
}

// NewFactory creates a new OAuth2 provider factory
func NewFactory(stateStore metadata.StateStore) *Factory {
	return &Factory{
		stateStore: stateStore,
	}
}

// Create creates a new OAuth2 provider instance
func (f *Factory) Create(config interface{}) (metadata.Provider, error) {
	cfg, err := f.parseConfig(config)
	if err != nil {
		return nil, err
	}
	
	// Set state store
	cfg.StateStore = f.stateStore
	
	provider, err := NewProvider(cfg)
	if err != nil {
		return nil, err
	}
	
	return provider, nil
}

// CreateWithProvider creates a pre-configured OAuth2 provider for a specific service
func (f *Factory) CreateWithProvider(providerName string, config interface{}) (metadata.Provider, error) {
	cfg, err := f.parseConfig(config)
	if err != nil {
		return nil, err
	}
	
	// Apply provider-specific configuration
	if err := cfg.ApplyProviderConfig(providerName); err != nil {
		return nil, err
	}
	
	// Set state store
	cfg.StateStore = f.stateStore
	
	provider, err := NewProvider(cfg)
	if err != nil {
		return nil, err
	}
	
	return provider, nil
}

// parseConfig parses various configuration formats
func (f *Factory) parseConfig(config interface{}) (*Config, error) {
	var cfg *Config
	
	switch c := config.(type) {
	case *Config:
		cfg = c
		
	case Config:
		cfg = &c
		
	case map[string]interface{}:
		cfg = DefaultConfig()
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			WeaklyTypedInput: true,
			Result:           cfg,
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
			),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create decoder: %w", err)
		}
		
		if err := decoder.Decode(c); err != nil {
			return nil, fmt.Errorf("failed to decode configuration: %w", err)
		}
		
	default:
		// Try to use reflection for struct types
		cfg = DefaultConfig()
		configType := reflect.TypeOf(config)
		if configType.Kind() == reflect.Ptr {
			configType = configType.Elem()
		}
		
		if configType.Kind() == reflect.Struct {
			decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
				WeaklyTypedInput: true,
				Result:           cfg,
				DecodeHook: mapstructure.ComposeDecodeHookFunc(
					mapstructure.StringToTimeDurationHookFunc(),
					mapstructure.StringToSliceHookFunc(","),
				),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create decoder: %w", err)
			}
			
			if err := decoder.Decode(config); err != nil {
				return nil, fmt.Errorf("failed to decode configuration: %w", err)
			}
		} else {
			return nil, fmt.Errorf("unsupported configuration type: %T", config)
		}
	}
	
	return cfg, nil
}

// GetMetadata returns factory metadata
func (f *Factory) GetMetadata() metadata.ProviderMetadata {
	return metadata.ProviderMetadata{
		ID:          "oauth2-factory",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "OAuth2 Provider Factory",
		Description: "Factory for creating OAuth2 authentication providers",
		Author:      "Auth2 Team",
	}
}

// QuickGoogle creates a Google OAuth2 provider with minimal configuration
func QuickGoogle(clientID, clientSecret, redirectURL string, stateStore metadata.StateStore) (*Provider, error) {
	cfg := DefaultConfig()
	cfg.ClientID = clientID
	cfg.ClientSecret = clientSecret
	cfg.RedirectURL = redirectURL
	cfg.StateStore = stateStore
	
	if err := cfg.ApplyProviderConfig("google"); err != nil {
		return nil, err
	}
	
	return NewProvider(cfg)
}

// QuickGitHub creates a GitHub OAuth2 provider with minimal configuration
func QuickGitHub(clientID, clientSecret, redirectURL string, stateStore metadata.StateStore) (*Provider, error) {
	cfg := DefaultConfig()
	cfg.ClientID = clientID
	cfg.ClientSecret = clientSecret
	cfg.RedirectURL = redirectURL
	cfg.StateStore = stateStore
	
	if err := cfg.ApplyProviderConfig("github"); err != nil {
		return nil, err
	}
	
	return NewProvider(cfg)
}

// QuickMicrosoft creates a Microsoft OAuth2 provider with minimal configuration
func QuickMicrosoft(clientID, clientSecret, redirectURL string, stateStore metadata.StateStore) (*Provider, error) {
	cfg := DefaultConfig()
	cfg.ClientID = clientID
	cfg.ClientSecret = clientSecret
	cfg.RedirectURL = redirectURL
	cfg.StateStore = stateStore
	
	if err := cfg.ApplyProviderConfig("microsoft"); err != nil {
		return nil, err
	}
	
	return NewProvider(cfg)
}

// QuickFacebook creates a Facebook OAuth2 provider with minimal configuration
func QuickFacebook(clientID, clientSecret, redirectURL string, stateStore metadata.StateStore) (*Provider, error) {
	cfg := DefaultConfig()
	cfg.ClientID = clientID
	cfg.ClientSecret = clientSecret
	cfg.RedirectURL = redirectURL
	cfg.StateStore = stateStore
	
	if err := cfg.ApplyProviderConfig("facebook"); err != nil {
		return nil, err
	}
	
	return NewProvider(cfg)
}