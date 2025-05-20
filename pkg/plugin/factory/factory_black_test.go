package factory_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/factory"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// MockProvider implements the metadata.Provider interface for testing
type MockProvider struct {
	meta metadata.ProviderMetadata
}

func (p *MockProvider) GetMetadata() metadata.ProviderMetadata {
	return p.meta
}

func (p *MockProvider) Initialize(ctx context.Context, config interface{}) error {
	return nil
}

func (p *MockProvider) Validate(ctx context.Context) error {
	return nil
}

func (p *MockProvider) IsCompatibleVersion(version string) bool {
	return true
}

// TestBaseFactoryCreation tests the creation of providers using the BaseFactory
func TestBaseFactoryCreation(t *testing.T) {
	// Define provider metadata for testing
	authProviderMeta := metadata.ProviderMetadata{
		ID:      "auth-basic",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Basic Auth Provider",
	}
	
	mfaProviderMeta := metadata.ProviderMetadata{
		ID:      "mfa-totp",
		Type:    metadata.ProviderTypeMFA,
		Version: "1.0.0",
		Name:    "TOTP MFA Provider",
	}
	
	// Create a factory with available providers
	authFactory := factory.NewBaseFactory(
		metadata.ProviderTypeAuth,
		func(id string, config interface{}) (metadata.Provider, error) {
			// This creator function would normally validate the id and config,
			// but for testing we'll just return a mock provider
			return &MockProvider{
				meta: metadata.ProviderMetadata{
					ID:      id,
					Type:    metadata.ProviderTypeAuth,
					Version: "1.0.0",
					Name:    "Mock " + id,
				},
			}, nil
		},
		[]metadata.ProviderMetadata{authProviderMeta},
	)
	
	// Test factory metadata
	t.Run("Factory metadata", func(t *testing.T) {
		// Check factory type
		if authFactory.GetType() != metadata.ProviderTypeAuth {
			t.Errorf("Expected factory type %s, got %s", metadata.ProviderTypeAuth, authFactory.GetType())
		}
		
		// Check available providers
		providers := authFactory.GetMetadata()
		if len(providers) != 1 {
			t.Errorf("Expected 1 available provider, got %d", len(providers))
		}
		
		if providers[0].ID != "auth-basic" {
			t.Errorf("Expected provider ID auth-basic, got %s", providers[0].ID)
		}
	})
	
	// Test provider creation with valid ID
	t.Run("Create valid provider", func(t *testing.T) {
		provider, err := authFactory.Create("auth-basic", nil)
		if err != nil {
			t.Errorf("Failed to create provider: %v", err)
		}
		
		if provider == nil {
			t.Fatalf("Created provider is nil")
		}
		
		if provider.GetMetadata().ID != "auth-basic" {
			t.Errorf("Expected provider ID auth-basic, got %s", provider.GetMetadata().ID)
		}
		
		if provider.GetMetadata().Type != metadata.ProviderTypeAuth {
			t.Errorf("Expected provider type %s, got %s", 
				metadata.ProviderTypeAuth, provider.GetMetadata().Type)
		}
	})
	
	// Test provider creation with invalid ID
	t.Run("Create invalid provider", func(t *testing.T) {
		_, err := authFactory.Create("invalid-id", nil)
		if err == nil {
			t.Errorf("Expected error when creating provider with invalid ID")
		}
	})
	
	// Test factory registry
	t.Run("Factory registry", func(t *testing.T) {
		// Create a factory registry
		registry := factory.NewFactoryRegistry()
		
		// Register the auth factory
		err := registry.RegisterFactory("auth-factory", authFactory)
		if err != nil {
			t.Errorf("Failed to register auth factory: %v", err)
		}
		
		// Create an MFA factory
		mfaFactory := factory.NewBaseFactory(
			metadata.ProviderTypeMFA,
			func(id string, config interface{}) (metadata.Provider, error) {
				return &MockProvider{
					meta: metadata.ProviderMetadata{
						ID:      id,
						Type:    metadata.ProviderTypeMFA,
						Version: "1.0.0",
						Name:    "Mock " + id,
					},
				}, nil
			},
			[]metadata.ProviderMetadata{mfaProviderMeta},
		)
		
		// Register the MFA factory
		err = registry.RegisterFactory("mfa-factory", mfaFactory)
		if err != nil {
			t.Errorf("Failed to register MFA factory: %v", err)
		}
		
		// Try to register the same factory again (should fail)
		err = registry.RegisterFactory("auth-factory", authFactory)
		if err == nil {
			t.Errorf("Expected error when registering the same factory twice")
		}
		
		// Test getting a factory
		retrievedFactory, err := registry.GetFactory(metadata.ProviderTypeAuth, "auth-factory")
		if err != nil {
			t.Errorf("Failed to get registered factory: %v", err)
		}
		
		if retrievedFactory.GetType() != metadata.ProviderTypeAuth {
			t.Errorf("Retrieved factory has wrong type: %s, expected: %s", 
				retrievedFactory.GetType(), metadata.ProviderTypeAuth)
		}
		
		// Test getting a non-existent factory
		_, err = registry.GetFactory(metadata.ProviderTypeAuth, "nonexistent")
		if err == nil {
			t.Errorf("Expected error when getting non-existent factory")
		}
		
		// Test getting a factory for a non-existent type
		_, err = registry.GetFactory(metadata.ProviderTypeHTTP, "auth-factory")
		if err == nil {
			t.Errorf("Expected error when getting factory with non-existent type")
		}
		
		// Test getting all factories for a type
		authFactories, err := registry.GetFactories(metadata.ProviderTypeAuth)
		if err != nil {
			t.Errorf("Failed to get factories by type: %v", err)
		}
		
		if len(authFactories) != 1 {
			t.Errorf("Expected 1 auth factory, got %d", len(authFactories))
		}
		
		// Test getting factories for a non-existent type
		_, err = registry.GetFactories(metadata.ProviderTypeHTTP)
		if err == nil {
			t.Errorf("Expected error when getting factories for non-existent type")
		}
		
		// Test listing provider types
		types := registry.ListProviderTypes()
		if len(types) != 2 {
			t.Errorf("Expected 2 provider types, got %d", len(types))
		}
		
		// Check available providers
		authProviders, err := registry.GetAvailableProviders(metadata.ProviderTypeAuth)
		if err != nil {
			t.Errorf("Failed to get available auth providers: %v", err)
		}
		
		if len(authProviders) != 1 {
			t.Errorf("Expected 1 available auth provider, got %d", len(authProviders))
		}
		
		// Test creating a provider using the registry
		provider, err := registry.CreateProvider(
			metadata.ProviderTypeAuth,
			"auth-factory",
			"auth-basic",
			nil,
		)
		if err != nil {
			t.Errorf("Failed to create provider using registry: %v", err)
		}
		
		if provider.GetMetadata().ID != "auth-basic" {
			t.Errorf("Created provider has wrong ID: %s, expected: auth-basic",
				provider.GetMetadata().ID)
		}
		
		// Test creating a provider with an non-existent factory
		_, err = registry.CreateProvider(
			metadata.ProviderTypeAuth,
			"nonexistent",
			"auth-basic",
			nil,
		)
		if err == nil {
			t.Errorf("Expected error when creating provider with non-existent factory")
		}
		
		// Test creating a provider with an invalid provider ID
		_, err = registry.CreateProvider(
			metadata.ProviderTypeAuth,
			"auth-factory",
			"nonexistent",
			nil,
		)
		if err == nil {
			t.Errorf("Expected error when creating provider with invalid ID")
		}
	})
}

// TestFactoryConfiguration tests passing configuration to providers
func TestFactoryConfiguration(t *testing.T) {
	// This test validates that configuration is correctly passed through the factory
	// to created providers
	
	// Define a test provider that validates configuration
	type ConfigValidatingProvider struct {
		MockProvider
		receivedConfig interface{}
	}
	
	// Define a test configuration struct
	type TestConfig struct {
		ApiKey    string
		Endpoint  string
		Debug     bool
	}
	
	// Create a factory that passes configuration
	configTestFactory := factory.NewBaseFactory(
		metadata.ProviderTypeAuth,
		func(id string, config interface{}) (metadata.Provider, error) {
			return &ConfigValidatingProvider{
				MockProvider: MockProvider{
					meta: metadata.ProviderMetadata{
						ID:      id,
						Type:    metadata.ProviderTypeAuth,
						Version: "1.0.0",
						Name:    "Config Test Provider",
					},
				},
				receivedConfig: config,
			}, nil
		},
		[]metadata.ProviderMetadata{
			{
				ID:      "config-test",
				Type:    metadata.ProviderTypeAuth,
				Version: "1.0.0",
				Name:    "Config Test Provider",
			},
		},
	)
	
	// Test configuration passing
	testConfig := TestConfig{
		ApiKey:   "test-key",
		Endpoint: "https://api.example.com",
		Debug:    true,
	}
	
	provider, err := configTestFactory.Create("config-test", testConfig)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}
	
	// Type assert to our test provider type
	configProvider, ok := provider.(*ConfigValidatingProvider)
	if !ok {
		t.Fatalf("Created provider is not a ConfigValidatingProvider")
	}
	
	// Verify configuration was received
	receivedConfig, ok := configProvider.receivedConfig.(TestConfig)
	if !ok {
		t.Fatalf("Received config is not a TestConfig")
	}
	
	// Check config values
	if receivedConfig.ApiKey != testConfig.ApiKey {
		t.Errorf("Expected ApiKey %s, got %s", testConfig.ApiKey, receivedConfig.ApiKey)
	}
	
	if receivedConfig.Endpoint != testConfig.Endpoint {
		t.Errorf("Expected Endpoint %s, got %s", testConfig.Endpoint, receivedConfig.Endpoint)
	}
	
	if receivedConfig.Debug != testConfig.Debug {
		t.Errorf("Expected Debug %v, got %v", testConfig.Debug, receivedConfig.Debug)
	}
}