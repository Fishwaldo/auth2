package factory

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// MockProvider implements the metadata.Provider interface for testing
type MockProvider struct {
	metadata metadata.ProviderMetadata
}

func (p *MockProvider) GetMetadata() metadata.ProviderMetadata {
	return p.metadata
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

func TestBaseFactory(t *testing.T) {
	// Create provider metadata
	meta1 := metadata.ProviderMetadata{
		ID:      "provider1",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Provider 1",
	}
	
	meta2 := metadata.ProviderMetadata{
		ID:      "provider2",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Provider 2",
	}
	
	// Create a factory
	factory := NewBaseFactory(
		metadata.ProviderTypeAuth,
		func(id string, config interface{}) (metadata.Provider, error) {
			return &MockProvider{
				metadata: metadata.ProviderMetadata{
					ID:      id,
					Type:    metadata.ProviderTypeAuth,
					Version: "1.0.0",
					Name:    "Test Provider",
				},
			}, nil
		},
		[]metadata.ProviderMetadata{meta1, meta2},
	)
	
	// Test GetType
	if factory.GetType() != metadata.ProviderTypeAuth {
		t.Errorf("GetType() = %v, want %v", factory.GetType(), metadata.ProviderTypeAuth)
	}
	
	// Test GetMetadata
	metadataList := factory.GetMetadata()
	if len(metadataList) != 2 {
		t.Errorf("GetMetadata() len = %v, want %v", len(metadataList), 2)
	}
	
	// Test Create with supported provider ID
	provider, err := factory.Create("provider1", nil)
	if err != nil {
		t.Errorf("Create() error = %v, want nil", err)
	}
	if provider.GetMetadata().ID != "provider1" {
		t.Errorf("Create().GetMetadata().ID = %v, want %v", provider.GetMetadata().ID, "provider1")
	}
	
	// Test Create with unsupported provider ID
	_, err = factory.Create("unsupported", nil)
	if err == nil {
		t.Errorf("Create() error = nil, want error")
	}
}

func TestFactoryRegistry(t *testing.T) {
	// Create provider metadata
	meta1 := metadata.ProviderMetadata{
		ID:      "provider1",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Provider 1",
	}
	
	// Create a factory
	factory1 := NewBaseFactory(
		metadata.ProviderTypeAuth,
		func(id string, config interface{}) (metadata.Provider, error) {
			return &MockProvider{
				metadata: metadata.ProviderMetadata{
					ID:      id,
					Type:    metadata.ProviderTypeAuth,
					Version: "1.0.0",
					Name:    "Test Provider",
				},
			}, nil
		},
		[]metadata.ProviderMetadata{meta1},
	)
	
	// Create another factory
	factory2 := NewBaseFactory(
		metadata.ProviderTypeMFA,
		func(id string, config interface{}) (metadata.Provider, error) {
			return &MockProvider{
				metadata: metadata.ProviderMetadata{
					ID:      id,
					Type:    metadata.ProviderTypeMFA,
					Version: "1.0.0",
					Name:    "Test Provider",
				},
			}, nil
		},
		[]metadata.ProviderMetadata{},
	)
	
	// Create a factory registry
	registry := NewFactoryRegistry()
	
	// Test RegisterFactory
	err := registry.RegisterFactory("auth-factory", factory1)
	if err != nil {
		t.Errorf("RegisterFactory() error = %v, want nil", err)
	}
	
	// Test registering the same factory again
	err = registry.RegisterFactory("auth-factory", factory1)
	if err == nil {
		t.Errorf("RegisterFactory() error = nil, want error")
	}
	
	// Test registering a factory with a different type
	err = registry.RegisterFactory("mfa-factory", factory2)
	if err != nil {
		t.Errorf("RegisterFactory() error = %v, want nil", err)
	}
	
	// Test GetFactory
	retrievedFactory, err := registry.GetFactory(metadata.ProviderTypeAuth, "auth-factory")
	if err != nil {
		t.Errorf("GetFactory() error = %v, want nil", err)
	}
	if retrievedFactory.GetType() != metadata.ProviderTypeAuth {
		t.Errorf("GetFactory().GetType() = %v, want %v", retrievedFactory.GetType(), metadata.ProviderTypeAuth)
	}
	
	// Test GetFactory with non-existent factory
	_, err = registry.GetFactory(metadata.ProviderTypeAuth, "non-existent")
	if err == nil {
		t.Errorf("GetFactory() error = nil, want error")
	}
	
	// Test GetFactories
	factories, err := registry.GetFactories(metadata.ProviderTypeAuth)
	if err != nil {
		t.Errorf("GetFactories() error = %v, want nil", err)
	}
	if len(factories) != 1 {
		t.Errorf("GetFactories() len = %v, want %v", len(factories), 1)
	}
	
	// Test ListProviderTypes
	types := registry.ListProviderTypes()
	if len(types) != 2 {
		t.Errorf("ListProviderTypes() len = %v, want %v", len(types), 2)
	}
	
	// Test GetAvailableProviders
	providers, err := registry.GetAvailableProviders(metadata.ProviderTypeAuth)
	if err != nil {
		t.Errorf("GetAvailableProviders() error = %v, want nil", err)
	}
	if len(providers) != 1 {
		t.Errorf("GetAvailableProviders() len = %v, want %v", len(providers), 1)
	}
	
	// Test CreateProvider
	provider, err := registry.CreateProvider(metadata.ProviderTypeAuth, "auth-factory", "provider1", nil)
	if err != nil {
		t.Errorf("CreateProvider() error = %v, want nil", err)
	}
	if provider.GetMetadata().ID != "provider1" {
		t.Errorf("CreateProvider().GetMetadata().ID = %v, want %v", provider.GetMetadata().ID, "provider1")
	}
	
	// Test CreateProvider with non-existent factory
	_, err = registry.CreateProvider(metadata.ProviderTypeAuth, "non-existent", "provider1", nil)
	if err == nil {
		t.Errorf("CreateProvider() error = nil, want error")
	}
	
	// Test CreateProvider with non-existent provider ID
	_, err = registry.CreateProvider(metadata.ProviderTypeAuth, "auth-factory", "non-existent", nil)
	if err == nil {
		t.Errorf("CreateProvider() error = nil, want error")
	}
}