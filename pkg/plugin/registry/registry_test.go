package registry

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// MockProvider implements the metadata.Provider interface for testing
type MockProvider struct {
	metadata metadata.ProviderMetadata
	initErr  error
	validateErr error
}

func (p *MockProvider) GetMetadata() metadata.ProviderMetadata {
	return p.metadata
}

func (p *MockProvider) Initialize(ctx context.Context, config interface{}) error {
	return p.initErr
}

func (p *MockProvider) Validate(ctx context.Context) error {
	return p.validateErr
}

func (p *MockProvider) IsCompatibleVersion(version string) bool {
	return true
}

func TestRegistry(t *testing.T) {
	// Create a new registry
	registry := NewRegistry()
	
	// Create a mock provider
	provider := &MockProvider{
		metadata: metadata.ProviderMetadata{
			ID:      "test-provider",
			Type:    metadata.ProviderTypeAuth,
			Version: "1.0.0",
			Name:    "Test Provider",
		},
	}
	
	// Test RegisterProvider
	err := registry.RegisterProvider(provider)
	if err != nil {
		t.Errorf("RegisterProvider() error = %v, want nil", err)
	}
	
	// Test registering the same provider again
	err = registry.RegisterProvider(provider)
	if err == nil {
		t.Errorf("RegisterProvider() error = nil, want error")
	}
	
	// Test GetProvider
	retrievedProvider, err := registry.GetProvider(metadata.ProviderTypeAuth, "test-provider")
	if err != nil {
		t.Errorf("GetProvider() error = %v, want nil", err)
	}
	if retrievedProvider.GetMetadata().ID != "test-provider" {
		t.Errorf("GetProvider().GetMetadata().ID = %v, want %v", retrievedProvider.GetMetadata().ID, "test-provider")
	}
	
	// Test GetProvider with non-existent provider
	_, err = registry.GetProvider(metadata.ProviderTypeAuth, "non-existent")
	if err == nil {
		t.Errorf("GetProvider() error = nil, want error")
	}
	
	// Test GetProviders
	providers, err := registry.GetProviders(metadata.ProviderTypeAuth)
	if err != nil {
		t.Errorf("GetProviders() error = %v, want nil", err)
	}
	if len(providers) != 1 {
		t.Errorf("GetProviders() len = %v, want %v", len(providers), 1)
	}
	
	// Test GetProviders with non-existent provider type
	_, err = registry.GetProviders(metadata.ProviderTypeMFA)
	if err == nil {
		t.Errorf("GetProviders() error = nil, want error")
	}
	
	// Test ListProviderTypes
	types := registry.ListProviderTypes()
	if len(types) != 1 {
		t.Errorf("ListProviderTypes() len = %v, want %v", len(types), 1)
	}
	if types[0] != metadata.ProviderTypeAuth {
		t.Errorf("ListProviderTypes()[0] = %v, want %v", types[0], metadata.ProviderTypeAuth)
	}
	
	// Test GetProviderMetadata
	metadataList, err := registry.GetProviderMetadata(metadata.ProviderTypeAuth)
	if err != nil {
		t.Errorf("GetProviderMetadata() error = %v, want nil", err)
	}
	if len(metadataList) != 1 {
		t.Errorf("GetProviderMetadata() len = %v, want %v", len(metadataList), 1)
	}
	if metadataList[0].ID != "test-provider" {
		t.Errorf("GetProviderMetadata()[0].ID = %v, want %v", metadataList[0].ID, "test-provider")
	}
	
	// Test UnregisterProvider
	err = registry.UnregisterProvider(metadata.ProviderTypeAuth, "test-provider")
	if err != nil {
		t.Errorf("UnregisterProvider() error = %v, want nil", err)
	}
	
	// Test that the provider is no longer registered
	_, err = registry.GetProvider(metadata.ProviderTypeAuth, "test-provider")
	if err == nil {
		t.Errorf("GetProvider() error = nil, want error after unregistering")
	}
}