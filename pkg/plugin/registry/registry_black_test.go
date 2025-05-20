package registry_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/plugin/registry"
)

// MockProvider implements the metadata.Provider interface for testing
type MockProvider struct {
	meta        metadata.ProviderMetadata
	initErr     error
	validateErr error
}

func (p *MockProvider) GetMetadata() metadata.ProviderMetadata {
	return p.meta
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

// NewMockProvider creates a new mock provider
func NewMockProvider(id string, pType metadata.ProviderType, name string) *MockProvider {
	return &MockProvider{
		meta: metadata.ProviderMetadata{
			ID:      id,
			Type:    pType,
			Version: "1.0.0",
			Name:    name,
		},
	}
}

// TestRegistryProviderManagement tests the provider management functions of the registry
func TestRegistryProviderManagement(t *testing.T) {
	// Create a new registry
	reg := registry.NewRegistry()
	
	// Create mock providers of different types
	authProvider := NewMockProvider("auth1", metadata.ProviderTypeAuth, "Auth Provider 1")
	mfaProvider := NewMockProvider("mfa1", metadata.ProviderTypeMFA, "MFA Provider 1")
	storageProvider := NewMockProvider("storage1", metadata.ProviderTypeStorage, "Storage Provider 1")
	
	// Test provider registration
	t.Run("RegisterProvider", func(t *testing.T) {
		if err := reg.RegisterProvider(authProvider); err != nil {
			t.Errorf("Failed to register auth provider: %v", err)
		}
		
		if err := reg.RegisterProvider(mfaProvider); err != nil {
			t.Errorf("Failed to register MFA provider: %v", err)
		}
		
		if err := reg.RegisterProvider(storageProvider); err != nil {
			t.Errorf("Failed to register storage provider: %v", err)
		}
		
		// Registering the same provider again should fail
		if err := reg.RegisterProvider(authProvider); err == nil {
			t.Errorf("Expected error when registering the same provider twice")
		}
	})
	
	// Test provider retrieval
	t.Run("GetProvider", func(t *testing.T) {
		// Valid provider
		provider, err := reg.GetProvider(metadata.ProviderTypeAuth, "auth1")
		if err != nil {
			t.Errorf("Failed to get registered provider: %v", err)
		}
		if provider.GetMetadata().ID != "auth1" {
			t.Errorf("Got wrong provider ID: %s, expected: auth1", provider.GetMetadata().ID)
		}
		
		// Missing provider
		_, err = reg.GetProvider(metadata.ProviderTypeAuth, "nonexistent")
		if err == nil {
			t.Errorf("Expected error when getting non-existent provider")
		}
		
		// Missing provider type
		_, err = reg.GetProvider(metadata.ProviderTypeHTTP, "auth1")
		if err == nil {
			t.Errorf("Expected error when getting provider with non-existent type")
		}
	})
	
	// Test getting all providers of a type
	t.Run("GetProviders", func(t *testing.T) {
		// Register a second auth provider
		authProvider2 := NewMockProvider("auth2", metadata.ProviderTypeAuth, "Auth Provider 2")
		if err := reg.RegisterProvider(authProvider2); err != nil {
			t.Errorf("Failed to register second auth provider: %v", err)
		}
		
		// Get all auth providers
		providers, err := reg.GetProviders(metadata.ProviderTypeAuth)
		if err != nil {
			t.Errorf("Failed to get providers by type: %v", err)
		}
		
		if len(providers) != 2 {
			t.Errorf("Expected 2 auth providers, got %d", len(providers))
		}
		
		// Make sure we can't modify the returned map to affect the registry
		providers["new"] = authProvider
		
		// Verify the original registry is unchanged
		verifyProviders, err := reg.GetProviders(metadata.ProviderTypeAuth)
		if err != nil {
			t.Errorf("Failed to get providers by type: %v", err)
		}
		
		if len(verifyProviders) != 2 {
			t.Errorf("Registry was modified by external code, expected 2 providers, got %d", len(verifyProviders))
		}
		
		// Get providers of non-existent type
		_, err = reg.GetProviders(metadata.ProviderTypeHTTP)
		if err == nil {
			t.Errorf("Expected error when getting providers of non-existent type")
		}
	})
	
	// Test listing provider types
	t.Run("ListProviderTypes", func(t *testing.T) {
		types := reg.ListProviderTypes()
		
		if len(types) != 3 {
			t.Errorf("Expected 3 provider types, got %d", len(types))
		}
		
		// Check that all registered types are in the list
		typeMap := make(map[metadata.ProviderType]bool)
		for _, pt := range types {
			typeMap[pt] = true
		}
		
		if !typeMap[metadata.ProviderTypeAuth] {
			t.Errorf("Missing provider type: %s", metadata.ProviderTypeAuth)
		}
		
		if !typeMap[metadata.ProviderTypeMFA] {
			t.Errorf("Missing provider type: %s", metadata.ProviderTypeMFA)
		}
		
		if !typeMap[metadata.ProviderTypeStorage] {
			t.Errorf("Missing provider type: %s", metadata.ProviderTypeStorage)
		}
	})
	
	// Test getting provider metadata
	t.Run("GetProviderMetadata", func(t *testing.T) {
		// Valid type
		metadataList, err := reg.GetProviderMetadata(metadata.ProviderTypeAuth)
		if err != nil {
			t.Errorf("Failed to get provider metadata: %v", err)
		}
		
		if len(metadataList) != 2 {
			t.Errorf("Expected 2 metadata entries, got %d", len(metadataList))
		}
		
		// Map IDs for verification
		idMap := make(map[string]bool)
		for _, meta := range metadataList {
			idMap[meta.ID] = true
		}
		
		if !idMap["auth1"] || !idMap["auth2"] {
			t.Errorf("Missing expected provider IDs in metadata")
		}
		
		// Non-existent type
		_, err = reg.GetProviderMetadata(metadata.ProviderTypeHTTP)
		if err == nil {
			t.Errorf("Expected error when getting metadata for non-existent type")
		}
	})
	
	// Test unregistering providers
	t.Run("UnregisterProvider", func(t *testing.T) {
		// Valid provider
		err := reg.UnregisterProvider(metadata.ProviderTypeAuth, "auth1")
		if err != nil {
			t.Errorf("Failed to unregister provider: %v", err)
		}
		
		// Verify it's gone
		_, err = reg.GetProvider(metadata.ProviderTypeAuth, "auth1")
		if err == nil {
			t.Errorf("Provider should not exist after unregistering")
		}
		
		// Non-existent provider
		err = reg.UnregisterProvider(metadata.ProviderTypeAuth, "nonexistent")
		if err == nil {
			t.Errorf("Expected error when unregistering non-existent provider")
		}
		
		// Non-existent type
		err = reg.UnregisterProvider(metadata.ProviderTypeHTTP, "auth2")
		if err == nil {
			t.Errorf("Expected error when unregistering from non-existent type")
		}
	})
}

// TestRegistryProviderValidation tests the validation functionality
func TestRegistryProviderValidation(t *testing.T) {
	reg := registry.NewRegistry()
	ctx := context.Background()
	
	// Create providers with validation errors
	validProvider := &MockProvider{
		meta: metadata.ProviderMetadata{
			ID:      "valid",
			Type:    metadata.ProviderTypeAuth,
			Version: "1.0.0",
			Name:    "Valid Provider",
		},
		validateErr: nil,
	}
	
	invalidProvider := &MockProvider{
		meta: metadata.ProviderMetadata{
			ID:      "invalid",
			Type:    metadata.ProviderTypeAuth,
			Version: "1.0.0",
			Name:    "Invalid Provider",
		},
		validateErr: metadata.NewProviderError("invalid", "auth", "validation failed"),
	}
	
	// Register providers
	if err := reg.RegisterProvider(validProvider); err != nil {
		t.Fatalf("Failed to register valid provider: %v", err)
	}
	
	if err := reg.RegisterProvider(invalidProvider); err != nil {
		t.Fatalf("Failed to register invalid provider: %v", err)
	}
	
	// Test validation
	err := reg.ValidateProviders(ctx)
	if err == nil {
		t.Errorf("Expected validation error but got nil")
	}
}

// TestRegistryProviderInitialization tests the initialization functionality
func TestRegistryProviderInitialization(t *testing.T) {
	reg := registry.NewRegistry()
	ctx := context.Background()
	
	// Create providers with different initialization behavior
	validProvider := &MockProvider{
		meta: metadata.ProviderMetadata{
			ID:      "valid",
			Type:    metadata.ProviderTypeAuth,
			Version: "1.0.0",
			Name:    "Valid Provider",
		},
		initErr: nil,
	}
	
	invalidProvider := &MockProvider{
		meta: metadata.ProviderMetadata{
			ID:      "invalid",
			Type:    metadata.ProviderTypeAuth,
			Version: "1.0.0",
			Name:    "Invalid Provider",
		},
		initErr: metadata.NewProviderError("invalid", "auth", "initialization failed"),
	}
	
	// Register providers
	if err := reg.RegisterProvider(validProvider); err != nil {
		t.Fatalf("Failed to register valid provider: %v", err)
	}
	
	if err := reg.RegisterProvider(invalidProvider); err != nil {
		t.Fatalf("Failed to register invalid provider: %v", err)
	}
	
	// Test initialization
	configs := map[string]interface{}{
		"auth.valid":   map[string]string{"key": "value"},
		"auth.invalid": nil,
	}
	
	err := reg.InitializeProviders(ctx, configs)
	if err == nil {
		t.Errorf("Expected initialization error but got nil")
	}
}