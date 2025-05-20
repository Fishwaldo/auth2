package discovery_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/plugin/discovery"
	"github.com/Fishwaldo/auth2/pkg/plugin/factory"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/plugin/registry"
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

// MockAuthProvider implements the metadata.AuthProvider interface
type MockAuthProvider struct {
	MockProvider
}

func (p *MockAuthProvider) Authenticate(ctx context.Context, credentials interface{}) (string, error) {
	// In a real implementation, this would validate credentials and return a user ID
	return "user-123", nil
}

func (p *MockAuthProvider) Supports(credentials interface{}) bool {
	// Check if the provider supports the given credentials type
	_, ok := credentials.(metadata.UsernamePasswordCredentials)
	return ok
}

// MockMFAProvider implements the metadata.MFAProvider interface
type MockMFAProvider struct {
	MockProvider
}

func (p *MockMFAProvider) Setup(ctx context.Context, userID string) (metadata.SetupData, error) {
	// In a real implementation, this would generate and return MFA setup data
	return metadata.SetupData{
		ProviderID: p.meta.ID,
		UserID:     userID,
		Secret:     "test-secret",
		QRCode:     []byte("test-qr-code"),
	}, nil
}

func (p *MockMFAProvider) Verify(ctx context.Context, userID string, code string) (bool, error) {
	// In a real implementation, this would validate the MFA code
	return code == "123456", nil
}

func (p *MockMFAProvider) GenerateBackupCodes(ctx context.Context, userID string, count int) ([]string, error) {
	// In a real implementation, this would generate backup codes
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		codes[i] = "backup-" + string(rune(i+48))
	}
	return codes, nil
}

// TestDiscoveryService tests the discovery service functionality
func TestDiscoveryService(t *testing.T) {
	// Create registry and factory registry
	reg := registry.NewRegistry()
	factoryReg := factory.NewFactoryRegistry()
	
	// Create and register a discovery service
	discoveryService := discovery.NewDiscoveryService(reg, factoryReg)
	
	// Define provider metadata
	basicAuthMeta := metadata.ProviderMetadata{
		ID:      "basic-auth",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Basic Auth Provider",
	}
	
	oauthAuthMeta := metadata.ProviderMetadata{
		ID:      "oauth-auth",
		Type:    metadata.ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "OAuth Auth Provider",
	}
	
	totpMFAMeta := metadata.ProviderMetadata{
		ID:      "totp-mfa",
		Type:    metadata.ProviderTypeMFA,
		Version: "1.0.0",
		Name:    "TOTP MFA Provider",
	}
	
	// Create factories
	authFactory := factory.NewBaseFactory(
		metadata.ProviderTypeAuth,
		func(id string, config interface{}) (metadata.Provider, error) {
			if id == "basic-auth" {
				return &MockAuthProvider{
					MockProvider: MockProvider{
						meta: basicAuthMeta,
					},
				}, nil
			} else if id == "oauth-auth" {
				return &MockAuthProvider{
					MockProvider: MockProvider{
						meta: oauthAuthMeta,
					},
				}, nil
			}
			return nil, metadata.NewProviderError(id, string(metadata.ProviderTypeAuth), "unknown provider")
		},
		[]metadata.ProviderMetadata{basicAuthMeta, oauthAuthMeta},
	)
	
	mfaFactory := factory.NewBaseFactory(
		metadata.ProviderTypeMFA,
		func(id string, config interface{}) (metadata.Provider, error) {
			if id == "totp-mfa" {
				return &MockMFAProvider{
					MockProvider: MockProvider{
						meta: totpMFAMeta,
					},
				}, nil
			}
			return nil, metadata.NewProviderError(id, string(metadata.ProviderTypeMFA), "unknown provider")
		},
		[]metadata.ProviderMetadata{totpMFAMeta},
	)
	
	// Register factories
	if err := factoryReg.RegisterFactory("auth-factory", authFactory); err != nil {
		t.Fatalf("Failed to register auth factory: %v", err)
	}
	
	if err := factoryReg.RegisterFactory("mfa-factory", mfaFactory); err != nil {
		t.Fatalf("Failed to register MFA factory: %v", err)
	}
	
	// Test listing available providers
	t.Run("List available providers", func(t *testing.T) {
		// List available auth providers
		authProviders, err := discoveryService.ListAvailableAuthProviders()
		if err != nil {
			t.Errorf("Failed to list available auth providers: %v", err)
		}
		
		if len(authProviders) != 2 {
			t.Errorf("Expected 2 available auth providers, got %d", len(authProviders))
		}
		
		// List available MFA providers
		mfaProviders, err := discoveryService.ListAvailableMFAProviders()
		if err != nil {
			t.Errorf("Failed to list available MFA providers: %v", err)
		}
		
		if len(mfaProviders) != 1 {
			t.Errorf("Expected 1 available MFA provider, got %d", len(mfaProviders))
		}
	})
	
	// Test creating providers
	t.Run("Create providers", func(t *testing.T) {
		// Create an auth provider
		authProvider, err := discoveryService.CreateAuthProvider("auth-factory", "basic-auth", nil)
		if err != nil {
			t.Errorf("Failed to create auth provider: %v", err)
		}
		
		if authProvider.GetMetadata().ID != "basic-auth" {
			t.Errorf("Created auth provider has wrong ID: %s, expected: basic-auth", 
				authProvider.GetMetadata().ID)
		}
		
		// Test the auth provider functionality
		creds := metadata.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpass",
		}
		
		if !authProvider.Supports(creds) {
			t.Errorf("Auth provider should support username/password credentials")
		}
		
		userID, err := authProvider.Authenticate(context.Background(), creds)
		if err != nil {
			t.Errorf("Auth provider authentication failed: %v", err)
		}
		
		if userID != "user-123" {
			t.Errorf("Expected user ID user-123, got %s", userID)
		}
		
		// Create an MFA provider
		mfaProvider, err := discoveryService.CreateMFAProvider("mfa-factory", "totp-mfa", nil)
		if err != nil {
			t.Errorf("Failed to create MFA provider: %v", err)
		}
		
		if mfaProvider.GetMetadata().ID != "totp-mfa" {
			t.Errorf("Created MFA provider has wrong ID: %s, expected: totp-mfa", 
				mfaProvider.GetMetadata().ID)
		}
		
		// Test the MFA provider functionality
		setupData, err := mfaProvider.Setup(context.Background(), "user-123")
		if err != nil {
			t.Errorf("MFA provider setup failed: %v", err)
		}
		
		if setupData.Secret != "test-secret" {
			t.Errorf("Expected secret test-secret, got %s", setupData.Secret)
		}
		
		// Test MFA verification
		valid, err := mfaProvider.Verify(context.Background(), "user-123", "123456")
		if err != nil {
			t.Errorf("MFA provider verification failed: %v", err)
		}
		
		if !valid {
			t.Errorf("Expected valid MFA code, got invalid")
		}
		
		// Test generating backup codes
		codes, err := mfaProvider.GenerateBackupCodes(context.Background(), "user-123", 5)
		if err != nil {
			t.Errorf("Failed to generate backup codes: %v", err)
		}
		
		if len(codes) != 5 {
			t.Errorf("Expected 5 backup codes, got %d", len(codes))
		}
	})
	
	// Test listing registered providers (should be empty initially)
	t.Run("List registered providers", func(t *testing.T) {
		_, err := discoveryService.ListAuthProviders()
		if err == nil {
			t.Errorf("Expected error when listing non-existent auth providers")
		}
		
		_, err = discoveryService.ListMFAProviders()
		if err == nil {
			t.Errorf("Expected error when listing non-existent MFA providers")
		}
	})
	
	// Register providers
	t.Run("Register providers", func(t *testing.T) {
		// Create providers
		authProvider, err := discoveryService.CreateAuthProvider("auth-factory", "basic-auth", nil)
		if err != nil {
			t.Fatalf("Failed to create auth provider: %v", err)
		}
		
		mfaProvider, err := discoveryService.CreateMFAProvider("mfa-factory", "totp-mfa", nil)
		if err != nil {
			t.Fatalf("Failed to create MFA provider: %v", err)
		}
		
		// Register providers
		if err := reg.RegisterProvider(authProvider); err != nil {
			t.Errorf("Failed to register auth provider: %v", err)
		}
		
		if err := reg.RegisterProvider(mfaProvider); err != nil {
			t.Errorf("Failed to register MFA provider: %v", err)
		}
		
		// List registered providers
		registeredAuthProviders, err := discoveryService.ListAuthProviders()
		if err != nil {
			t.Errorf("Failed to list registered auth providers: %v", err)
		}
		
		if len(registeredAuthProviders) != 1 {
			t.Errorf("Expected 1 registered auth provider, got %d", len(registeredAuthProviders))
		}
		
		registeredMFAProviders, err := discoveryService.ListMFAProviders()
		if err != nil {
			t.Errorf("Failed to list registered MFA providers: %v", err)
		}
		
		if len(registeredMFAProviders) != 1 {
			t.Errorf("Expected 1 registered MFA provider, got %d", len(registeredMFAProviders))
		}
	})
	
	// Test factory access
	t.Run("Factory access", func(t *testing.T) {
		// Get auth provider factories
		authFactories, err := discoveryService.GetAuthProviderFactories()
		if err != nil {
			t.Errorf("Failed to get auth provider factories: %v", err)
		}
		
		if len(authFactories) != 1 {
			t.Errorf("Expected 1 auth provider factory, got %d", len(authFactories))
		}
		
		// Get MFA provider factories
		mfaFactories, err := discoveryService.GetMFAProviderFactories()
		if err != nil {
			t.Errorf("Failed to get MFA provider factories: %v", err)
		}
		
		if len(mfaFactories) != 1 {
			t.Errorf("Expected 1 MFA provider factory, got %d", len(mfaFactories))
		}
	})
}