package providers_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock AuthProvider
type mockAuthProvider struct {
	mock.Mock
}

func (m *mockAuthProvider) GetMetadata() metadata.ProviderMetadata {
	args := m.Called()
	return args.Get(0).(metadata.ProviderMetadata)
}

func (m *mockAuthProvider) Authenticate(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
	args := m.Called(ctx, credentials)
	if result := args.Get(0); result != nil {
		return result.(*providers.AuthResult), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockAuthProvider) Initialize(ctx context.Context, config interface{}) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *mockAuthProvider) Shutdown(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockAuthProvider) GetRequiredFields() []string {
	args := m.Called()
	if fields := args.Get(0); fields != nil {
		return fields.([]string)
	}
	return nil
}

func (m *mockAuthProvider) ValidateCredentials(credentials interface{}) error {
	args := m.Called(credentials)
	return args.Error(0)
}

func (m *mockAuthProvider) Supports(credentials interface{}) bool {
	args := m.Called(credentials)
	return args.Bool(0)
}

func (m *mockAuthProvider) Validate(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockAuthProvider) IsCompatibleVersion(version string) bool {
	args := m.Called(version)
	return args.Bool(0)
}

// Mock metadata.Provider (not AuthProvider)
type mockMetadataProvider struct {
	mock.Mock
}

func (m *mockMetadataProvider) GetMetadata() metadata.ProviderMetadata {
	args := m.Called()
	return args.Get(0).(metadata.ProviderMetadata)
}

func (m *mockMetadataProvider) Initialize(ctx context.Context, config interface{}) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *mockMetadataProvider) Validate(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockMetadataProvider) IsCompatibleVersion(version string) bool {
	args := m.Called(version)
	return args.Bool(0)
}

// Mock Factory
type mockFactory struct {
	mock.Mock
}

func (m *mockFactory) Create(id string, config interface{}) (metadata.Provider, error) {
	args := m.Called(id, config)
	if result := args.Get(0); result != nil {
		return result.(metadata.Provider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockFactory) GetType() metadata.ProviderType {
	args := m.Called()
	return args.Get(0).(metadata.ProviderType)
}

func (m *mockFactory) GetMetadata() []metadata.ProviderMetadata {
	args := m.Called()
	if result := args.Get(0); result != nil {
		return result.([]metadata.ProviderMetadata)
	}
	return nil
}

func TestNewDefaultRegistry(t *testing.T) {
	registry := providers.NewDefaultRegistry()
	assert.NotNil(t, registry)
	
	// Test that the registry starts empty
	providers := registry.ListAuthProviders()
	assert.Empty(t, providers)
}

func TestDefaultRegistry_RegisterAuthProvider(t *testing.T) {
	tests := []struct {
		name          string
		setupRegistry func() *providers.DefaultRegistry
		provider      func() providers.AuthProvider
		expectError   bool
		errorContains string
	}{
		{
			name: "register new provider",
			setupRegistry: func() *providers.DefaultRegistry {
				return providers.NewDefaultRegistry()
			},
			provider: func() providers.AuthProvider {
				mockProvider := new(mockAuthProvider)
				mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
					ID:   "test-provider",
					Name: "Test Provider",
				})
				return mockProvider
			},
			expectError: false,
		},
		{
			name: "register duplicate provider",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				// Register first provider
				mockProvider := new(mockAuthProvider)
				mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
					ID:   "test-provider",
					Name: "Test Provider",
				})
				registry.RegisterAuthProvider(mockProvider)
				return registry
			},
			provider: func() providers.AuthProvider {
				mockProvider := new(mockAuthProvider)
				mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
					ID:   "test-provider",
					Name: "Another Test Provider",
				})
				return mockProvider
			},
			expectError:   true,
			errorContains: "provider already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := tt.setupRegistry()
			provider := tt.provider()
			
			err := registry.RegisterAuthProvider(provider)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultRegistry_GetAuthProvider(t *testing.T) {
	tests := []struct {
		name          string
		setupRegistry func() *providers.DefaultRegistry
		providerID    string
		expectError   bool
		errorContains string
	}{
		{
			name: "get existing provider",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				mockProvider := new(mockAuthProvider)
				mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
					ID:   "test-provider",
					Name: "Test Provider",
				})
				registry.RegisterAuthProvider(mockProvider)
				return registry
			},
			providerID:  "test-provider",
			expectError: false,
		},
		{
			name: "get non-existent provider",
			setupRegistry: func() *providers.DefaultRegistry {
				return providers.NewDefaultRegistry()
			},
			providerID:    "non-existent",
			expectError:   true,
			errorContains: "provider not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := tt.setupRegistry()
			
			provider, err := registry.GetAuthProvider(tt.providerID)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestDefaultRegistry_RegisterAuthProviderFactory(t *testing.T) {
	tests := []struct {
		name          string
		setupRegistry func() *providers.DefaultRegistry
		factoryID     string
		factory       func() *mockFactory
		expectError   bool
		errorContains string
	}{
		{
			name: "register new factory",
			setupRegistry: func() *providers.DefaultRegistry {
				return providers.NewDefaultRegistry()
			},
			factoryID: "test-factory",
			factory: func() *mockFactory {
				return new(mockFactory)
			},
			expectError: false,
		},
		{
			name: "register duplicate factory",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				// Register first factory
				registry.RegisterAuthProviderFactory("test-factory", new(mockFactory))
				return registry
			},
			factoryID: "test-factory",
			factory: func() *mockFactory {
				return new(mockFactory)
			},
			expectError:   true,
			errorContains: "factory already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := tt.setupRegistry()
			factory := tt.factory()
			
			err := registry.RegisterAuthProviderFactory(tt.factoryID, factory)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultRegistry_GetAuthProviderFactory(t *testing.T) {
	tests := []struct {
		name          string
		setupRegistry func() *providers.DefaultRegistry
		factoryID     string
		expectError   bool
		errorContains string
	}{
		{
			name: "get existing factory",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				registry.RegisterAuthProviderFactory("test-factory", new(mockFactory))
				return registry
			},
			factoryID:   "test-factory",
			expectError: false,
		},
		{
			name: "get non-existent factory",
			setupRegistry: func() *providers.DefaultRegistry {
				return providers.NewDefaultRegistry()
			},
			factoryID:     "non-existent",
			expectError:   true,
			errorContains: "factory not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := tt.setupRegistry()
			
			factory, err := registry.GetAuthProviderFactory(tt.factoryID)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, factory)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, factory)
			}
		})
	}
}

func TestDefaultRegistry_ListAuthProviders(t *testing.T) {
	registry := providers.NewDefaultRegistry()
	
	// Initially empty
	providers := registry.ListAuthProviders()
	assert.Empty(t, providers)
	
	// Add some providers
	provider1 := new(mockAuthProvider)
	provider1.On("GetMetadata").Return(metadata.ProviderMetadata{
		ID:   "provider1",
		Name: "Provider 1",
	})
	registry.RegisterAuthProvider(provider1)
	
	provider2 := new(mockAuthProvider)
	provider2.On("GetMetadata").Return(metadata.ProviderMetadata{
		ID:   "provider2",
		Name: "Provider 2",
	})
	registry.RegisterAuthProvider(provider2)
	
	// List should now contain both providers
	providers = registry.ListAuthProviders()
	assert.Len(t, providers, 2)
	
	// Verify both providers are in the list
	providerIDs := make(map[string]bool)
	for _, p := range providers {
		providerIDs[p.GetMetadata().ID] = true
	}
	assert.True(t, providerIDs["provider1"])
	assert.True(t, providerIDs["provider2"])
}

func TestDefaultRegistry_CreateAuthProvider(t *testing.T) {
	tests := []struct {
		name          string
		setupRegistry func() *providers.DefaultRegistry
		factoryID     string
		providerID    string
		config        interface{}
		expectError   bool
		errorContains string
	}{
		{
			name: "create provider with existing factory",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				mockFactory := new(mockFactory)
				mockProvider := new(mockAuthProvider)
				mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
					ID:   "created-provider",
					Name: "Created Provider",
				})
				mockFactory.On("Create", "created-provider", mock.Anything).Return(mockProvider, nil)
				registry.RegisterAuthProviderFactory("test-factory", mockFactory)
				return registry
			},
			factoryID:   "test-factory",
			providerID:  "created-provider",
			config:      map[string]interface{}{"key": "value"},
			expectError: false,
		},
		{
			name: "create provider with non-existent factory",
			setupRegistry: func() *providers.DefaultRegistry {
				return providers.NewDefaultRegistry()
			},
			factoryID:     "non-existent",
			providerID:    "test-provider",
			config:        nil,
			expectError:   true,
			errorContains: "factory not found",
		},
		{
			name: "factory create error",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				mockFactory := new(mockFactory)
				mockFactory.On("Create", "test-provider", mock.Anything).Return(nil, errors.New("creation failed"))
				registry.RegisterAuthProviderFactory("test-factory", mockFactory)
				return registry
			},
			factoryID:     "test-factory",
			providerID:    "test-provider",
			config:        nil,
			expectError:   true,
			errorContains: "failed to create provider",
		},
		{
			name: "factory returns wrong type",
			setupRegistry: func() *providers.DefaultRegistry {
				registry := providers.NewDefaultRegistry()
				mockFactory := new(mockFactory)
				// Return a mock that implements metadata.Provider but not AuthProvider
				mockProvider := new(mockMetadataProvider)
				mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
					ID: "test-provider",
				})
				mockFactory.On("Create", "test-provider", mock.Anything).Return(mockProvider, nil)
				registry.RegisterAuthProviderFactory("test-factory", mockFactory)
				return registry
			},
			factoryID:     "test-factory",
			providerID:    "test-provider",
			config:        nil,
			expectError:   true,
			errorContains: "factory did not return an AuthProvider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := tt.setupRegistry()
			ctx := context.Background()
			
			provider, err := registry.CreateAuthProvider(ctx, tt.factoryID, tt.providerID, tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestDefaultRegistry_ConcurrentOperations(t *testing.T) {
	registry := providers.NewDefaultRegistry()
	
	// Test concurrent provider registration and retrieval
	done := make(chan bool)
	errors := make(chan error, 100)
	
	// Register providers concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			mockProvider := new(mockAuthProvider)
			mockProvider.On("GetMetadata").Return(metadata.ProviderMetadata{
				ID:   fmt.Sprintf("provider-%d", id),
				Name: fmt.Sprintf("Provider %d", id),
			})
			if err := registry.RegisterAuthProvider(mockProvider); err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}
	
	// Get providers concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			_, _ = registry.GetAuthProvider(fmt.Sprintf("provider-%d", id))
			done <- true
		}(i)
	}
	
	// List providers concurrently
	for i := 0; i < 5; i++ {
		go func() {
			_ = registry.ListAuthProviders()
			done <- true
		}()
	}
	
	// Wait for all goroutines
	for i := 0; i < 25; i++ {
		<-done
	}
	
	close(errors)
	
	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
	
	// Verify all providers were registered
	providers := registry.ListAuthProviders()
	assert.Len(t, providers, 10)
}