package webauthn_test

import (
	"testing"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/auth/providers/webauthn"
	"github.com/Fishwaldo/auth2/pkg/plugin/factory"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestFactory_Create(t *testing.T) {
	mockStore := &mockStateStore{}
	defaultConfig := &webauthn.Config{
		RPDisplayName: "Default App",
		RPID:          "default.com",
		RPOrigins:     []string{"https://default.com"},
		StateStore:    mockStore,
	}
	
	factory := webauthn.NewFactory(defaultConfig)
	
	tests := []struct {
		name          string
		config        interface{}
		expectedError string
		validate      func(*testing.T, metadata.Provider)
	}{
		{
			name: "valid *Config",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "test.com",
				RPOrigins:     []string{"https://test.com"},
				StateStore:    mockStore,
			},
			expectedError: "",
			validate: func(t *testing.T, p metadata.Provider) {
				assert.NotNil(t, p)
				// Verify it implements both interfaces
				_, isAuth := p.(providers.AuthProvider)
				assert.True(t, isAuth)
				_, isMFA := p.(metadata.MFAProvider)
				assert.True(t, isMFA)
			},
		},
		{
			name: "valid Config value",
			config: webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "test.com",
				RPOrigins:     []string{"https://test.com"},
				StateStore:    mockStore,
			},
			expectedError: "",
			validate: func(t *testing.T, p metadata.Provider) {
				assert.NotNil(t, p)
			},
		},
		{
			name: "valid map config",
			config: map[string]interface{}{
				"rp_display_name": "Map App",
				"rp_id":           "map.com",
				"rp_origins":      []string{"https://map.com"},
				"state_store":     mockStore,
			},
			expectedError: "",
			validate: func(t *testing.T, p metadata.Provider) {
				assert.NotNil(t, p)
			},
		},
		{
			name: "map config with interface origins",
			config: map[string]interface{}{
				"rp_display_name": "Map App",
				"rp_id":           "map.com",
				"rp_origins":      []interface{}{"https://map.com", "https://www.map.com"},
				"state_store":     mockStore,
			},
			expectedError: "",
			validate: func(t *testing.T, p metadata.Provider) {
				assert.NotNil(t, p)
			},
		},
		{
			name:          "nil config uses default",
			config:        nil,
			expectedError: "",
			validate: func(t *testing.T, p metadata.Provider) {
				assert.NotNil(t, p)
			},
		},
		{
			name: "missing state store",
			config: &webauthn.Config{
				RPDisplayName: "Test App",
				RPID:          "test.com",
				RPOrigins:     []string{"https://test.com"},
				// No StateStore
			},
			expectedError: "state_store is required",
		},
		{
			name:          "unsupported config type",
			config:        "invalid",
			expectedError: "unsupported config type",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.Create(tt.config)
			
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, provider)
				}
			}
		})
	}
}

func TestFactory_GetType(t *testing.T) {
	factory := webauthn.NewFactory(nil)
	assert.Equal(t, metadata.ProviderTypeAuth, factory.GetType())
}

func TestFactory_GetMetadata(t *testing.T) {
	factory := webauthn.NewFactory(nil)
	meta := factory.GetMetadata()
	
	assert.Equal(t, "webauthn", meta.ID)
	assert.Equal(t, metadata.ProviderTypeAuth, meta.Type)
	assert.Equal(t, "WebAuthn", meta.Name)
	assert.Contains(t, meta.Description, "WebAuthn/FIDO2")
	assert.Equal(t, "1.0.0", meta.Version)
	assert.Equal(t, "auth2", meta.Author)
}

// Mock Registry for testing
type mockRegistry struct {
	mock.Mock
}

func (m *mockRegistry) RegisterAuthProvider(provider providers.AuthProvider) error {
	args := m.Called(provider)
	return args.Error(0)
}

func (m *mockRegistry) RegisterAuthProviderFactory(id string, factory factory.Factory) error {
	args := m.Called(id, factory)
	return args.Error(0)
}

func (m *mockRegistry) GetAuthProvider(id string) (providers.AuthProvider, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(providers.AuthProvider), args.Error(1)
}

func (m *mockRegistry) GetAuthProviderFactory(id string) (factory.Factory, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(factory.Factory), args.Error(1)
}

func (m *mockRegistry) ListAuthProviders() []metadata.ProviderMetadata {
	args := m.Called()
	return args.Get(0).([]metadata.ProviderMetadata)
}

func (m *mockRegistry) RegisterMFAProvider(provider metadata.MFAProvider) error {
	args := m.Called(provider)
	return args.Error(0)
}

func (m *mockRegistry) RegisterMFAProviderFactory(id string, factory factory.Factory) error {
	args := m.Called(id, factory)
	return args.Error(0)
}

func (m *mockRegistry) GetMFAProvider(id string) (metadata.MFAProvider, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(metadata.MFAProvider), args.Error(1)
}

func (m *mockRegistry) GetMFAProviderFactory(id string) (factory.Factory, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(factory.Factory), args.Error(1)
}

func (m *mockRegistry) ListMFAProviders() []metadata.ProviderMetadata {
	args := m.Called()
	return args.Get(0).([]metadata.ProviderMetadata)
}

func (m *mockRegistry) RegisterStorageProvider(provider metadata.StorageProvider) error {
	args := m.Called(provider)
	return args.Error(0)
}

func (m *mockRegistry) RegisterStorageProviderFactory(id string, factory factory.Factory) error {
	args := m.Called(id, factory)
	return args.Error(0)
}

func (m *mockRegistry) GetStorageProvider(id string) (metadata.StorageProvider, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(metadata.StorageProvider), args.Error(1)
}

func (m *mockRegistry) GetStorageProviderFactory(id string) (factory.Factory, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(factory.Factory), args.Error(1)
}

func (m *mockRegistry) ListStorageProviders() []metadata.ProviderMetadata {
	args := m.Called()
	return args.Get(0).([]metadata.ProviderMetadata)
}

func (m *mockRegistry) RegisterHTTPProvider(provider metadata.HTTPProvider) error {
	args := m.Called(provider)
	return args.Error(0)
}

func (m *mockRegistry) RegisterHTTPProviderFactory(id string, factory factory.Factory) error {
	args := m.Called(id, factory)
	return args.Error(0)
}

func (m *mockRegistry) GetHTTPProvider(id string) (metadata.HTTPProvider, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(metadata.HTTPProvider), args.Error(1)
}

func (m *mockRegistry) GetHTTPProviderFactory(id string) (factory.Factory, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(factory.Factory), args.Error(1)
}

func (m *mockRegistry) ListHTTPProviders() []metadata.ProviderMetadata {
	args := m.Called()
	return args.Get(0).([]metadata.ProviderMetadata)
}

// TestRegister is removed as the actual registry doesn't support factory methods

func TestCreateAuthProvider(t *testing.T) {
	mockStore := &mockStateStore{}
	config := &webauthn.Config{
		RPDisplayName: "Test App",
		RPID:          "test.com",
		RPOrigins:     []string{"https://test.com"},
		StateStore:    mockStore,
	}
	
	provider, err := webauthn.CreateAuthProvider(config)
	
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	
	// Verify it's an AuthProvider
	_, ok := provider.(providers.AuthProvider)
	assert.True(t, ok)
}

func TestCreateMFAProvider(t *testing.T) {
	mockStore := &mockStateStore{}
	config := &webauthn.Config{
		RPDisplayName: "Test App",
		RPID:          "test.com",
		RPOrigins:     []string{"https://test.com"},
		StateStore:    mockStore,
	}
	
	provider, err := webauthn.CreateMFAProvider(config)
	
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	
	// Verify it's an MFAProvider
	_, ok := provider.(metadata.MFAProvider)
	assert.True(t, ok)
}

func TestCreateDualModeProvider(t *testing.T) {
	mockStore := &mockStateStore{}
	config := &webauthn.Config{
		RPDisplayName: "Test App",
		RPID:          "test.com",
		RPOrigins:     []string{"https://test.com"},
		StateStore:    mockStore,
	}
	
	provider, err := webauthn.CreateDualModeProvider(config)
	
	assert.NoError(t, err)
	assert.NotNil(t, provider)
	
	// Verify it implements both interfaces
	_, isAuth := interface{}(provider).(providers.AuthProvider)
	assert.True(t, isAuth)
	
	_, isMFA := interface{}(provider).(metadata.MFAProvider)
	assert.True(t, isMFA)
}