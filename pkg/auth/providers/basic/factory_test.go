package basic_test

import (
	"context"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/auth/providers/basic"
	"github.com/Fishwaldo/auth2/pkg/plugin/factory"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewFactory(t *testing.T) {
	mockStore := &mockUserStore{}
	mockPwdUtils := &mockPasswordUtils{}
	
	factory := basic.NewFactory(mockStore, mockPwdUtils)
	
	assert.NotNil(t, factory)
}

func TestFactory_Create(t *testing.T) {
	mockStore := &mockUserStore{}
	mockPwdUtils := &mockPasswordUtils{}
	factory := basic.NewFactory(mockStore, mockPwdUtils)

	tests := []struct {
		name          string
		id            string
		config        interface{}
		expectError   bool
		errorContains string
		validate      func(*testing.T, metadata.Provider)
	}{
		{
			name:   "create with Config struct",
			id:     "test-provider",
			config: &basic.Config{
				AccountLockThreshold: 10,
				AccountLockDuration:  60,
				RequireVerifiedEmail: true,
			},
			expectError: false,
			validate: func(t *testing.T, p metadata.Provider) {
				authProvider, ok := p.(*basic.Provider)
				require.True(t, ok)
				assert.NotNil(t, authProvider)
			},
		},
		{
			name:        "create with nil config",
			id:          "test-provider",
			config:      nil,
			expectError: false,
			validate: func(t *testing.T, p metadata.Provider) {
				authProvider, ok := p.(*basic.Provider)
				require.True(t, ok)
				assert.NotNil(t, authProvider)
			},
		},
		{
			name:   "create with map config",
			id:     "test-provider",
			config: map[string]interface{}{
				"account_lock_threshold": 15,
				"account_lock_duration":  120,
				"require_verified_email": false,
			},
			expectError: false,
			validate: func(t *testing.T, p metadata.Provider) {
				authProvider, ok := p.(*basic.Provider)
				require.True(t, ok)
				assert.NotNil(t, authProvider)
			},
		},
		{
			name:   "create with map config - partial values",
			id:     "test-provider",
			config: map[string]interface{}{
				"account_lock_threshold": 20,
			},
			expectError: false,
			validate: func(t *testing.T, p metadata.Provider) {
				authProvider, ok := p.(*basic.Provider)
				require.True(t, ok)
				assert.NotNil(t, authProvider)
			},
		},
		{
			name:   "create with map config - wrong types",
			id:     "test-provider",
			config: map[string]interface{}{
				"account_lock_threshold": "not an int",
				"account_lock_duration":  "not an int",
				"require_verified_email": "not a bool",
			},
			expectError: false, // Should not error, just use defaults
			validate: func(t *testing.T, p metadata.Provider) {
				authProvider, ok := p.(*basic.Provider)
				require.True(t, ok)
				assert.NotNil(t, authProvider)
			},
		},
		{
			name:          "create with invalid config type",
			id:            "test-provider",
			config:        "invalid config",
			expectError:   true,
			errorContains: "invalid configuration type",
		},
		{
			name:          "create with invalid config struct",
			id:            "test-provider",
			config:        struct{ Field string }{Field: "value"},
			expectError:   true,
			errorContains: "invalid configuration type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.Create(tt.id, tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, provider)
			} else {
				require.NoError(t, err)
				require.NotNil(t, provider)
				if tt.validate != nil {
					tt.validate(t, provider)
				}
			}
		})
	}
}

func TestFactory_GetType(t *testing.T) {
	mockStore := &mockUserStore{}
	mockPwdUtils := &mockPasswordUtils{}
	factory := basic.NewFactory(mockStore, mockPwdUtils)
	
	providerType := factory.GetType()
	assert.Equal(t, metadata.ProviderTypeAuth, providerType)
}

func TestFactory_GetMetadata(t *testing.T) {
	mockStore := &mockUserStore{}
	mockPwdUtils := &mockPasswordUtils{}
	factory := basic.NewFactory(mockStore, mockPwdUtils)
	
	metadataList := factory.GetMetadata()
	
	assert.Len(t, metadataList, 1)
	
	md := metadataList[0]
	assert.Equal(t, "basic", md.ID)
	assert.Equal(t, metadata.ProviderTypeAuth, md.Type)
	assert.Equal(t, basic.ProviderName, md.Name)
	assert.Equal(t, basic.ProviderDescription, md.Description)
	assert.Equal(t, basic.ProviderVersion, md.Version)
}

func TestRegister(t *testing.T) {
	mockRegistry := &mockRegistry{}
	mockStore := &mockUserStore{}
	mockPwdUtils := &mockPasswordUtils{}

	// Set up expectation
	mockRegistry.On("RegisterAuthProviderFactory", "basic", mock.AnythingOfType("*basic.Factory")).Return(nil)

	err := basic.Register(mockRegistry, mockStore, mockPwdUtils)
	assert.NoError(t, err)
	
	mockRegistry.AssertExpectations(t)
}

func TestRegister_Error(t *testing.T) {
	mockRegistry := &mockRegistry{}
	mockStore := &mockUserStore{}
	mockPwdUtils := &mockPasswordUtils{}

	// Set up expectation for error
	expectedErr := assert.AnError
	mockRegistry.On("RegisterAuthProviderFactory", "basic", mock.AnythingOfType("*basic.Factory")).Return(expectedErr)

	err := basic.Register(mockRegistry, mockStore, mockPwdUtils)
	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	
	mockRegistry.AssertExpectations(t)
}

// Mock Registry for testing
type mockRegistry struct {
	mock.Mock
}

func (m *mockRegistry) RegisterAuthProvider(provider providers.AuthProvider) error {
	args := m.Called(provider)
	return args.Error(0)
}

func (m *mockRegistry) GetAuthProvider(id string) (providers.AuthProvider, error) {
	args := m.Called(id)
	if args.Get(0) != nil {
		return args.Get(0).(providers.AuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockRegistry) RegisterAuthProviderFactory(id string, factory factory.Factory) error {
	args := m.Called(id, factory)
	return args.Error(0)
}

func (m *mockRegistry) GetAuthProviderFactory(id string) (factory.Factory, error) {
	args := m.Called(id)
	if args.Get(0) != nil {
		return args.Get(0).(factory.Factory), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockRegistry) ListAuthProviders() []providers.AuthProvider {
	args := m.Called()
	if args.Get(0) != nil {
		return args.Get(0).([]providers.AuthProvider)
	}
	return nil
}

func (m *mockRegistry) CreateAuthProvider(ctx context.Context, factoryID, providerID string, config interface{}) (providers.AuthProvider, error) {
	args := m.Called(ctx, factoryID, providerID, config)
	if args.Get(0) != nil {
		return args.Get(0).(providers.AuthProvider), args.Error(1)
	}
	return nil, args.Error(1)
}