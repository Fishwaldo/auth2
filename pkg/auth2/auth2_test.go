package auth2_test

import (
	"context"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/auth2"
	"github.com/Fishwaldo/auth2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name          string
		config        *config.Config
		expectError   bool
		errorContains string
	}{
		{
			name:        "with nil config uses default",
			config:      nil,
			expectError: false,
		},
		{
			name:        "with valid config",
			config:      config.DefaultConfig(),
			expectError: false,
		},
		{
			name: "with invalid config",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Logging.Level = "invalid" // Invalid log level
				return cfg
			}(),
			expectError:   true,
			errorContains: "must be one of: debug, info, warn, error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := auth2.New(tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, auth)
			} else {
				require.NoError(t, err)
				require.NotNil(t, auth)
				
				// Verify config and logger are set
				assert.NotNil(t, auth.Config())
				assert.NotNil(t, auth.Logger())
			}
		})
	}
}

func TestAuth2_Config(t *testing.T) {
	cfg := config.DefaultConfig()
	auth, err := auth2.New(cfg)
	require.NoError(t, err)
	
	// Should return the same config
	assert.Equal(t, cfg, auth.Config())
}

func TestAuth2_Logger(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)
	
	// Should have a logger
	logger := auth.Logger()
	assert.NotNil(t, logger)
}

func TestAuth2_RegisterProvider(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	// Define test provider types
	type AuthProvider interface{}
	type StorageProvider interface{}

	tests := []struct {
		name         string
		providerName string
		providerType interface{}
		provider     interface{}
		expectError  bool
	}{
		{
			name:         "register auth provider",
			providerName: "basic",
			providerType: (*AuthProvider)(nil),
			provider:     "mock-auth-provider",
			expectError:  false,
		},
		{
			name:         "register storage provider",
			providerName: "memory",
			providerType: (*StorageProvider)(nil),
			provider:     "mock-storage-provider",
			expectError:  false,
		},
		{
			name:         "register duplicate provider",
			providerName: "basic",
			providerType: (*AuthProvider)(nil),
			provider:     "another-auth-provider",
			expectError:  true,
		},
		{
			name:         "register same name different type",
			providerName: "basic",
			providerType: (*StorageProvider)(nil),
			provider:     "storage-provider-named-basic",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.RegisterProvider(tt.providerName, tt.providerType, tt.provider)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "provider already registered")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuth2_GetProvider(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	// Define test provider types
	type AuthProvider interface{}
	type StorageProvider interface{}

	// Register some providers
	authProvider := "mock-auth-provider"
	storageProvider := "mock-storage-provider"
	
	err = auth.RegisterProvider("basic", (*AuthProvider)(nil), authProvider)
	require.NoError(t, err)
	
	err = auth.RegisterProvider("memory", (*StorageProvider)(nil), storageProvider)
	require.NoError(t, err)

	tests := []struct {
		name           string
		providerName   string
		providerType   interface{}
		expectError    bool
		expectedResult interface{}
	}{
		{
			name:           "get existing auth provider",
			providerName:   "basic",
			providerType:   (*AuthProvider)(nil),
			expectError:    false,
			expectedResult: authProvider,
		},
		{
			name:           "get existing storage provider",
			providerName:   "memory",
			providerType:   (*StorageProvider)(nil),
			expectError:    false,
			expectedResult: storageProvider,
		},
		{
			name:         "get non-existent provider",
			providerName: "oauth",
			providerType: (*AuthProvider)(nil),
			expectError:  true,
		},
		{
			name:         "get provider with wrong type",
			providerName: "basic",
			providerType: (*StorageProvider)(nil),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auth.GetProvider(tt.providerName, tt.providerType)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "provider not registered")
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestAuth2_UnregisterProvider(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	// Define test provider type
	type AuthProvider interface{}

	// Register a provider first
	err = auth.RegisterProvider("basic", (*AuthProvider)(nil), "mock-provider")
	require.NoError(t, err)

	tests := []struct {
		name         string
		providerName string
		providerType interface{}
		expectError  bool
	}{
		{
			name:         "unregister existing provider",
			providerName: "basic",
			providerType: (*AuthProvider)(nil),
			expectError:  false,
		},
		{
			name:         "unregister non-existent provider",
			providerName: "oauth",
			providerType: (*AuthProvider)(nil),
			expectError:  true,
		},
		{
			name:         "unregister already unregistered provider",
			providerName: "basic",
			providerType: (*AuthProvider)(nil),
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auth.UnregisterProvider(tt.providerName, tt.providerType)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "provider not registered")
			} else {
				assert.NoError(t, err)
				
				// Verify provider is actually removed
				_, err := auth.GetProvider(tt.providerName, tt.providerType)
				assert.Error(t, err)
			}
		})
	}
}

func TestAuth2_Context(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	// Create context with auth2 instance
	ctx := auth.Context(context.Background())
	
	// Retrieve auth2 instance from context
	retrievedAuth, ok := auth2.FromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, auth, retrievedAuth)
}

func TestFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		setup    func() context.Context
		wantAuth bool
	}{
		{
			name: "context with auth2",
			setup: func() context.Context {
				auth, _ := auth2.New(nil)
				return auth.Context(context.Background())
			},
			wantAuth: true,
		},
		{
			name:     "context without auth2",
			ctx:      context.Background(),
			wantAuth: false,
		},
		{
			name: "context with wrong type",
			setup: func() context.Context {
				type wrongKey struct{}
				return context.WithValue(context.Background(), wrongKey{}, "not-auth2")
			},
			wantAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.ctx
			if tt.setup != nil {
				ctx = tt.setup()
			}
			
			auth, ok := auth2.FromContext(ctx)
			
			if tt.wantAuth {
				assert.True(t, ok)
				assert.NotNil(t, auth)
			} else {
				assert.False(t, ok)
				assert.Nil(t, auth)
			}
		})
	}
}

func TestAuth2_Initialize(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = auth.Initialize(ctx)
	assert.NoError(t, err)
}

func TestAuth2_Shutdown(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	ctx := context.Background()
	err = auth.Shutdown(ctx)
	assert.NoError(t, err)
}

// Test concurrent operations
func TestAuth2_ConcurrentOperations(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	type TestProvider interface{}

	// Run concurrent operations
	done := make(chan bool)
	errors := make(chan error, 100)

	// Register providers concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			err := auth.RegisterProvider(
				"provider"+string(rune('0'+id)),
				(*TestProvider)(nil),
				"mock-provider",
			)
			if err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Get providers concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			_, _ = auth.GetProvider(
				"provider"+string(rune('0'+id)),
				(*TestProvider)(nil),
			)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 20; i++ {
		<-done
	}

	close(errors)
	
	// Check for any errors
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

// Test provider type key generation
func TestProviderTypeHandling(t *testing.T) {
	auth, err := auth2.New(nil)
	require.NoError(t, err)

	// Test with nil provider type
	err = auth.RegisterProvider("test", nil, "mock-provider")
	assert.NoError(t, err)

	// Should be able to retrieve with nil type
	provider, err := auth.GetProvider("test", nil)
	assert.NoError(t, err)
	assert.Equal(t, "mock-provider", provider)

	// Test with different types but same name
	type Type1 interface{}
	type Type2 interface{}

	err = auth.RegisterProvider("multi", (*Type1)(nil), "provider1")
	assert.NoError(t, err)

	err = auth.RegisterProvider("multi", (*Type2)(nil), "provider2")
	assert.NoError(t, err)

	// Should get different providers for different types
	p1, err := auth.GetProvider("multi", (*Type1)(nil))
	assert.NoError(t, err)
	assert.Equal(t, "provider1", p1)

	p2, err := auth.GetProvider("multi", (*Type2)(nil))
	assert.NoError(t, err)
	assert.Equal(t, "provider2", p2)
}