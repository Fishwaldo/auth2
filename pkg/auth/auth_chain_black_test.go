package auth_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/auth"
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/auth/test"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/plugin/registry"
	"github.com/stretchr/testify/assert"
)

func TestAuthChain(t *testing.T) {
	reg := registry.NewRegistry()
	config := auth.ManagerConfig{
		DefaultProviderID: "default",
		MFARequired:       false,
		MaxLoginAttempts:  5,
		LockoutDuration:   300,
	}
	
	manager := auth.NewManager(reg, config)
	
	// Create test providers
	defaultProvider := test.NewMockAuthProvider(metadata.ProviderMetadata{
		ID:          "default",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "Default Provider",
		Description: "Default provider",
		Author:      "Auth2 Team",
	})
	
	defaultProvider.AuthenticateFunc = func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
		return &providers.AuthResult{
			Success:    true,
			UserID:     "default-user",
			ProviderID: "default",
		}, nil
	}
	
	passwordProvider := test.NewMockAuthProvider(metadata.ProviderMetadata{
		ID:          "password",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "Password Provider",
		Description: "Password-based provider",
		Author:      "Auth2 Team",
	})
	
	passwordProvider.AuthenticateFunc = func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
		// Check if credentials are username/password
		if _, ok := credentials.(providers.UsernamePasswordCredentials); ok {
			return &providers.AuthResult{
				Success:    true,
				UserID:     "password-user",
				ProviderID: "password",
			}, nil
		}
		
		return &providers.AuthResult{
			Success:    false,
			ProviderID: "password",
			Error:      providers.NewAuthFailedError("unsupported credentials", nil),
		}, providers.NewAuthFailedError("unsupported credentials", nil)
	}
	
	passwordProvider.SupportsFunc = func(credentials interface{}) bool {
		_, ok := credentials.(providers.UsernamePasswordCredentials)
		return ok
	}
	
	tokenProvider := test.NewMockAuthProvider(metadata.ProviderMetadata{
		ID:          "token",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "Token Provider",
		Description: "Token-based provider",
		Author:      "Auth2 Team",
	})
	
	tokenProvider.AuthenticateFunc = func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
		// Check if credentials are token credentials
		if _, ok := credentials.(providers.TokenCredentials); ok {
			return &providers.AuthResult{
				Success:    true,
				UserID:     "token-user",
				ProviderID: "token",
			}, nil
		}
		
		return &providers.AuthResult{
			Success:    false,
			ProviderID: "token",
			Error:      providers.NewAuthFailedError("unsupported credentials", nil),
		}, providers.NewAuthFailedError("unsupported credentials", nil)
	}
	
	tokenProvider.SupportsFunc = func(credentials interface{}) bool {
		_, ok := credentials.(providers.TokenCredentials)
		return ok
	}
	
	// Register providers
	err := manager.RegisterProvider(defaultProvider)
	assert.NoError(t, err)
	
	err = manager.RegisterProvider(passwordProvider)
	assert.NoError(t, err)
	
	err = manager.RegisterProvider(tokenProvider)
	assert.NoError(t, err)
	
	t.Run("DefaultProviderHandler", func(t *testing.T) {
		// Override default provider support for this test
		prevSupports := defaultProvider.SupportsFunc
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return true
		}
		
		// Create new chain for this test
		testChain := auth.NewAuthChain(manager)
		testChain.Handler(testChain.DefaultProviderHandler())
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "default-user", result.UserID)
		assert.Equal(t, "default", result.ProviderID)
		
		// Restore original supports function
		defaultProvider.SupportsFunc = prevSupports
	})
	
	t.Run("AllProvidersHandler_Password", func(t *testing.T) {
		// Override default provider support for this test
		prevDefaultSupports := defaultProvider.SupportsFunc
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		// Create new chain for this test
		testChain := auth.NewAuthChain(manager)
		testChain.Handler(testChain.AllProvidersHandler())
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "password-user", result.UserID)
		assert.Equal(t, "password", result.ProviderID)
		
		// Restore original supports function
		defaultProvider.SupportsFunc = prevDefaultSupports
	})
	
	t.Run("AllProvidersHandler_Token", func(t *testing.T) {
		// Override default provider support for this test
		prevDefaultSupports := defaultProvider.SupportsFunc
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		// Create new chain for this test
		testChain := auth.NewAuthChain(manager)
		testChain.Handler(testChain.AllProvidersHandler())
		
		credentials := providers.TokenCredentials{
			TokenType:  "Bearer",
			TokenValue: "test-token",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "token-user", result.UserID)
		assert.Equal(t, "token", result.ProviderID)
		
		// Restore original supports function
		defaultProvider.SupportsFunc = prevDefaultSupports
	})
	
	t.Run("SpecificProviderHandler", func(t *testing.T) {
		// Create new chain for this test
		testChain := auth.NewAuthChain(manager)
		testChain.Handler(testChain.SpecificProviderHandler("token"))
		
		credentials := providers.TokenCredentials{
			TokenType:  "Bearer",
			TokenValue: "test-token",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "token-user", result.UserID)
		assert.Equal(t, "token", result.ProviderID)
	})
	
	t.Run("ChainOfResponsibility", func(t *testing.T) {
		// Configure chain with multiple handlers
		testChain := auth.NewAuthChain(manager)
		testChain.Handler(testChain.SpecificProviderHandler("nonexistent")) // This will fail
		testChain.Handler(testChain.SpecificProviderHandler("token"))       // This will succeed for token credentials
		testChain.Handler(testChain.SpecificProviderHandler("password"))    // This won't be reached for token credentials
		
		// Test with token credentials
		tokenCreds := providers.TokenCredentials{
			TokenType:  "Bearer",
			TokenValue: "test-token",
		}
		
		result, err := testChain.Authenticate(context.Background(), tokenCreds)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "token-user", result.UserID)
		assert.Equal(t, "token", result.ProviderID)
		
		// Test with password credentials
		passwordCreds := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err = testChain.Authenticate(context.Background(), passwordCreds)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "password-user", result.UserID)
		assert.Equal(t, "password", result.ProviderID)
	})
	
	t.Run("EmptyChain", func(t *testing.T) {
		emptyChain := auth.NewAuthChain(manager)
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := emptyChain.Authenticate(context.Background(), credentials)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.True(t, errors.Is(err, errors.ErrServiceUnavailable))
	})
	
	t.Run("AllHandlersFail", func(t *testing.T) {
		// Save original support functions
		prevDefaultSupports := defaultProvider.SupportsFunc
		prevPasswordSupports := passwordProvider.SupportsFunc
		prevTokenSupports := tokenProvider.SupportsFunc
		
		// Configure providers to not support any credentials
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		passwordProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		tokenProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		testChain := auth.NewAuthChain(manager)
		testChain.Handler(testChain.DefaultProviderHandler())
		testChain.Handler(testChain.AllProvidersHandler())
		
		credentials := providers.SAMLCredentials{
			SAMLResponse: "test-response",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		
		// Restore original support functions
		defaultProvider.SupportsFunc = prevDefaultSupports
		passwordProvider.SupportsFunc = prevPasswordSupports
		tokenProvider.SupportsFunc = prevTokenSupports
	})
	
	t.Run("Middleware", func(t *testing.T) {
		var middlewareCalled bool
		
		middleware := func(ctx *providers.AuthContext, credentials providers.Credentials, next auth.AuthHandlerFunc) (*providers.AuthResult, error) {
			middlewareCalled = true
			return next(ctx, credentials, next)
		}
		
		// Override default provider support for this test
		prevSupports := defaultProvider.SupportsFunc
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return true
		}
		
		testChain := auth.NewAuthChain(manager)
		testChain.Use(middleware)
		testChain.Handler(testChain.DefaultProviderHandler())
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.True(t, middlewareCalled)
		
		// Restore original supports function
		defaultProvider.SupportsFunc = prevSupports
	})
	
	t.Run("BuildDefaultChain", func(t *testing.T) {
		// Override supports functions for this test
		prevDefaultSupports := defaultProvider.SupportsFunc
		
		// First test: default provider supports the credentials
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return true
		}
		
		testChain := auth.NewAuthChain(manager).BuildDefaultChain()
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "default-user", result.UserID)
		assert.Equal(t, "default", result.ProviderID)
		
		// Second test: default provider doesn't support the credentials
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		testChain = auth.NewAuthChain(manager).BuildDefaultChain()
		
		result, err = testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "password-user", result.UserID)
		assert.Equal(t, "password", result.ProviderID)
		
		// Restore original supports function
		defaultProvider.SupportsFunc = prevDefaultSupports
	})
	
	t.Run("BuiltInMiddleware", func(t *testing.T) {
		// Override default provider support for this test
		prevSupports := defaultProvider.SupportsFunc
		defaultProvider.SupportsFunc = func(creds interface{}) bool {
			return true
		}
		
		testChain := auth.NewAuthChain(manager)
		testChain.Use(auth.LoggingMiddleware())
		testChain.Use(auth.AuditingMiddleware())
		testChain.Use(auth.RateLimitingMiddleware(5, 300))
		testChain.Handler(testChain.DefaultProviderHandler())
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := testChain.Authenticate(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		
		// Restore original supports function
		defaultProvider.SupportsFunc = prevSupports
	})
}