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

func TestAuthManager(t *testing.T) {
	reg := registry.NewRegistry()
	config := auth.ManagerConfig{
		DefaultProviderID: "default",
		MFARequired:       false,
		MaxLoginAttempts:  5,
		LockoutDuration:   300,
	}
	
	manager := auth.NewManager(reg, config)
	
	// Create test providers
	successProvider := test.NewMockAuthProvider(metadata.ProviderMetadata{
		ID:          "success",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "Success Provider",
		Description: "Always succeeds",
		Author:      "Auth2 Team",
	})
	
	successProvider.AuthenticateFunc = func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
		return &providers.AuthResult{
			Success:    true,
			UserID:     "user123",
			ProviderID: "success",
		}, nil
	}
	
	failureProvider := test.NewMockAuthProvider(metadata.ProviderMetadata{
		ID:          "failure",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "Failure Provider",
		Description: "Always fails",
		Author:      "Auth2 Team",
	})
	
	failureProvider.AuthenticateFunc = func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
		errResult := providers.NewAuthFailedError("authentication failed", nil)
		return &providers.AuthResult{
			Success:    false,
			ProviderID: "failure",
			Error:      errResult,
		}, errResult
	}
	
	mfaProvider := test.NewMockAuthProvider(metadata.ProviderMetadata{
		ID:          "mfa",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "MFA Provider",
		Description: "Requires MFA",
		Author:      "Auth2 Team",
	})
	
	mfaProvider.AuthenticateFunc = func(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
		errResult := providers.NewMFARequiredError("user123", []string{"totp", "webauthn"})
		return &providers.AuthResult{
			Success:      false,
			UserID:       "user123",
			ProviderID:   "mfa",
			RequiresMFA:  true,
			MFAProviders: []string{"totp", "webauthn"},
			Error:        errResult,
		}, errResult
	}
	
	t.Run("RegisterProvider", func(t *testing.T) {
		err := manager.RegisterProvider(successProvider)
		assert.NoError(t, err)
		
		err = manager.RegisterProvider(failureProvider)
		assert.NoError(t, err)
		
		err = manager.RegisterProvider(mfaProvider)
		assert.NoError(t, err)
		
		// Register same provider again should fail
		err = manager.RegisterProvider(successProvider)
		assert.Error(t, err)
		assert.True(t, errors.IsPluginError(err))
	})
	
	t.Run("GetProvider", func(t *testing.T) {
		provider, err := manager.GetProvider("success")
		assert.NoError(t, err)
		assert.Equal(t, "success", provider.GetMetadata().ID)
		
		provider, err = manager.GetProvider("nonexistent")
		assert.Error(t, err)
		assert.Nil(t, provider)
		assert.True(t, errors.IsPluginError(err))
	})
	
	t.Run("GetProviders", func(t *testing.T) {
		providers := manager.GetProviders()
		assert.Len(t, providers, 3)
		assert.Contains(t, providers, "success")
		assert.Contains(t, providers, "failure")
		assert.Contains(t, providers, "mfa")
	})
	
	t.Run("AuthenticateWithCredentials_Success", func(t *testing.T) {
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		// Configure provider to support these credentials
		successProvider.SupportsFunc = func(creds interface{}) bool {
			_, ok := creds.(providers.UsernamePasswordCredentials)
			return ok
		}
		
		failureProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		mfaProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		result, err := manager.AuthenticateWithCredentials(context.Background(), credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "user123", result.UserID)
		assert.Equal(t, "success", result.ProviderID)
	})
	
	t.Run("AuthenticateWithCredentials_Failure", func(t *testing.T) {
		credentials := providers.TokenCredentials{
			TokenType:  "Bearer",
			TokenValue: "invalid-token",
		}
		
		// Configure providers to not support these credentials
		successProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		failureProvider.SupportsFunc = func(creds interface{}) bool {
			_, ok := creds.(providers.TokenCredentials)
			return ok
		}
		
		mfaProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		result, err := manager.AuthenticateWithCredentials(context.Background(), credentials)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, "failure", result.ProviderID)
	})
	
	t.Run("AuthenticateWithCredentials_MFA", func(t *testing.T) {
		credentials := providers.OAuthCredentials{
			ProviderName: "google",
			Code:         "test-code",
		}
		
		// Configure providers to support these credentials
		successProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		failureProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		mfaProvider.SupportsFunc = func(creds interface{}) bool {
			_, ok := creds.(providers.OAuthCredentials)
			return ok
		}
		
		result, err := manager.AuthenticateWithCredentials(context.Background(), credentials)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.True(t, result.RequiresMFA)
		assert.Equal(t, "mfa", result.ProviderID)
		assert.Equal(t, []string{"totp", "webauthn"}, result.MFAProviders)
	})
	
	t.Run("AuthenticateWithCredentials_NoProviders", func(t *testing.T) {
		credentials := providers.SAMLCredentials{
			SAMLResponse: "test-response",
		}
		
		// Configure all providers to not support these credentials
		successProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		failureProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		mfaProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		result, err := manager.AuthenticateWithCredentials(context.Background(), credentials)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, errors.ErrUnsupported))
		assert.Nil(t, result)
	})
	
	t.Run("AuthenticateWithProviderID_Success", func(t *testing.T) {
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		// Configure provider to support these credentials
		successProvider.SupportsFunc = func(creds interface{}) bool {
			_, ok := creds.(providers.UsernamePasswordCredentials)
			return ok
		}
		
		result, err := manager.AuthenticateWithProviderID(context.Background(), "success", credentials)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, "user123", result.UserID)
		assert.Equal(t, "success", result.ProviderID)
	})
	
	t.Run("AuthenticateWithProviderID_Failure", func(t *testing.T) {
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		// Configure failure provider to support these credentials
		failureProvider.SupportsFunc = func(creds interface{}) bool {
			_, ok := creds.(providers.UsernamePasswordCredentials)
			return ok
		}
		
		result, err := manager.AuthenticateWithProviderID(context.Background(), "failure", credentials)
		assert.Error(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, "failure", result.ProviderID)
	})
	
	t.Run("AuthenticateWithProviderID_NotFound", func(t *testing.T) {
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := manager.AuthenticateWithProviderID(context.Background(), "nonexistent", credentials)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.True(t, errors.IsPluginError(err))
	})
	
	t.Run("AuthenticateWithProviderID_Unsupported", func(t *testing.T) {
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		// Configure provider to not support these credentials
		successProvider.SupportsFunc = func(creds interface{}) bool {
			return false
		}
		
		result, err := manager.AuthenticateWithProviderID(context.Background(), "success", credentials)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.True(t, errors.Is(err, errors.ErrUnsupported))
	})
	
	t.Run("UnregisterProvider", func(t *testing.T) {
		err := manager.UnregisterProvider("success")
		assert.NoError(t, err)
		
		// Verify provider was removed
		provider, err := manager.GetProvider("success")
		assert.Error(t, err)
		assert.Nil(t, provider)
		
		// Unregister nonexistent provider should fail
		err = manager.UnregisterProvider("nonexistent")
		assert.Error(t, err)
		assert.True(t, errors.IsPluginError(err))
	})
	
	t.Run("ValidateConfig", func(t *testing.T) {
		// Current config has default provider "default" which doesn't exist
		err := manager.ValidateConfig()
		assert.Error(t, err)
		
		// Set default provider to a registered provider
		manager.Config.DefaultProviderID = "failure"
		err = manager.ValidateConfig()
		assert.NoError(t, err)
	})
	
	t.Run("Initialize", func(t *testing.T) {
		err := manager.Initialize(context.Background(), map[string]interface{}{
			"auth.failure": map[string]interface{}{
				"option": "value",
			},
		})
		assert.NoError(t, err)
		
		// Verify Initialize was called on the provider
		assert.Len(t, failureProvider.InitializeCalls, 1)
		assert.Equal(t, map[string]interface{}{
			"option": "value",
		}, failureProvider.InitializeCalls[0].Config)
	})
}