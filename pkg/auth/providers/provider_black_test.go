package providers_test

import (
	"context"
	"testing"
	
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/stretchr/testify/assert"
)

func TestBaseAuthProvider(t *testing.T) {
	meta := metadata.ProviderMetadata{
		ID:          "test",
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        "Test Provider",
		Description: "Test provider for unit tests",
		Author:      "Auth2 Team",
	}
	
	provider := providers.NewBaseAuthProvider(meta)
	
	t.Run("GetMetadata", func(t *testing.T) {
		returnedMeta := provider.GetMetadata()
		assert.Equal(t, meta, returnedMeta)
	})
	
	t.Run("Authenticate", func(t *testing.T) {
		ctx := &providers.AuthContext{
			OriginalContext: context.Background(),
			RequestID:       "test-request",
		}
		
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		result, err := provider.Authenticate(ctx, credentials)
		assert.Error(t, err)
		assert.Equal(t, metadata.ErrNotImplemented, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, "test", result.ProviderID)
		assert.Equal(t, metadata.ErrNotImplemented, result.Error)
	})
	
	t.Run("Supports", func(t *testing.T) {
		credentials := providers.UsernamePasswordCredentials{
			Username: "testuser",
			Password: "testpassword",
		}
		
		supports := provider.Supports(credentials)
		assert.False(t, supports)
	})
	
	t.Run("Initialize", func(t *testing.T) {
		err := provider.Initialize(context.Background(), nil)
		assert.NoError(t, err)
	})
	
	t.Run("Validate", func(t *testing.T) {
		err := provider.Validate(context.Background())
		assert.NoError(t, err)
	})
}

func TestAuthErrorHelpers(t *testing.T) {
	t.Run("IsAuthenticationError", func(t *testing.T) {
		assert.True(t, providers.IsAuthenticationError(errors.ErrAuthFailed))
		assert.True(t, providers.IsAuthenticationError(metadata.ErrNotImplemented))
		assert.False(t, providers.IsAuthenticationError(errors.ErrNotFound))
	})
	
	t.Run("NewAuthFailedError", func(t *testing.T) {
		// Test with provided details
		err := providers.NewAuthFailedError("test reason", map[string]interface{}{
			"test_key": "test_value",
		})
		
		assert.Error(t, err)
		assert.True(t, errors.Is(err, errors.ErrAuthFailed))
		
		var stdErr *errors.Error
		assert.True(t, errors.As(err, &stdErr))
		assert.Equal(t, errors.CodeAuthFailed, stdErr.ErrorCode)
		assert.Equal(t, "test reason", stdErr.Message)
		assert.Equal(t, "test_value", stdErr.Details["test_key"])
		assert.Equal(t, "test reason", stdErr.Details["reason"])
		
		// Test with nil details
		err2 := providers.NewAuthFailedError("another reason", nil)
		
		assert.Error(t, err2)
		assert.True(t, errors.Is(err2, errors.ErrAuthFailed))
		
		var stdErr2 *errors.Error
		assert.True(t, errors.As(err2, &stdErr2))
		assert.Equal(t, errors.CodeAuthFailed, stdErr2.ErrorCode)
		assert.Equal(t, "another reason", stdErr2.Message)
		assert.Equal(t, "another reason", stdErr2.Details["reason"])
	})
	
	t.Run("NewInvalidCredentialsError", func(t *testing.T) {
		err := providers.NewInvalidCredentialsError("test reason")
		
		assert.Error(t, err)
		assert.True(t, errors.Is(err, errors.ErrInvalidCredentials))
		
		var stdErr *errors.Error
		assert.True(t, errors.As(err, &stdErr))
		assert.Equal(t, errors.CodeInvalidCredentials, stdErr.ErrorCode)
		assert.Equal(t, "test reason", stdErr.Message)
	})
	
	t.Run("NewUserNotFoundError", func(t *testing.T) {
		err := providers.NewUserNotFoundError("test@example.com")
		
		assert.Error(t, err)
		assert.True(t, errors.Is(err, errors.ErrUserNotFound))
		
		var stdErr *errors.Error
		assert.True(t, errors.As(err, &stdErr))
		assert.Equal(t, errors.CodeUserNotFound, stdErr.ErrorCode)
		assert.Equal(t, "user not found", stdErr.Message)
		assert.Equal(t, "test@example.com", stdErr.Details["identifier"])
	})
	
	t.Run("NewMFARequiredError", func(t *testing.T) {
		err := providers.NewMFARequiredError("user123", []string{"totp", "webauthn"})
		
		assert.Error(t, err)
		assert.True(t, errors.Is(err, errors.ErrMFARequired))
		
		var stdErr *errors.Error
		assert.True(t, errors.As(err, &stdErr))
		assert.Equal(t, errors.CodeMFARequired, stdErr.ErrorCode)
		assert.Equal(t, "multi-factor authentication required", stdErr.Message)
		assert.Equal(t, "user123", stdErr.Details["user_id"])
		assert.Equal(t, []string{"totp", "webauthn"}, stdErr.Details["mfa_providers"])
	})
}