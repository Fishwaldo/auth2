package providers

import (
	"context"
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// AuthResult contains the result of an authentication attempt
type AuthResult struct {
	// Success indicates whether the authentication was successful
	Success bool

	// UserID is the authenticated user's ID (if successful)
	UserID string

	// ProviderID is the ID of the provider that authenticated the user
	ProviderID string

	// RequiresMFA indicates whether MFA is required to complete authentication
	RequiresMFA bool

	// MFAProviders is a list of MFA provider IDs that the user has enabled
	MFAProviders []string

	// Extra contains additional provider-specific data
	Extra map[string]interface{}

	// Error contains any error that occurred during authentication
	Error error
}

// AuthContext contains context information for authentication
type AuthContext struct {
	// OriginalContext is the original context passed to the provider
	OriginalContext context.Context

	// RequestID is a unique identifier for the authentication request
	RequestID string

	// ClientIP is the IP address of the client making the request
	ClientIP string

	// UserAgent is the user agent of the client making the request
	UserAgent string

	// RequestMetadata contains additional request metadata
	RequestMetadata map[string]interface{}
}

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	metadata.Provider

	// Authenticate verifies user credentials and returns an AuthResult
	Authenticate(ctx *AuthContext, credentials interface{}) (*AuthResult, error)

	// Supports returns true if this provider supports the given credentials type
	Supports(credentials interface{}) bool

	// GetMetadata returns provider metadata (already provided by metadata.Provider)
	// GetMetadata() metadata.ProviderMetadata
}

// BaseAuthProvider provides a base implementation of the AuthProvider interface
type BaseAuthProvider struct {
	*metadata.BaseProvider
}

// NewBaseAuthProvider creates a new BaseAuthProvider
func NewBaseAuthProvider(meta metadata.ProviderMetadata) *BaseAuthProvider {
	return &BaseAuthProvider{
		BaseProvider: metadata.NewBaseProvider(meta),
	}
}

// Authenticate provides a default implementation that always fails
func (p *BaseAuthProvider) Authenticate(ctx *AuthContext, credentials interface{}) (*AuthResult, error) {
	return &AuthResult{
		Success:    false,
		ProviderID: p.GetMetadata().ID,
		Error:      metadata.ErrNotImplemented,
	}, metadata.ErrNotImplemented
}

// Supports provides a default implementation that always returns false
func (p *BaseAuthProvider) Supports(credentials interface{}) bool {
	return false
}

// IsAuthenticationError checks if an error is an authentication error
func IsAuthenticationError(err error) bool {
	authError := errors.ErrAuthFailed
	providerError := metadata.ErrNotImplemented
	return errors.Is(err, authError) || errors.Is(err, providerError)
}

// NewAuthFailedError creates a new authentication failed error
func NewAuthFailedError(reason string, details map[string]interface{}) error {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["reason"] = reason
	
	return errors.WrapError(errors.ErrAuthFailed, errors.CodeAuthFailed, reason).WithDetails(details)
}

// NewInvalidCredentialsError creates a new invalid credentials error
func NewInvalidCredentialsError(reason string) error {
	return errors.WrapError(errors.ErrInvalidCredentials, errors.CodeInvalidCredentials, reason)
}

// NewUserNotFoundError creates a new user not found error
func NewUserNotFoundError(identifier string) error {
	return errors.WrapError(errors.ErrUserNotFound, errors.CodeUserNotFound, 
		"user not found").WithDetails(map[string]interface{}{
		"identifier": identifier,
	})
}

// NewMFARequiredError creates a new MFA required error
func NewMFARequiredError(userID string, availableProviders []string) error {
	return errors.WrapError(errors.ErrMFARequired, errors.CodeMFARequired, 
		"multi-factor authentication required").WithDetails(map[string]interface{}{
		"user_id":     userID,
		"mfa_providers": availableProviders,
	})
}