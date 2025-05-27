package oauth2

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidState indicates the state parameter doesn't match
	ErrInvalidState = errors.New("oauth2: invalid state parameter")
	
	// ErrStateExpired indicates the state has expired
	ErrStateExpired = errors.New("oauth2: state parameter expired")
	
	// ErrStateNotFound indicates the state was not found in storage
	ErrStateNotFound = errors.New("oauth2: state not found")
	
	// ErrNoAuthorizationCode indicates no authorization code was provided
	ErrNoAuthorizationCode = errors.New("oauth2: no authorization code provided")
	
	// ErrTokenExpired indicates the access token has expired
	ErrTokenExpired = errors.New("oauth2: token expired")
	
	// ErrNoRefreshToken indicates no refresh token is available
	ErrNoRefreshToken = errors.New("oauth2: no refresh token available")
	
	// ErrInvalidToken indicates the token is invalid
	ErrInvalidToken = errors.New("oauth2: invalid token")
	
	// ErrInvalidCredentials indicates invalid OAuth2 credentials
	ErrInvalidCredentials = errors.New("oauth2: invalid credentials")
	
	// ErrProviderError indicates an error from the OAuth2 provider
	ErrProviderError = errors.New("oauth2: provider error")
	
	// ErrProfileMapping indicates an error mapping the user profile
	ErrProfileMapping = errors.New("oauth2: error mapping user profile")
	
	// ErrUnsupportedResponseType indicates an unsupported response type
	ErrUnsupportedResponseType = errors.New("oauth2: unsupported response type")
	
	// ErrMissingClientID indicates the client ID is missing
	ErrMissingClientID = errors.New("oauth2: missing client ID")
	
	// ErrMissingClientSecret indicates the client secret is missing
	ErrMissingClientSecret = errors.New("oauth2: missing client secret")
	
	// ErrMissingAuthURL indicates the authorization URL is missing
	ErrMissingAuthURL = errors.New("oauth2: missing authorization URL")
	
	// ErrMissingTokenURL indicates the token URL is missing
	ErrMissingTokenURL = errors.New("oauth2: missing token URL")
)

// ProviderError represents an error response from an OAuth2 provider
type ProviderError struct {
	Code        string
	Description string
	URI         string
}

// Error implements the error interface
func (e *ProviderError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth2: provider error %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("oauth2: provider error: %s", e.Code)
}

// WrapProviderError wraps a provider error with additional context
func WrapProviderError(code, description, uri string) error {
	return &ProviderError{
		Code:        code,
		Description: description,
		URI:         uri,
	}
}