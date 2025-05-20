package metadata

import (
	"context"
	"net/http"
)

// HTTPProvider defines the interface for HTTP framework adapters
type HTTPProvider interface {
	Provider
	
	// Middleware returns middleware for the specific framework
	// The returned value is framework-specific and should be type asserted by the caller
	Middleware() interface{}
	
	// RegisterRoutes registers authentication routes with the HTTP framework
	// The router parameter is framework-specific and should be type asserted by the caller
	RegisterRoutes(router interface{}) error
	
	// ParseRequest extracts authentication data from HTTP requests
	// The request parameter is framework-specific and should be type asserted by the caller
	ParseRequest(ctx context.Context, request interface{}) (AuthData, error)
	
	// WriteResponse writes authentication responses
	// The response and data parameters are framework-specific and should be type asserted by the caller
	WriteResponse(ctx context.Context, response interface{}, data interface{}) error
	
	// SetAuthManager sets the authentication manager to use
	// This is called during initialization to provide the HTTP provider with access to auth functionality
	SetAuthManager(authManager interface{}) error
	
	// SetSessionManager sets the session manager to use
	// This is called during initialization to provide the HTTP provider with access to session functionality
	SetSessionManager(sessionManager interface{}) error
}

// AuthData represents authentication data extracted from HTTP requests
type AuthData struct {
	// Type is the type of authentication data
	Type string
	
	// Token is the authentication token (if applicable)
	Token string
	
	// Credentials contains the credentials extracted from the request
	Credentials interface{}
	
	// SessionID is the session ID (if applicable)
	SessionID string
	
	// UserID is the user ID (if applicable)
	UserID string
	
	// Raw contains the raw authentication data
	Raw interface{}
}

// BaseHTTPProvider provides a base implementation of the HTTPProvider interface
type BaseHTTPProvider struct {
	*BaseProvider
	authManager    interface{}
	sessionManager interface{}
}

// NewBaseHTTPProvider creates a new BaseHTTPProvider
func NewBaseHTTPProvider(metadata ProviderMetadata) *BaseHTTPProvider {
	return &BaseHTTPProvider{
		BaseProvider: NewBaseProvider(metadata),
	}
}

// Middleware returns middleware for the specific framework
func (p *BaseHTTPProvider) Middleware() interface{} {
	return nil
}

// RegisterRoutes registers authentication routes with the HTTP framework
func (p *BaseHTTPProvider) RegisterRoutes(router interface{}) error {
	return ErrNotImplemented
}

// ParseRequest extracts authentication data from HTTP requests
func (p *BaseHTTPProvider) ParseRequest(ctx context.Context, request interface{}) (AuthData, error) {
	return AuthData{}, ErrNotImplemented
}

// WriteResponse writes authentication responses
func (p *BaseHTTPProvider) WriteResponse(ctx context.Context, response interface{}, data interface{}) error {
	return ErrNotImplemented
}

// SetAuthManager sets the authentication manager to use
func (p *BaseHTTPProvider) SetAuthManager(authManager interface{}) error {
	p.authManager = authManager
	return nil
}

// SetSessionManager sets the session manager to use
func (p *BaseHTTPProvider) SetSessionManager(sessionManager interface{}) error {
	p.sessionManager = sessionManager
	return nil
}

// StandardHTTPHandlerFunc is a function that handles standard HTTP requests
type StandardHTTPHandlerFunc func(http.ResponseWriter, *http.Request)

// StandardHTTPMiddleware is middleware for standard HTTP requests
type StandardHTTPMiddleware func(http.Handler) http.Handler