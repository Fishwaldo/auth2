package metadata

import (
	"context"
)

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	Provider
	
	// Authenticate verifies user credentials and returns a user ID if successful
	Authenticate(ctx context.Context, credentials interface{}) (string, error)
	
	// Supports returns true if this provider supports the given credentials type
	Supports(credentials interface{}) bool
}

// AuthProviderCredentials is the base interface for all authentication credentials
type AuthProviderCredentials interface {
	// GetType returns the type of credentials
	GetType() string
}

// UsernamePasswordCredentials represents username/password credentials
type UsernamePasswordCredentials struct {
	Username string
	Password string
}

// GetType returns the type of credentials
func (c UsernamePasswordCredentials) GetType() string {
	return "username_password"
}

// OAuthCredentials represents OAuth credentials
type OAuthCredentials struct {
	Provider  string
	Code      string
	RedirectURI string
	State     string
}

// GetType returns the type of credentials
func (c OAuthCredentials) GetType() string {
	return "oauth"
}

// SAMLCredentials represents SAML credentials
type SAMLCredentials struct {
	SAMLResponse string
	RelayState   string
}

// GetType returns the type of credentials
func (c SAMLCredentials) GetType() string {
	return "saml"
}

// WebAuthnCredentials represents WebAuthn credentials
type WebAuthnCredentials struct {
	CredentialID       []byte
	AuthenticatorData  []byte
	ClientDataJSON     []byte
	Signature          []byte
	UserHandle         []byte
}

// GetType returns the type of credentials
func (c WebAuthnCredentials) GetType() string {
	return "webauthn"
}

// BaseAuthProvider provides a base implementation of the AuthProvider interface
type BaseAuthProvider struct {
	*BaseProvider
}

// NewBaseAuthProvider creates a new BaseAuthProvider
func NewBaseAuthProvider(metadata ProviderMetadata) *BaseAuthProvider {
	return &BaseAuthProvider{
		BaseProvider: NewBaseProvider(metadata),
	}
}

// Authenticate provides a default implementation that always fails
func (p *BaseAuthProvider) Authenticate(ctx context.Context, credentials interface{}) (string, error) {
	return "", ErrNotImplemented
}

// Supports provides a default implementation that always returns false
func (p *BaseAuthProvider) Supports(credentials interface{}) bool {
	return false
}

// ErrNotImplemented is returned when a method is not implemented
var ErrNotImplemented = NewProviderError("", "not_implemented", "method not implemented")