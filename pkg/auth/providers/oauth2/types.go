package oauth2

import (
	"time"
)

// TokenType represents the type of OAuth2 token
type TokenType string

const (
	// TokenTypeBearer is the bearer token type
	TokenTypeBearer TokenType = "Bearer"
)

// GrantType represents the OAuth2 grant type
type GrantType string

const (
	// GrantTypeAuthorizationCode is the authorization code grant type
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	// GrantTypeRefreshToken is the refresh token grant type
	GrantTypeRefreshToken GrantType = "refresh_token"
	// GrantTypeClientCredentials is the client credentials grant type
	GrantTypeClientCredentials GrantType = "client_credentials"
)

// ResponseType represents the OAuth2 response type
type ResponseType string

const (
	// ResponseTypeCode is the authorization code response type
	ResponseTypeCode ResponseType = "code"
	// ResponseTypeToken is the implicit grant token response type
	ResponseTypeToken ResponseType = "token"
)

// Token represents an OAuth2 token
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    TokenType `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	
	// Additional fields that some providers return
	IDToken      string                 `json:"id_token,omitempty"`
	Extra        map[string]interface{} `json:"extra,omitempty"`
}

// TokenResponse represents the response from a token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	
	// OpenID Connect fields
	IDToken      string `json:"id_token,omitempty"`
	
	// Error fields
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// AuthorizationRequest represents an OAuth2 authorization request
type AuthorizationRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType ResponseType
	Scope        []string
	State        string
	
	// PKCE parameters
	CodeChallenge       string
	CodeChallengeMethod string
	
	// Additional parameters
	Extra map[string]string
}

// AuthorizationResponse represents the response from an authorization endpoint
type AuthorizationResponse struct {
	Code  string
	State string
	Error string
	ErrorDescription string
}

// TokenRequest represents a request to the token endpoint
type TokenRequest struct {
	GrantType    GrantType
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        []string
	
	// PKCE parameters
	CodeVerifier string
}

// UserInfo represents basic user information from OAuth2 provider
type UserInfo struct {
	ID              string                 `json:"id"`
	Email           string                 `json:"email"`
	EmailVerified   bool                   `json:"email_verified"`
	Name            string                 `json:"name"`
	GivenName       string                 `json:"given_name"`
	FamilyName      string                 `json:"family_name"`
	Picture         string                 `json:"picture"`
	Locale          string                 `json:"locale"`
	
	// Provider-specific fields
	ProviderID      string                 `json:"provider_id"`
	ProviderName    string                 `json:"provider_name"`
	Raw             map[string]interface{} `json:"raw"`
}

// StateData represents the data stored for CSRF protection
type StateData struct {
	State       string    `json:"state"`
	Nonce       string    `json:"nonce,omitempty"`
	RedirectURI string    `json:"redirect_uri"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	
	// Additional data that can be round-tripped
	Extra       map[string]string `json:"extra,omitempty"`
}

// ProfileMappingFunc is a function that maps provider-specific user data to UserInfo
type ProfileMappingFunc func(providerData map[string]interface{}) (*UserInfo, error)

// OAuth2Credentials represents credentials for OAuth2 authentication
type OAuth2Credentials struct {
	Code         string `json:"code,omitempty"`
	State        string `json:"state,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// ProviderConfig represents provider-specific configuration
type ProviderConfig struct {
	Name         string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	Scopes       []string
	ProfileMap   ProfileMappingFunc
}