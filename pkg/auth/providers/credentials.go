package providers

// CredentialType defines the type of authentication credentials
type CredentialType string

const (
	// CredentialTypeUsernamePassword represents username/password credentials
	CredentialTypeUsernamePassword CredentialType = "username_password"
	
	// CredentialTypeOAuth represents OAuth credentials
	CredentialTypeOAuth CredentialType = "oauth"
	
	// CredentialTypeSAML represents SAML credentials
	CredentialTypeSAML CredentialType = "saml"
	
	// CredentialTypeWebAuthn represents WebAuthn credentials
	CredentialTypeWebAuthn CredentialType = "webauthn"
	
	// CredentialTypeMFA represents MFA verification credentials
	CredentialTypeMFA CredentialType = "mfa"
	
	// CredentialTypeSession represents session credentials
	CredentialTypeSession CredentialType = "session"
	
	// CredentialTypeToken represents token credentials
	CredentialTypeToken CredentialType = "token"
)

// Credentials is the base interface for all authentication credentials
type Credentials interface {
	// GetType returns the type of credentials
	GetType() CredentialType
}

// UsernamePasswordCredentials represents username/password credentials
type UsernamePasswordCredentials struct {
	Username string
	Password string
}

// GetType returns the type of credentials
func (c UsernamePasswordCredentials) GetType() CredentialType {
	return CredentialTypeUsernamePassword
}

// OAuthCredentials represents OAuth credentials
type OAuthCredentials struct {
	ProviderName string
	Code         string
	RedirectURI  string
	State        string
	Scope        string
	TokenType    string
	AccessToken  string
	RefreshToken string
}

// GetType returns the type of credentials
func (c OAuthCredentials) GetType() CredentialType {
	return CredentialTypeOAuth
}

// SAMLCredentials represents SAML credentials
type SAMLCredentials struct {
	SAMLResponse string
	RelayState   string
}

// GetType returns the type of credentials
func (c SAMLCredentials) GetType() CredentialType {
	return CredentialTypeSAML
}

// WebAuthnCredentials represents WebAuthn credentials
type WebAuthnCredentials struct {
	CredentialID       []byte
	AuthenticatorData  []byte
	ClientDataJSON     []byte
	Signature          []byte
	UserHandle         []byte
	Challenge          string
	RelyingPartyID     string
	UserVerification   string
	Extensions         map[string]interface{}
	RegistrationPhase  bool
}

// GetType returns the type of credentials
func (c WebAuthnCredentials) GetType() CredentialType {
	return CredentialTypeWebAuthn
}

// MFACredentials represents MFA verification credentials
type MFACredentials struct {
	UserID     string
	ProviderID string
	Code       string
	Challenge  string
}

// GetType returns the type of credentials
func (c MFACredentials) GetType() CredentialType {
	return CredentialTypeMFA
}

// SessionCredentials represents session-based credentials
type SessionCredentials struct {
	SessionID string
	Token     string
}

// GetType returns the type of credentials
func (c SessionCredentials) GetType() CredentialType {
	return CredentialTypeSession
}

// TokenCredentials represents token-based credentials
type TokenCredentials struct {
	TokenType  string
	TokenValue string
}

// GetType returns the type of credentials
func (c TokenCredentials) GetType() CredentialType {
	return CredentialTypeToken
}