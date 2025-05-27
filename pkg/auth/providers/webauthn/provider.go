package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
	
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Provider implements both AuthProvider and MFAProvider for WebAuthn
type Provider struct {
	*providers.BaseAuthProvider
	config           *Config
	webauthn         *webauthn.WebAuthn
	credentialStore  *CredentialStore
	challengeManager *ChallengeManager
}

// Ensure Provider implements both interfaces
var _ providers.AuthProvider = (*Provider)(nil)
var _ metadata.MFAProvider = (*Provider)(nil)

// New creates a new WebAuthn provider
func New(config *Config) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	
	// Create WebAuthn instance
	wconfig := &webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigins:     config.RPOrigins,
		AttestationPreference: protocol.ConveyancePreference(config.AttestationPreference),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment(config.AuthenticatorAttachment),
			RequireResidentKey:      &config.RequireResidentKey,
			ResidentKey:             protocol.ResidentKeyRequirement(config.ResidentKeyRequirement),
			UserVerification:        protocol.UserVerificationRequirement(config.UserVerification),
		},
		Debug:   config.Debug,
	}
	
	w, err := webauthn.New(wconfig)
	if err != nil {
		return nil, WrapError(err, "failed to create webauthn instance")
	}
	
	provider := &Provider{
		BaseAuthProvider: providers.NewBaseAuthProvider(metadata.ProviderMetadata{
			ID:          "webauthn",
			Type:        metadata.ProviderTypeAuth,
			Name:        "WebAuthn",
			Description: "WebAuthn/FIDO2 passwordless authentication and MFA",
			Version:     "1.0.0",
			Author:      "auth2",
		}),
		config:           config,
		webauthn:         w,
		credentialStore:  NewCredentialStore(config.StateStore),
		challengeManager: NewChallengeManager(config.StateStore, config.ChallengeTimeout),
	}
	
	return provider, nil
}

// Initialize initializes the provider with the given configuration
func (p *Provider) Initialize(ctx context.Context, config interface{}) error {
	cfg, ok := config.(*Config)
	if !ok {
		return ErrInvalidConfig("expected *Config")
	}
	
	newProvider, err := New(cfg)
	if err != nil {
		return err
	}
	
	// Copy the initialized fields
	p.config = newProvider.config
	p.webauthn = newProvider.webauthn
	p.credentialStore = newProvider.credentialStore
	p.challengeManager = newProvider.challengeManager
	
	return nil
}

// Supports checks if the provider supports the given credentials
func (p *Provider) Supports(credentials interface{}) bool {
	switch creds := credentials.(type) {
	case *WebAuthnAuthenticationCredentials:
		return true
	case WebAuthnAuthenticationCredentials:
		return true
	case map[string]interface{}:
		// Check if it has webauthn fields
		_, hasID := creds["credentialId"]
		_, hasResponse := creds["response"]
		return hasID && hasResponse
	default:
		return false
	}
}

// Authenticate performs passwordless authentication
func (p *Provider) Authenticate(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
	// Parse credentials
	authCreds, err := p.parseAuthenticationCredentials(credentials)
	if err != nil {
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      err,
		}, err
	}
	
	// Get user ID from challenge
	challenge, err := p.challengeManager.ValidateChallenge(ctx.OriginalContext, authCreds.UserID, authCreds.ChallengeID)
	if err != nil {
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      ErrInvalidChallenge,
		}, ErrInvalidChallenge
	}
	
	// Get user credentials
	userCreds, err := p.credentialStore.GetUserCredentials(ctx.OriginalContext, challenge.UserID)
	if err != nil || len(userCreds.Credentials) == 0 {
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      ErrUserNotFound,
		}, ErrUserNotFound
	}
	
	// Create webauthn user
	user := &webauthnUser{
		id:          challenge.UserID,
		credentials: userCreds.Credentials,
	}
	
	// Parse the assertion
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(authCreds.Response))
	if err != nil {
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      ErrAuthenticationFailed,
		}, ErrAuthenticationFailed
	}
	
	// Create session data with challenge
	sessionData := &webauthn.SessionData{
		Challenge: base64.URLEncoding.EncodeToString(challenge.Challenge),
		UserID:    []byte(challenge.UserID),
	}
	
	// Validate the assertion
	credential, err := p.webauthn.ValidateLogin(user, *sessionData, parsedResponse)
	if err != nil {
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      ErrAuthenticationFailed,
		}, ErrAuthenticationFailed
	}
	
	// Update credential counter
	for i, cred := range userCreds.Credentials {
		if string(cred.ID) == string(credential.ID) {
			// Check counter
			if credential.Authenticator.SignCount > 0 && credential.Authenticator.SignCount <= cred.Counter {
				return &providers.AuthResult{
					Success:    false,
					ProviderID: p.GetMetadata().ID,
					Error:      ErrCounterError,
				}, ErrCounterError
			}
			
			// Update counter and last used
			userCreds.Credentials[i].Counter = credential.Authenticator.SignCount
			userCreds.Credentials[i].LastUsedAt = time.Now()
			
			// Update in store
			if err := p.credentialStore.UpdateCredential(ctx.OriginalContext, challenge.UserID, &userCreds.Credentials[i]); err != nil {
				// Log error but don't fail authentication
				fmt.Printf("Failed to update credential: %v\n", err)
			}
			break
		}
	}
	
	return &providers.AuthResult{
		Success:    true,
		UserID:     challenge.UserID,
		ProviderID: p.GetMetadata().ID,
		Extra: map[string]interface{}{
			"credential_id": base64.URLEncoding.EncodeToString(credential.ID),
			"user_verified": credential.Flags.UserVerified,
		},
	}, nil
}

// Setup initializes WebAuthn as an MFA method for a user
func (p *Provider) Setup(ctx context.Context, userID string) (metadata.SetupData, error) {
	// Create registration options
	options, challenge, err := p.createRegistrationOptions(ctx, userID, false)
	if err != nil {
		return metadata.SetupData{}, err
	}
	
	// Convert options to JSON for QR code or client
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return metadata.SetupData{}, WrapError(err, "failed to marshal options")
	}
	
	return metadata.SetupData{
		ProviderID: p.GetMetadata().ID,
		UserID:     userID,
		Secret:     challenge.ID, // Store challenge ID as secret
		QRCode:     optionsJSON, // Options as "QR code" (client will handle)
		AdditionalData: map[string]interface{}{
			"challenge_id": challenge.ID,
			"rp_id":        p.config.RPID,
			"timeout":      p.config.Timeout.Seconds(),
		},
	}, nil
}

// Verify verifies an MFA code (WebAuthn assertion)
func (p *Provider) Verify(ctx context.Context, userID string, code string) (bool, error) {
	// The "code" should be a JSON-encoded authentication response
	var authResponse map[string]interface{}
	if err := json.Unmarshal([]byte(code), &authResponse); err != nil {
		return false, ErrInvalidCredential
	}
	
	// Add user ID to the response
	authResponse["userId"] = userID
	
	// Use the Authenticate method
	authCtx := &providers.AuthContext{
		OriginalContext: ctx,
	}
	
	result, err := p.Authenticate(authCtx, authResponse)
	if err != nil {
		return false, err
	}
	
	return result.Success && result.UserID == userID, nil
}

// AuthenticateMetadata implements metadata.AuthProvider interface
func (p *Provider) AuthenticateMetadata(ctx context.Context, credentials interface{}) (string, error) {
	authCtx := &providers.AuthContext{
		OriginalContext: ctx,
	}
	
	result, err := p.Authenticate(authCtx, credentials)
	if err != nil {
		return "", err
	}
	
	if !result.Success {
		return "", result.Error
	}
	
	return result.UserID, nil
}

// GenerateBackupCodes is not applicable for WebAuthn
func (p *Provider) GenerateBackupCodes(ctx context.Context, userID string, count int) ([]string, error) {
	return nil, fmt.Errorf("backup codes are not supported for WebAuthn")
}

// BeginRegistration starts the WebAuthn registration process
func (p *Provider) BeginRegistration(ctx context.Context, userID string, username string, displayName string) (*RegistrationOptions, error) {
	options, _, err := p.createRegistrationOptions(ctx, userID, true)
	if err != nil {
		return nil, err
	}
	
	// Set user information
	if username != "" {
		options.User.Name = username
	}
	if displayName != "" {
		options.User.DisplayName = displayName
	}
	
	return options, nil
}

// CompleteRegistration completes the WebAuthn registration process
func (p *Provider) CompleteRegistration(ctx context.Context, userID string, challengeID string, response *RegistrationResponse) error {
	// Validate challenge
	challenge, err := p.challengeManager.ValidateChallenge(ctx, userID, challengeID)
	if err != nil {
		return ErrInvalidChallenge
	}
	
	// Create webauthn user
	user := &webauthnUser{
		id:          userID,
		name:        userID,
		displayName: userID,
	}
	
	// Create session data
	sessionData := &webauthn.SessionData{
		Challenge: base64.URLEncoding.EncodeToString(challenge.Challenge),
		UserID:    []byte(userID),
	}
	
	// Parse credential creation response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response.ClientDataJSON))
	if err != nil {
		return WrapError(err, "failed to parse response")
	}
	
	// Verify the registration
	credential, err := p.webauthn.CreateCredential(user, *sessionData, parsedResponse)
	if err != nil {
		return WrapError(err, "failed to create credential")
	}
	
	// Store the credential
	cred := &Credential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: string(credential.AttestationType),
		Transport:       response.Transports,
		Flags: CredentialFlags{
			UserPresent:    credential.Flags.UserPresent,
			UserVerified:   credential.Flags.UserVerified,
			BackupEligible: credential.Flags.BackupEligible,
			BackupState:    credential.Flags.BackupState,
		},
		Authenticator: AuthenticatorData{
			AAGUID:       credential.Authenticator.AAGUID,
			SignCount:    credential.Authenticator.SignCount,
			CloneWarning: credential.Authenticator.CloneWarning,
		},
		Counter:    credential.Authenticator.SignCount,
		Attachment: response.AuthenticatorAttachment,
	}
	
	if err := p.credentialStore.AddCredential(ctx, userID, cred); err != nil {
		return err
	}
	
	return nil
}

// BeginAuthentication starts the WebAuthn authentication process
func (p *Provider) BeginAuthentication(ctx context.Context, userID string) (*AuthenticationOptions, error) {
	// Get user credentials
	userCreds, err := p.credentialStore.GetUserCredentials(ctx, userID)
	if err != nil || len(userCreds.Credentials) == 0 {
		return nil, ErrUserNotFound
	}
	
	// Create challenge
	challenge, err := p.challengeManager.CreateChallenge(ctx, userID, "authentication")
	if err != nil {
		return nil, err
	}
	
	// Build allowed credentials
	allowedCreds := make([]PublicKeyCredentialDescriptor, len(userCreds.Credentials))
	for i, cred := range userCreds.Credentials {
		allowedCreds[i] = PublicKeyCredentialDescriptor{
			Type:       "public-key",
			ID:         cred.ID,
			Transports: cred.Transport,
		}
	}
	
	options := &AuthenticationOptions{
		Challenge:        challenge.Challenge,
		Timeout:          uint64(p.config.Timeout.Milliseconds()),
		RelyingPartyID:   p.config.RPID,
		AllowCredentials: allowedCreds,
		UserVerification: p.config.UserVerification,
	}
	
	return options, nil
}

// Helper functions

func (p *Provider) createRegistrationOptions(ctx context.Context, userID string, includeUser bool) (*RegistrationOptions, *Challenge, error) {
	// Create challenge
	challenge, err := p.challengeManager.CreateChallenge(ctx, userID, "registration")
	if err != nil {
		return nil, nil, err
	}
	
	// Get existing credentials to exclude
	userCreds, _ := p.credentialStore.GetUserCredentials(ctx, userID)
	excludeCreds := make([]PublicKeyCredentialDescriptor, len(userCreds.Credentials))
	for i, cred := range userCreds.Credentials {
		excludeCreds[i] = PublicKeyCredentialDescriptor{
			Type:       "public-key",
			ID:         cred.ID,
			Transports: cred.Transport,
		}
	}
	
	// Build credential parameters
	credParams := make([]PublicKeyCredentialParameters, len(p.config.SupportedAlgorithms))
	for i, alg := range p.config.SupportedAlgorithms {
		credParams[i] = PublicKeyCredentialParameters{
			Type:      "public-key",
			Algorithm: alg,
		}
	}
	
	options := &RegistrationOptions{
		Challenge: challenge.Challenge,
		RelyingParty: RelyingParty{
			ID:   p.config.RPID,
			Name: p.config.RPDisplayName,
		},
		PubKeyCredParams:   credParams,
		Timeout:            uint64(p.config.Timeout.Milliseconds()),
		ExcludeCredentials: excludeCreds,
		Attestation:        p.config.AttestationPreference,
		AuthenticatorSelection: &AuthenticatorSelection{
			AuthenticatorAttachment: p.config.AuthenticatorAttachment,
			ResidentKey:             p.config.ResidentKeyRequirement,
			RequireResidentKey:      p.config.RequireResidentKey,
			UserVerification:        p.config.UserVerification,
		},
	}
	
	if includeUser {
		// Generate user ID bytes
		userIDBytes := make([]byte, 32)
		copy(userIDBytes, []byte(userID))
		
		options.User = User{
			ID:          userIDBytes,
			Name:        userID,
			DisplayName: userID,
		}
	}
	
	return options, challenge, nil
}

func (p *Provider) parseAuthenticationCredentials(credentials interface{}) (*WebAuthnAuthenticationCredentials, error) {
	switch creds := credentials.(type) {
	case *WebAuthnAuthenticationCredentials:
		return creds, nil
	case WebAuthnAuthenticationCredentials:
		return &creds, nil
	case map[string]interface{}:
		// Parse from map
		result := &WebAuthnAuthenticationCredentials{}
		
		if v, ok := creds["credentialId"].(string); ok {
			result.CredentialID = v
		}
		if v, ok := creds["response"].([]byte); ok {
			result.Response = v
		} else if v, ok := creds["response"].(string); ok {
			result.Response = []byte(v)
		}
		if v, ok := creds["challengeId"].(string); ok {
			result.ChallengeID = v
		}
		if v, ok := creds["userId"].(string); ok {
			result.UserID = v
		}
		
		if result.CredentialID == "" || len(result.Response) == 0 {
			return nil, ErrInvalidCredential
		}
		
		return result, nil
	default:
		return nil, ErrInvalidCredential
	}
}

// WebAuthnAuthenticationCredentials represents credentials for WebAuthn authentication
type WebAuthnAuthenticationCredentials struct {
	CredentialID string `json:"credentialId"`
	Response     []byte `json:"response"`
	ChallengeID  string `json:"challengeId"`
	UserID       string `json:"userId"`
}

// webauthnUser implements webauthn.User interface
type webauthnUser struct {
	id          string
	name        string
	displayName string
	credentials []Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.id)
}

func (u *webauthnUser) WebAuthnName() string {
	if u.name != "" {
		return u.name
	}
	return u.id
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	if u.displayName != "" {
		return u.displayName
	}
	return u.name
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.credentials))
	for i, c := range u.credentials {
		creds[i] = webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       convertTransports(c.Transport),
			Flags: webauthn.CredentialFlags{
				UserPresent:    c.Flags.UserPresent,
				UserVerified:   c.Flags.UserVerified,
				BackupEligible: c.Flags.BackupEligible,
				BackupState:    c.Flags.BackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:       c.Authenticator.AAGUID,
				SignCount:    c.Authenticator.SignCount,
				CloneWarning: c.Authenticator.CloneWarning,
			},
		}
	}
	return creds
}

func (u *webauthnUser) WebAuthnIcon() string {
	return ""
}

// convertTransports converts string transports to protocol.AuthenticatorTransport
func convertTransports(transports []string) []protocol.AuthenticatorTransport {
	if len(transports) == 0 {
		return nil
	}
	
	result := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		result[i] = protocol.AuthenticatorTransport(t)
	}
	return result
}