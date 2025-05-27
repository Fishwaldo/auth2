package oauth2

import (
	"context"
	"fmt"

	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Provider implements OAuth2 authentication
type Provider struct {
	*providers.BaseAuthProvider
	config       *Config
	flowHandler  *FlowHandler
	stateManager *StateManager
	tokenManager *TokenManager
}

// NewProvider creates a new OAuth2 authentication provider
func NewProvider(config *Config) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Create managers
	stateManager := NewStateManager(config.StateStore, config.StateTTL, config.ProviderID)
	tokenManager := NewTokenManager(config.StateStore, config.ProviderID)
	flowHandler := NewFlowHandler(config, stateManager, tokenManager)
	
	meta := metadata.ProviderMetadata{
		ID:          config.ProviderID,
		Type:        metadata.ProviderTypeAuth,
		Version:     "1.0.0",
		Name:        fmt.Sprintf("OAuth2 %s Provider", config.ProviderName),
		Description: fmt.Sprintf("OAuth2 authentication provider for %s", config.ProviderName),
		Author:      "Auth2 Team",
	}
	
	provider := &Provider{
		BaseAuthProvider: providers.NewBaseAuthProvider(meta),
		config:       config,
		flowHandler:  flowHandler,
		stateManager: stateManager,
		tokenManager: tokenManager,
	}
	
	return provider, nil
}

// Initialize initializes the provider with configuration
func (p *Provider) Initialize(ctx context.Context, config interface{}) error {
	// If already configured, skip
	if p.config != nil {
		return nil
	}
	
	// Parse configuration
	cfg, ok := config.(*Config)
	if !ok {
		return fmt.Errorf("invalid configuration type: expected *Config, got %T", config)
	}
	
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Update configuration
	p.config = cfg
	p.stateManager = NewStateManager(cfg.StateStore, cfg.StateTTL, cfg.ProviderID)
	p.tokenManager = NewTokenManager(cfg.StateStore, cfg.ProviderID)
	p.flowHandler = NewFlowHandler(cfg, p.stateManager, p.tokenManager)
	
	return nil
}

// Authenticate authenticates a user using OAuth2
func (p *Provider) Authenticate(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
	// Parse credentials
	oauth2Creds, ok := credentials.(*providers.OAuthCredentials)
	if !ok {
		return nil, ErrInvalidCredentials
	}
	
	// Handle different OAuth2 flows
	var userID string
	var err error
	
	switch {
	case oauth2Creds.Code != "":
		// Authorization code flow
		userID, err = p.handleAuthorizationCode(ctx.OriginalContext, oauth2Creds)
		
	case oauth2Creds.AccessToken != "":
		// Direct token validation (for testing or trusted scenarios)
		userID, err = p.handleDirectToken(ctx.OriginalContext, oauth2Creds)
		
	default:
		return nil, ErrInvalidCredentials
	}
	
	if err != nil {
		return &providers.AuthResult{
			UserID:     "",
			Success:    false,
			ProviderID: p.config.ProviderID,
			Error:      err,
		}, err
	}
	
	// Get user info if available
	userInfo, _ := p.GetUserInfo(ctx.OriginalContext, userID)
	
	result := &providers.AuthResult{
		UserID:     userID,
		Success:    true,
		ProviderID: p.config.ProviderID,
		Extra: map[string]interface{}{
			"provider": p.config.ProviderID,
		},
	}
	
	if userInfo != nil {
		result.Extra["email"] = userInfo.Email
		result.Extra["name"] = userInfo.Name
		result.Extra["picture"] = userInfo.Picture
	}
	
	return result, nil
}

// handleAuthorizationCode handles the authorization code flow
func (p *Provider) handleAuthorizationCode(ctx context.Context, creds *providers.OAuthCredentials) (string, error) {
	// Exchange code for token
	token, err := p.flowHandler.ExchangeCode(ctx, creds.Code, creds.State)
	if err != nil {
		return "", fmt.Errorf("failed to exchange code: %w", err)
	}
	
	// Get user info
	userInfo, err := p.flowHandler.GetUserInfo(ctx, token.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to get user info: %w", err)
	}
	
	// Generate user ID (provider:providerUserID)
	userID := fmt.Sprintf("%s:%s", p.config.ProviderID, userInfo.ProviderID)
	
	// Store token and user info
	if err := p.tokenManager.StoreToken(ctx, userID, token); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}
	
	if err := p.tokenManager.StoreUserInfo(ctx, userID, userInfo); err != nil {
		// Don't fail auth if we can't store user info
		// Log this in production
	}
	
	return userID, nil
}

// handleDirectToken handles direct token validation
func (p *Provider) handleDirectToken(ctx context.Context, creds *providers.OAuthCredentials) (string, error) {
	// Get user info using the provided token
	userInfo, err := p.flowHandler.GetUserInfo(ctx, creds.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to validate token: %w", err)
	}
	
	// Generate user ID
	userID := fmt.Sprintf("%s:%s", p.config.ProviderID, userInfo.ProviderID)
	
	// Create token object
	token := &Token{
		AccessToken: creds.AccessToken,
		TokenType:   TokenTypeBearer,
	}
	
	// Store token and user info
	if err := p.tokenManager.StoreToken(ctx, userID, token); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}
	
	if err := p.tokenManager.StoreUserInfo(ctx, userID, userInfo); err != nil {
		// Don't fail auth if we can't store user info
		// Log this in production
	}
	
	return userID, nil
}

// Supports checks if the provider supports the given credentials
func (p *Provider) Supports(credentials interface{}) bool {
	_, ok := credentials.(*providers.OAuthCredentials)
	return ok
}

// GetAuthorizationURL generates an authorization URL for OAuth2 flow
func (p *Provider) GetAuthorizationURL(ctx context.Context, extra map[string]string) (string, error) {
	var state string
	var err error
	
	// Generate state parameter if enabled
	if p.config.UseStateParam {
		state, err = p.stateManager.CreateState(ctx, p.config.RedirectURL, extra)
		if err != nil {
			return "", fmt.Errorf("failed to create state: %w", err)
		}
	}
	
	// Generate authorization URL
	authURL, err := p.flowHandler.GetAuthorizationURL(ctx, state, extra)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization URL: %w", err)
	}
	
	return authURL, nil
}

// RefreshUserToken refreshes the OAuth2 token for a user
func (p *Provider) RefreshUserToken(ctx context.Context, userID string) error {
	// Get current token
	token, err := p.tokenManager.GetToken(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get current token: %w", err)
	}
	
	// Check if refresh is needed
	if !p.tokenManager.IsTokenExpired(token, p.config.TokenRefreshThreshold) {
		return nil // Token is still valid
	}
	
	// Refresh token
	newToken, err := p.flowHandler.RefreshToken(ctx, token.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	
	// Store new token
	if err := p.tokenManager.StoreToken(ctx, userID, newToken); err != nil {
		return fmt.Errorf("failed to store refreshed token: %w", err)
	}
	
	return nil
}

// GetUserInfo retrieves the cached user information
func (p *Provider) GetUserInfo(ctx context.Context, userID string) (*UserInfo, error) {
	return p.tokenManager.GetUserInfo(ctx, userID)
}

// RevokeUserToken revokes the OAuth2 token for a user
func (p *Provider) RevokeUserToken(ctx context.Context, userID string) error {
	// Delete token
	if err := p.tokenManager.DeleteToken(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	
	// Note: Most OAuth2 providers don't support token revocation
	// This just removes it from our storage
	
	return nil
}

// Validate validates the provider configuration
func (p *Provider) Validate(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("provider not configured")
	}
	return p.config.Validate()
}