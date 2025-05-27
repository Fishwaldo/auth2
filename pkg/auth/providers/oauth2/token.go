package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// TokenManager handles OAuth2 token storage and refresh
type TokenManager struct {
	store    metadata.StateStore
	provider string
}

// NewTokenManager creates a new token manager
func NewTokenManager(store metadata.StateStore, provider string) *TokenManager {
	return &TokenManager{
		store:    store,
		provider: provider,
	}
}

// StoreToken stores an OAuth2 token for a user
func (tm *TokenManager) StoreToken(ctx context.Context, userID string, token *Token) error {
	// Calculate expiration time if not set
	if token.ExpiresAt.IsZero() && token.ExpiresIn > 0 {
		token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	
	if err := tm.store.StoreState(ctx, "oauth2_tokens", tm.provider, userID, token); err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}
	
	return nil
}

// GetToken retrieves an OAuth2 token for a user
func (tm *TokenManager) GetToken(ctx context.Context, userID string) (*Token, error) {
	var token Token
	
	err := tm.store.GetState(ctx, "oauth2_tokens", tm.provider, userID, &token)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}
	
	return &token, nil
}

// DeleteToken removes an OAuth2 token for a user
func (tm *TokenManager) DeleteToken(ctx context.Context, userID string) error {
	if err := tm.store.DeleteState(ctx, "oauth2_tokens", tm.provider, userID); err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}
	
	return nil
}

// IsTokenExpired checks if a token is expired
func (tm *TokenManager) IsTokenExpired(token *Token, threshold time.Duration) bool {
	if token.ExpiresAt.IsZero() {
		return false // No expiration set
	}
	
	// Check if token expires within the threshold
	return time.Now().Add(threshold).After(token.ExpiresAt)
}

// StoreUserInfo stores user profile information
func (tm *TokenManager) StoreUserInfo(ctx context.Context, userID string, userInfo *UserInfo) error {
	if err := tm.store.StoreState(ctx, "oauth2_profiles", tm.provider, userID, userInfo); err != nil {
		return fmt.Errorf("failed to store user info: %w", err)
	}
	
	return nil
}

// GetUserInfo retrieves stored user profile information
func (tm *TokenManager) GetUserInfo(ctx context.Context, userID string) (*UserInfo, error) {
	var userInfo UserInfo
	
	err := tm.store.GetState(ctx, "oauth2_profiles", tm.provider, userID, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user info: %w", err)
	}
	
	return &userInfo, nil
}

// ParseTokenResponse parses a token response from JSON
func ParseTokenResponse(data []byte) (*TokenResponse, error) {
	var response TokenResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	
	// Check for error in response
	if response.Error != "" {
		return nil, WrapProviderError(response.Error, response.ErrorDescription, response.ErrorURI)
	}
	
	return &response, nil
}

// ConvertTokenResponse converts a TokenResponse to a Token
func ConvertTokenResponse(response *TokenResponse) *Token {
	token := &Token{
		AccessToken:  response.AccessToken,
		TokenType:    TokenType(response.TokenType),
		RefreshToken: response.RefreshToken,
		ExpiresIn:    response.ExpiresIn,
		Scope:        response.Scope,
		IDToken:      response.IDToken,
	}
	
	// Calculate expiration time
	if token.ExpiresIn > 0 {
		token.ExpiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	
	return token
}