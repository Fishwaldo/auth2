package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FlowHandler handles OAuth2 authorization and token flows
type FlowHandler struct {
	config      *Config
	httpClient  *http.Client
	stateManager *StateManager
	tokenManager *TokenManager
}

// NewFlowHandler creates a new flow handler
func NewFlowHandler(config *Config, stateManager *StateManager, tokenManager *TokenManager) *FlowHandler {
	return &FlowHandler{
		config:       config,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		stateManager: stateManager,
		tokenManager: tokenManager,
	}
}

// GetAuthorizationURL generates the authorization URL for the OAuth2 flow
func (fh *FlowHandler) GetAuthorizationURL(ctx context.Context, state string, extra map[string]string) (string, error) {
	// Parse the base URL
	authURL, err := url.Parse(fh.config.AuthURL)
	if err != nil {
		return "", fmt.Errorf("invalid auth URL: %w", err)
	}
	
	// Build query parameters
	params := url.Values{}
	params.Set("response_type", string(ResponseTypeCode))
	params.Set("client_id", fh.config.ClientID)
	params.Set("redirect_uri", fh.config.RedirectURL)
	
	if len(fh.config.Scopes) > 0 {
		params.Set("scope", strings.Join(fh.config.Scopes, " "))
	}
	
	if state != "" {
		params.Set("state", state)
	}
	
	// Add any additional auth parameters
	for key, value := range fh.config.AuthParams {
		params.Set(key, value)
	}
	
	// Add extra parameters
	for key, value := range extra {
		params.Set(key, value)
	}
	
	authURL.RawQuery = params.Encode()
	return authURL.String(), nil
}

// ExchangeCode exchanges an authorization code for tokens
func (fh *FlowHandler) ExchangeCode(ctx context.Context, code, state string) (*Token, error) {
	// Validate state if enabled
	if fh.config.UseStateParam && state != "" {
		stateData, err := fh.stateManager.ValidateState(ctx, state)
		if err != nil {
			return nil, err
		}
		
		// Verify redirect URI matches
		if stateData.RedirectURI != fh.config.RedirectURL {
			return nil, fmt.Errorf("redirect URI mismatch")
		}
	}
	
	// Prepare token request
	data := url.Values{}
	data.Set("grant_type", string(GrantTypeAuthorizationCode))
	data.Set("code", code)
	data.Set("redirect_uri", fh.config.RedirectURL)
	data.Set("client_id", fh.config.ClientID)
	
	if fh.config.ClientSecret != "" {
		data.Set("client_secret", fh.config.ClientSecret)
	}
	
	// Add any additional token parameters
	for key, value := range fh.config.TokenParams {
		data.Set(key, value)
	}
	
	// Make token request
	resp, err := fh.httpClient.PostForm(fh.config.TokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}
	
	// Parse response
	tokenResp, err := ParseTokenResponse(body)
	if err != nil {
		return nil, err
	}
	
	// Convert to token
	token := ConvertTokenResponse(tokenResp)
	
	return token, nil
}

// RefreshToken refreshes an OAuth2 token
func (fh *FlowHandler) RefreshToken(ctx context.Context, refreshToken string) (*Token, error) {
	if refreshToken == "" {
		return nil, ErrNoRefreshToken
	}
	
	// Prepare refresh request
	data := url.Values{}
	data.Set("grant_type", string(GrantTypeRefreshToken))
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", fh.config.ClientID)
	
	if fh.config.ClientSecret != "" {
		data.Set("client_secret", fh.config.ClientSecret)
	}
	
	// Add scopes if configured
	if len(fh.config.Scopes) > 0 {
		data.Set("scope", strings.Join(fh.config.Scopes, " "))
	}
	
	// Make refresh request
	resp, err := fh.httpClient.PostForm(fh.config.TokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}
	
	// Parse response
	tokenResp, err := ParseTokenResponse(body)
	if err != nil {
		return nil, err
	}
	
	// Convert to token
	token := ConvertTokenResponse(tokenResp)
	
	// Some providers don't return a new refresh token
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	
	return token, nil
}

// GetUserInfo fetches user information using an access token
func (fh *FlowHandler) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if fh.config.UserInfoURL == "" {
		return nil, fmt.Errorf("user info URL not configured")
	}
	
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", fh.config.UserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}
	
	// Add authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Accept", "application/json")
	
	// Make request
	resp, err := fh.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("user info request failed: %w", err)
	}
	defer resp.Body.Close()
	
	// Check status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("user info request failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}
	
	// Parse response
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("failed to parse user info response: %w", err)
	}
	
	// Map to UserInfo using configured mapping function
	mappingFunc := fh.config.ProfileMap
	if mappingFunc == nil {
		mappingFunc = DefaultProfileMapping
	}
	
	userInfo, err := mappingFunc(data)
	if err != nil {
		return nil, fmt.Errorf("failed to map user profile: %w", err)
	}
	
	// Set provider name if not set by mapping
	if userInfo.ProviderName == "" {
		userInfo.ProviderName = fh.config.ProviderName
	}
	
	return userInfo, nil
}