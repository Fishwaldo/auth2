package oauth2_test

import (
	"context"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/auth/providers/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestTokenManager_StoreAndGetToken(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStateStore)
	
	tokenManager := oauth2.NewTokenManager(mockStore, "test-provider")

	tests := []struct {
		name       string
		userID     string
		token      *oauth2.Token
		setupMocks func()
		wantErr    bool
	}{
		{
			name:   "store and retrieve token",
			userID: "user123",
			token: &oauth2.Token{
				AccessToken:  "access-token",
				TokenType:    oauth2.TokenTypeBearer,
				RefreshToken: "refresh-token",
				ExpiresIn:    3600,
				Scope:        "email profile",
			},
			setupMocks: func() {
				// Store
				mockStore.On("StoreState", ctx, "oauth2_tokens", "test-provider", "user123", mock.MatchedBy(func(token *oauth2.Token) bool {
					return token.AccessToken == "access-token" && !token.ExpiresAt.IsZero()
				})).Return(nil).Once()
				
				// Get
				storedToken := &oauth2.Token{
					AccessToken:  "access-token",
					TokenType:    oauth2.TokenTypeBearer,
					RefreshToken: "refresh-token",
					ExpiresIn:    3600,
					ExpiresAt:    time.Now().Add(time.Hour),
					Scope:        "email profile",
				}
				mockStore.On("GetState", ctx, "oauth2_tokens", "test-provider", "user123", mock.Anything).
					Run(func(args mock.Arguments) {
						ptr := args.Get(4).(*oauth2.Token)
						*ptr = *storedToken
					}).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name:   "store error",
			userID: "user123",
			token:  &oauth2.Token{AccessToken: "token"},
			setupMocks: func() {
				mockStore.On("StoreState", ctx, "oauth2_tokens", "test-provider", "user123", mock.Anything).
					Return(assert.AnError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.ExpectedCalls = nil
			mockStore.Calls = nil
			
			if tt.setupMocks != nil {
				tt.setupMocks()
			}
			
			// Test Store
			err := tokenManager.StoreToken(ctx, tt.userID, tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				
				// Test Get
				retrieved, err := tokenManager.GetToken(ctx, tt.userID)
				assert.NoError(t, err)
				assert.Equal(t, tt.token.AccessToken, retrieved.AccessToken)
				assert.Equal(t, tt.token.TokenType, retrieved.TokenType)
				assert.Equal(t, tt.token.RefreshToken, retrieved.RefreshToken)
				assert.Equal(t, tt.token.Scope, retrieved.Scope)
			}
			
			mockStore.AssertExpectations(t)
		})
	}
}

func TestTokenManager_DeleteToken(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStateStore)
	
	tokenManager := oauth2.NewTokenManager(mockStore, "test-provider")

	tests := []struct {
		name       string
		userID     string
		setupMocks func()
		wantErr    bool
	}{
		{
			name:   "delete token successfully",
			userID: "user123",
			setupMocks: func() {
				mockStore.On("DeleteState", ctx, "oauth2_tokens", "test-provider", "user123").
					Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name:   "delete error",
			userID: "user123",
			setupMocks: func() {
				mockStore.On("DeleteState", ctx, "oauth2_tokens", "test-provider", "user123").
					Return(assert.AnError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.ExpectedCalls = nil
			mockStore.Calls = nil
			
			if tt.setupMocks != nil {
				tt.setupMocks()
			}
			
			err := tokenManager.DeleteToken(ctx, tt.userID)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			
			mockStore.AssertExpectations(t)
		})
	}
}

func TestTokenManager_IsTokenExpired(t *testing.T) {
	tokenManager := oauth2.NewTokenManager(nil, "test-provider")

	tests := []struct {
		name      string
		token     *oauth2.Token
		threshold time.Duration
		want      bool
	}{
		{
			name: "token not expired",
			token: &oauth2.Token{
				ExpiresAt: time.Now().Add(2 * time.Hour),
			},
			threshold: 5 * time.Minute,
			want:      false,
		},
		{
			name: "token expired",
			token: &oauth2.Token{
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			threshold: 5 * time.Minute,
			want:      true,
		},
		{
			name: "token expires within threshold",
			token: &oauth2.Token{
				ExpiresAt: time.Now().Add(3 * time.Minute),
			},
			threshold: 5 * time.Minute,
			want:      true,
		},
		{
			name: "no expiration set",
			token: &oauth2.Token{
				ExpiresAt: time.Time{},
			},
			threshold: 5 * time.Minute,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tokenManager.IsTokenExpired(tt.token, tt.threshold)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseTokenResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    *oauth2.TokenResponse
		wantErr bool
		errType error
	}{
		{
			name: "valid response",
			data: []byte(`{
				"access_token": "test-access-token",
				"token_type": "Bearer",
				"expires_in": 3600,
				"refresh_token": "test-refresh-token",
				"scope": "email profile"
			}`),
			want: &oauth2.TokenResponse{
				AccessToken:  "test-access-token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "test-refresh-token",
				Scope:        "email profile",
			},
			wantErr: false,
		},
		{
			name: "error response",
			data: []byte(`{
				"error": "invalid_request",
				"error_description": "Invalid authorization code",
				"error_uri": "https://provider.com/docs/errors"
			}`),
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			data:    []byte(`{invalid json`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := oauth2.ParseTokenResponse(tt.data)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, tt.want.AccessToken, got.AccessToken)
				assert.Equal(t, tt.want.TokenType, got.TokenType)
				assert.Equal(t, tt.want.ExpiresIn, got.ExpiresIn)
				assert.Equal(t, tt.want.RefreshToken, got.RefreshToken)
				assert.Equal(t, tt.want.Scope, got.Scope)
			}
		})
	}
}

func TestConvertTokenResponse(t *testing.T) {
	tests := []struct {
		name     string
		response *oauth2.TokenResponse
		want     func(*oauth2.Token) bool
	}{
		{
			name: "convert with expiration",
			response: &oauth2.TokenResponse{
				AccessToken:  "test-token",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
				RefreshToken: "refresh-token",
				Scope:        "email",
				IDToken:      "id-token",
			},
			want: func(token *oauth2.Token) bool {
				return token.AccessToken == "test-token" &&
					token.TokenType == oauth2.TokenTypeBearer &&
					token.ExpiresIn == 3600 &&
					!token.ExpiresAt.IsZero() &&
					token.RefreshToken == "refresh-token" &&
					token.Scope == "email" &&
					token.IDToken == "id-token"
			},
		},
		{
			name: "convert without expiration",
			response: &oauth2.TokenResponse{
				AccessToken: "test-token",
				TokenType:   "Bearer",
			},
			want: func(token *oauth2.Token) bool {
				return token.AccessToken == "test-token" &&
					token.ExpiresAt.IsZero()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := oauth2.ConvertTokenResponse(tt.response)
			assert.True(t, tt.want(got))
		})
	}
}

func TestTokenManager_UserInfo(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStateStore)
	
	tokenManager := oauth2.NewTokenManager(mockStore, "test-provider")

	userInfo := &oauth2.UserInfo{
		ID:            "12345",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Picture:       "https://example.com/avatar.jpg",
		ProviderID:    "12345",
		ProviderName:  "test-provider",
		Raw: map[string]interface{}{
			"id":    "12345",
			"email": "test@example.com",
		},
	}

	// Test store
	mockStore.On("StoreState", ctx, "oauth2_profiles", "test-provider", "user123", userInfo).
		Return(nil).Once()
	
	err := tokenManager.StoreUserInfo(ctx, "user123", userInfo)
	assert.NoError(t, err)

	// Test retrieve
	mockStore.On("GetState", ctx, "oauth2_profiles", "test-provider", "user123", mock.Anything).
		Run(func(args mock.Arguments) {
			ptr := args.Get(4).(*oauth2.UserInfo)
			*ptr = *userInfo
		}).Return(nil).Once()
	
	retrieved, err := tokenManager.GetUserInfo(ctx, "user123")
	assert.NoError(t, err)
	assert.Equal(t, userInfo.ID, retrieved.ID)
	assert.Equal(t, userInfo.Email, retrieved.Email)
	assert.Equal(t, userInfo.Name, retrieved.Name)
	
	mockStore.AssertExpectations(t)
}