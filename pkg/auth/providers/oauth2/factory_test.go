package oauth2_test

import (
	"testing"

	"github.com/Fishwaldo/auth2/pkg/auth/providers/oauth2"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory_Create(t *testing.T) {
	mockStore := new(MockStateStore)
	factory := oauth2.NewFactory(mockStore)

	tests := []struct {
		name    string
		config  interface{}
		wantErr bool
		errMsg  string
	}{
		{
			name: "create with Config struct",
			config: &oauth2.Config{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURL:  "http://localhost/callback",
				AuthURL:      "https://provider.com/auth",
				TokenURL:     "https://provider.com/token",
				ProviderName: "test",
			},
			wantErr: false,
		},
		{
			name: "create with map config",
			config: map[string]interface{}{
				"client_id":     "test-client",
				"client_secret": "test-secret",
				"redirect_url":  "http://localhost/callback",
				"auth_url":      "https://provider.com/auth",
				"token_url":     "https://provider.com/token",
				"provider_name": "test",
			},
			wantErr: false,
		},
		{
			name: "create with struct tags",
			config: struct {
				ClientID     string `mapstructure:"client_id"`
				ClientSecret string `mapstructure:"client_secret"`
				RedirectURL  string `mapstructure:"redirect_url"`
				AuthURL      string `mapstructure:"auth_url"`
				TokenURL     string `mapstructure:"token_url"`
			}{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURL:  "http://localhost/callback",
				AuthURL:      "https://provider.com/auth",
				TokenURL:     "https://provider.com/token",
			},
			wantErr: false,
		},
		{
			name: "invalid config - missing client ID",
			config: map[string]interface{}{
				"client_secret": "test-secret",
				"redirect_url":  "http://localhost/callback",
				"auth_url":      "https://provider.com/auth",
				"token_url":     "https://provider.com/token",
			},
			wantErr: true,
			errMsg:  "missing client ID",
		},
		{
			name:    "unsupported config type",
			config:  "invalid",
			wantErr: true,
			errMsg:  "unsupported configuration type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.Create(tt.config)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				
				// Verify it's an OAuth2 provider
				oauth2Provider, ok := provider.(*oauth2.Provider)
				assert.True(t, ok)
				assert.NotNil(t, oauth2Provider)
			}
		})
	}
}

func TestFactory_CreateWithProvider(t *testing.T) {
	mockStore := new(MockStateStore)
	factory := oauth2.NewFactory(mockStore)

	tests := []struct {
		name         string
		providerName string
		config       interface{}
		wantErr      bool
		checkFields  func(*testing.T, metadata.Provider)
	}{
		{
			name:         "create Google provider",
			providerName: "google",
			config: map[string]interface{}{
				"client_id":     "google-client",
				"client_secret": "google-secret",
				"redirect_url":  "http://localhost/callback",
			},
			wantErr: false,
			checkFields: func(t *testing.T, p metadata.Provider) {
				meta := p.GetMetadata()
				assert.Equal(t, "google", meta.ID)
				assert.Contains(t, meta.Name, "google")
			},
		},
		{
			name:         "create GitHub provider",
			providerName: "github",
			config: map[string]interface{}{
				"client_id":     "github-client",
				"client_secret": "github-secret",
				"redirect_url":  "http://localhost/callback",
			},
			wantErr: false,
			checkFields: func(t *testing.T, p metadata.Provider) {
				meta := p.GetMetadata()
				assert.Equal(t, "github", meta.ID)
				assert.Contains(t, meta.Name, "github")
			},
		},
		{
			name:         "unknown provider",
			providerName: "unknown",
			config: map[string]interface{}{
				"client_id":     "test-client",
				"client_secret": "test-secret",
				"redirect_url":  "http://localhost/callback",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.CreateWithProvider(tt.providerName, tt.config)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				
				if tt.checkFields != nil {
					tt.checkFields(t, provider)
				}
			}
		})
	}
}

func TestFactory_GetMetadata(t *testing.T) {
	factory := oauth2.NewFactory(nil)
	meta := factory.GetMetadata()
	
	assert.Equal(t, "oauth2-factory", meta.ID)
	assert.Equal(t, "auth", string(meta.Type))
	assert.Equal(t, "1.0.0", meta.Version)
	assert.NotEmpty(t, meta.Name)
	assert.NotEmpty(t, meta.Description)
	assert.NotEmpty(t, meta.Author)
}

func TestQuickProviders(t *testing.T) {
	mockStore := new(MockStateStore)
	
	clientID := "test-client"
	clientSecret := "test-secret"
	redirectURL := "http://localhost/callback"

	tests := []struct {
		name     string
		provider func() (*oauth2.Provider, error)
		expected string
	}{
		{
			name: "QuickGoogle",
			provider: func() (*oauth2.Provider, error) {
				return oauth2.QuickGoogle(clientID, clientSecret, redirectURL, mockStore)
			},
			expected: "google",
		},
		{
			name: "QuickGitHub",
			provider: func() (*oauth2.Provider, error) {
				return oauth2.QuickGitHub(clientID, clientSecret, redirectURL, mockStore)
			},
			expected: "github",
		},
		{
			name: "QuickMicrosoft",
			provider: func() (*oauth2.Provider, error) {
				return oauth2.QuickMicrosoft(clientID, clientSecret, redirectURL, mockStore)
			},
			expected: "microsoft",
		},
		{
			name: "QuickFacebook",
			provider: func() (*oauth2.Provider, error) {
				return oauth2.QuickFacebook(clientID, clientSecret, redirectURL, mockStore)
			},
			expected: "facebook",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := tt.provider()
			require.NoError(t, err)
			require.NotNil(t, provider)
			
			meta := provider.GetMetadata()
			assert.Equal(t, tt.expected, meta.ID)
			assert.Contains(t, meta.Name, tt.expected)
		})
	}
}

func TestConfig_ParseWithDuration(t *testing.T) {
	mockStore := new(MockStateStore)
	factory := oauth2.NewFactory(mockStore)

	config := map[string]interface{}{
		"client_id":                "test-client",
		"client_secret":            "test-secret",
		"redirect_url":             "http://localhost/callback",
		"auth_url":                 "https://provider.com/auth",
		"token_url":                "https://provider.com/token",
		"state_ttl":                "5m",
		"token_refresh_threshold":  "30s",
		"scopes":                   "email,profile,openid",
	}

	provider, err := factory.Create(config)
	require.NoError(t, err)
	require.NotNil(t, provider)
	
	// Check that durations and slices were parsed correctly
	oauth2Provider := provider.(*oauth2.Provider)
	assert.NotNil(t, oauth2Provider)
	
	// Note: We can't directly access the config from outside the package,
	// but we can verify the provider was created successfully
	meta := oauth2Provider.GetMetadata()
	assert.NotEmpty(t, meta.ID)
}