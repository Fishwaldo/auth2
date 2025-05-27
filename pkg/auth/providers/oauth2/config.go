package oauth2

import (
	"fmt"
	"time"

	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Config represents the configuration for an OAuth2 provider
type Config struct {
	// OAuth2 client configuration
	ClientID     string   `json:"client_id" mapstructure:"client_id"`
	ClientSecret string   `json:"client_secret" mapstructure:"client_secret"`
	RedirectURL  string   `json:"redirect_url" mapstructure:"redirect_url"`
	Scopes       []string `json:"scopes" mapstructure:"scopes"`
	
	// OAuth2 endpoints
	AuthURL     string `json:"auth_url" mapstructure:"auth_url"`
	TokenURL    string `json:"token_url" mapstructure:"token_url"`
	UserInfoURL string `json:"user_info_url" mapstructure:"user_info_url"`
	
	// Provider information
	ProviderName string             `json:"provider_name" mapstructure:"provider_name"`
	ProviderID   string             `json:"provider_id" mapstructure:"provider_id"`
	ProfileMap   ProfileMappingFunc `json:"-" mapstructure:"-"`
	
	// Security settings
	UseStateParam bool          `json:"use_state_param" mapstructure:"use_state_param"`
	StateTTL      time.Duration `json:"state_ttl" mapstructure:"state_ttl"`
	UsePKCE       bool          `json:"use_pkce" mapstructure:"use_pkce"`
	
	// Token settings
	TokenRefreshThreshold time.Duration `json:"token_refresh_threshold" mapstructure:"token_refresh_threshold"`
	
	// Storage
	StateStore metadata.StateStore `json:"-" mapstructure:"-"`
	
	// Additional parameters to send
	AuthParams  map[string]string `json:"auth_params" mapstructure:"auth_params"`
	TokenParams map[string]string `json:"token_params" mapstructure:"token_params"`
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		UseStateParam:         true,
		StateTTL:              10 * time.Minute,
		UsePKCE:               false,
		TokenRefreshThreshold: 5 * time.Minute,
		AuthParams:            make(map[string]string),
		TokenParams:           make(map[string]string),
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return ErrMissingClientID
	}
	
	if c.ClientSecret == "" && !c.UsePKCE {
		return ErrMissingClientSecret
	}
	
	if c.AuthURL == "" {
		return ErrMissingAuthURL
	}
	
	if c.TokenURL == "" {
		return ErrMissingTokenURL
	}
	
	if c.RedirectURL == "" {
		return fmt.Errorf("oauth2: missing redirect URL")
	}
	
	if c.ProviderName == "" {
		c.ProviderName = "oauth2"
	}
	
	if c.ProviderID == "" {
		c.ProviderID = c.ProviderName
	}
	
	if c.StateStore == nil {
		return fmt.Errorf("oauth2: missing state store")
	}
	
	if c.StateTTL <= 0 {
		c.StateTTL = 10 * time.Minute
	}
	
	if c.TokenRefreshThreshold <= 0 {
		c.TokenRefreshThreshold = 5 * time.Minute
	}
	
	return nil
}

// CommonProviderConfigs provides pre-configured settings for common OAuth2 providers
var CommonProviderConfigs = map[string]ProviderConfig{
	"google": {
		Name:        "google",
		AuthURL:     "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:    "https://oauth2.googleapis.com/token",
		UserInfoURL: "https://www.googleapis.com/oauth2/v2/userinfo",
		Scopes:      []string{"openid", "email", "profile"},
		ProfileMap:  GoogleProfileMapping,
	},
	"github": {
		Name:        "github",
		AuthURL:     "https://github.com/login/oauth/authorize",
		TokenURL:    "https://github.com/login/oauth/access_token",
		UserInfoURL: "https://api.github.com/user",
		Scopes:      []string{"read:user", "user:email"},
		ProfileMap:  GitHubProfileMapping,
	},
	"microsoft": {
		Name:        "microsoft",
		AuthURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		UserInfoURL: "https://graph.microsoft.com/v1.0/me",
		Scopes:      []string{"openid", "email", "profile"},
		ProfileMap:  MicrosoftProfileMapping,
	},
	"facebook": {
		Name:        "facebook",
		AuthURL:     "https://www.facebook.com/v12.0/dialog/oauth",
		TokenURL:    "https://graph.facebook.com/v12.0/oauth/access_token",
		UserInfoURL: "https://graph.facebook.com/me?fields=id,email,name,first_name,last_name,picture",
		Scopes:      []string{"email", "public_profile"},
		ProfileMap:  FacebookProfileMapping,
	},
}

// ApplyProviderConfig applies a provider configuration to the config
func (c *Config) ApplyProviderConfig(providerName string) error {
	providerConfig, ok := CommonProviderConfigs[providerName]
	if !ok {
		return fmt.Errorf("oauth2: unknown provider: %s", providerName)
	}
	
	c.ProviderName = providerConfig.Name
	c.ProviderID = providerConfig.Name
	c.AuthURL = providerConfig.AuthURL
	c.TokenURL = providerConfig.TokenURL
	c.UserInfoURL = providerConfig.UserInfoURL
	
	if len(c.Scopes) == 0 {
		c.Scopes = providerConfig.Scopes
	}
	
	if c.ProfileMap == nil {
		c.ProfileMap = providerConfig.ProfileMap
	}
	
	return nil
}