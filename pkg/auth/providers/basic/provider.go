package basic

import (
	"context"
	"fmt"

	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/user"
)

const (
	// ProviderType is the type of this provider
	ProviderType = "basic"

	// ProviderName is the human-readable name of this provider
	ProviderName = "Basic Authentication"

	// ProviderDescription is the description of this provider
	ProviderDescription = "Username/password authentication provider"

	// ProviderVersion is the version of this provider
	ProviderVersion = "1.0.0"
)

// Config is the configuration for the BasicAuthProvider
type Config struct {
	// AccountLockThreshold is the number of failed login attempts before an account is locked
	AccountLockThreshold int `json:"account_lock_threshold" yaml:"account_lock_threshold"`

	// AccountLockDuration is the duration (in minutes) for which an account is locked
	AccountLockDuration int `json:"account_lock_duration" yaml:"account_lock_duration"`

	// RequireVerifiedEmail indicates whether email verification is required to authenticate
	RequireVerifiedEmail bool `json:"require_verified_email" yaml:"require_verified_email"`
}

// DefaultConfig returns the default configuration for BasicAuthProvider
func DefaultConfig() *Config {
	return &Config{
		AccountLockThreshold:  5,
		AccountLockDuration:   30, // 30 minutes
		RequireVerifiedEmail:  true,
	}
}

// Provider is a basic authentication provider that uses username/password
type Provider struct {
	*providers.BaseAuthProvider
	userStore     user.Store
	passwordUtils user.PasswordUtils
	config        *Config
	initialized   bool
}

// NewProvider creates a new BasicAuthProvider
func NewProvider(id string, userStore user.Store, passwordUtils user.PasswordUtils, config *Config) *Provider {
	if config == nil {
		config = DefaultConfig()
	}

	meta := metadata.ProviderMetadata{
		ID:          id,
		Type:        metadata.ProviderTypeAuth,
		Name:        ProviderName,
		Description: ProviderDescription,
		Version:     ProviderVersion,
	}

	return &Provider{
		BaseAuthProvider: providers.NewBaseAuthProvider(meta),
		userStore:        userStore,
		passwordUtils:    passwordUtils,
		config:           config,
	}
}

// Authenticate verifies username/password credentials and returns an AuthResult
func (p *Provider) Authenticate(ctx *providers.AuthContext, credentials interface{}) (*providers.AuthResult, error) {
	// Verify credentials type
	creds, ok := credentials.(providers.UsernamePasswordCredentials)
	if !ok {
		invalidTypeErr := providers.NewInvalidCredentialsError("invalid credentials type")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      invalidTypeErr,
		}, invalidTypeErr
	}

	// Validate username and password
	if creds.Username == "" || creds.Password == "" {
		emptyCredentialsErr := providers.NewInvalidCredentialsError("username and password are required")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      emptyCredentialsErr,
		}, emptyCredentialsErr
	}

	// Get the user
	usr, err := p.userStore.GetByUsername(ctx.OriginalContext, creds.Username)
	if err != nil {
		// Check if it's a "user not found" error
		if errors.Is(err, errors.ErrNotFound) || errors.Is(err, user.ErrUserNotFound) {
			userNotFoundErr := providers.NewUserNotFoundError(creds.Username)
			return &providers.AuthResult{
				Success:    false,
				ProviderID: p.GetMetadata().ID,
				Error:      userNotFoundErr,
			}, userNotFoundErr
		}
		
		// Return the original error
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			Error:      err,
		}, err
	}

	// Check if the user is enabled
	if !usr.Enabled {
		userDisabledErr := errors.WrapError(errors.ErrUserDisabled, errors.CodeUserDisabled, "account is disabled")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			UserID:     usr.ID,
			Error:      userDisabledErr,
		}, userDisabledErr
	}

	// Check if the user is locked
	if usr.Locked {
		userLockedErr := errors.WrapError(errors.ErrUserLocked, errors.CodeUserLocked, "account is locked")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			UserID:     usr.ID,
			Error:      userLockedErr,
		}, userLockedErr
	}

	// Verify email if required
	if p.config.RequireVerifiedEmail && !usr.EmailVerified {
		emailNotVerifiedErr := errors.WrapError(errors.ErrUnauthenticated, errors.CodeEmailNotVerified, "email verification required")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			UserID:     usr.ID,
			Error:      emailNotVerifiedErr,
		}, emailNotVerifiedErr
	}

	// Verify the password
	match, err := p.passwordUtils.VerifyPassword(ctx.OriginalContext, creds.Password, usr.PasswordHash)
	if err != nil {
		authFailedErr := errors.WrapError(err, errors.CodeAuthFailed, "password verification failed")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			UserID:     usr.ID,
			Error:      authFailedErr,
		}, authFailedErr
	}

	// Check if the password matches
	if !match {
		// Track the failed login attempt
		p.trackFailedLoginAttempt(ctx.OriginalContext, usr)

		invalidCredentialsErr := providers.NewInvalidCredentialsError("invalid credentials")
		return &providers.AuthResult{
			Success:    false,
			ProviderID: p.GetMetadata().ID,
			UserID:     usr.ID,
			Error:      invalidCredentialsErr,
		}, invalidCredentialsErr
	}

	// Reset failed login attempts
	usr.FailedLoginAttempts = 0
	usr.LastLogin = providers.Now()
	
	// Update the user
	err = p.userStore.Update(ctx.OriginalContext, usr)
	if err != nil {
		// Log the error but continue authentication
		fmt.Printf("failed to update user after successful login: %v\n", err)
	}

	// Check if MFA is required
	requiresMFA := usr.MFAEnabled && len(usr.MFAMethods) > 0

	// Create the authentication result
	result := &providers.AuthResult{
		Success:       true,
		UserID:        usr.ID,
		ProviderID:    p.GetMetadata().ID,
		RequiresMFA:   requiresMFA,
		MFAProviders:  usr.MFAMethods,
		Extra:         make(map[string]interface{}),
	}

	if usr.RequirePasswordChange {
		result.Extra["require_password_change"] = true
	}

	return result, nil
}

// Supports returns true if this provider supports the given credentials type
func (p *Provider) Supports(credentials interface{}) bool {
	_, ok := credentials.(providers.UsernamePasswordCredentials)
	return ok
}

// Initialize initializes the provider with the given configuration
func (p *Provider) Initialize(ctx context.Context, config interface{}) error {
	// Check if the provider is already initialized
	if p.initialized {
		return nil
	}

	// If a config is provided, use it
	if config != nil {
		var providerConfig *Config
		var ok bool

		providerConfig, ok = config.(*Config)
		if !ok {
			// Try to convert from map
			configMap, mapOk := config.(map[string]interface{})
			if !mapOk {
				return fmt.Errorf("invalid configuration type: %T", config)
			}

			// Extract values from map
			providerConfig = DefaultConfig()

			// Account lock threshold
			if val, exists := configMap["account_lock_threshold"]; exists {
				if intVal, intOk := val.(int); intOk {
					providerConfig.AccountLockThreshold = intVal
				}
			}

			// Account lock duration
			if val, exists := configMap["account_lock_duration"]; exists {
				if intVal, intOk := val.(int); intOk {
					providerConfig.AccountLockDuration = intVal
				}
			}

			// Require verified email
			if val, exists := configMap["require_verified_email"]; exists {
				if boolVal, boolOk := val.(bool); boolOk {
					providerConfig.RequireVerifiedEmail = boolVal
				}
			}
		}

		p.config = providerConfig
	}

	p.initialized = true
	return nil
}

// Validate validates the provider configuration
func (p *Provider) Validate(ctx context.Context) error {
	// Check if user store is set
	if p.userStore == nil {
		return fmt.Errorf("user store not set")
	}

	// Check if password utils is set
	if p.passwordUtils == nil {
		return fmt.Errorf("password utilities not set")
	}

	// Check if config is set
	if p.config == nil {
		return fmt.Errorf("configuration not set")
	}

	return nil
}

// IsCompatibleVersion checks if the provider is compatible with a given version
func (p *Provider) IsCompatibleVersion(version string) bool {
	// Use the base provider's implementation
	return p.BaseAuthProvider.IsCompatibleVersion(version)
}

// trackFailedLoginAttempt tracks a failed login attempt and locks the account if necessary
func (p *Provider) trackFailedLoginAttempt(ctx context.Context, usr *user.User) {
	// Increment failed login attempts
	usr.FailedLoginAttempts++
	usr.LastFailedLogin = providers.Now()

	// Check if we need to lock the account
	if p.config.AccountLockThreshold > 0 && usr.FailedLoginAttempts >= p.config.AccountLockThreshold {
		usr.Locked = true
		usr.LockoutTime = providers.Now()
		usr.LockoutReason = "Too many failed login attempts"
	}

	// Update the user
	err := p.userStore.Update(ctx, usr)
	if err != nil {
		// Log the error but continue
		fmt.Printf("failed to update user after failed login attempt: %v\n", err)
	}
}