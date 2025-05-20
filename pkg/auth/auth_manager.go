package auth

import (
	"context"
	"fmt"
	"sync"
	
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/plugin/registry"
	"github.com/google/uuid"
)

// ManagerConfig contains configuration for the AuthManager
type ManagerConfig struct {
	DefaultProviderID      string
	MFARequired            bool
	MFARequiredForRoles    []string
	SessionDuration        int64
	TokenExpiration        int64
	MaxLoginAttempts       int
	LockoutDuration        int64
	PasswordPolicyEnabled  bool
}

// Manager manages authentication providers and handles authentication flows
type Manager struct {
	// Config is the configuration for the manager
	Config ManagerConfig
	
	// Providers is a map of provider ID to provider
	providers map[string]providers.AuthProvider
	
	// Registry is the provider registry
	registry *registry.Registry
	
	// RWMutex for thread safety
	mu sync.RWMutex
}

// NewManager creates a new AuthManager with the provided registry and configuration
func NewManager(reg *registry.Registry, config ManagerConfig) *Manager {
	return &Manager{
		Config:    config,
		providers: make(map[string]providers.AuthProvider),
		registry:  reg,
	}
}

// RegisterProvider registers an auth provider with the manager
func (m *Manager) RegisterProvider(provider providers.AuthProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	meta := provider.GetMetadata()
	
	// Check if provider is already registered
	if _, exists := m.providers[meta.ID]; exists {
		return errors.NewPluginError(
			errors.ErrIncompatiblePlugin,
			string(meta.Type),
			meta.ID,
			"provider already registered",
		)
	}
	
	// Register with the global registry if provided
	if m.registry != nil {
		if err := m.registry.RegisterProvider(provider); err != nil {
			return err
		}
	}
	
	// Register with the local provider map
	m.providers[meta.ID] = provider
	
	return nil
}

// GetProvider returns a provider by ID
func (m *Manager) GetProvider(providerID string) (providers.AuthProvider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	provider, exists := m.providers[providerID]
	if !exists {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(metadata.ProviderTypeAuth),
			providerID,
			"provider not registered",
		)
	}
	
	return provider, nil
}

// GetProviders returns all registered providers
func (m *Manager) GetProviders() map[string]providers.AuthProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Create a copy to prevent concurrent modification
	result := make(map[string]providers.AuthProvider, len(m.providers))
	for id, provider := range m.providers {
		result[id] = provider
	}
	
	return result
}

// UnregisterProvider removes a provider from the manager
func (m *Manager) UnregisterProvider(providerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Check if provider exists
	if _, exists := m.providers[providerID]; !exists {
		return errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(metadata.ProviderTypeAuth),
			providerID,
			"provider not registered",
		)
	}
	
	// Unregister from the global registry if provided
	if m.registry != nil {
		if err := m.registry.UnregisterProvider(metadata.ProviderTypeAuth, providerID); err != nil {
			return err
		}
	}
	
	// Unregister from the local provider map
	delete(m.providers, providerID)
	
	return nil
}

// AuthenticateWithCredentials authenticates a user with the provided credentials
func (m *Manager) AuthenticateWithCredentials(ctx context.Context, credentials providers.Credentials) (*providers.AuthResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Check if we have any providers
	if len(m.providers) == 0 {
		return nil, errors.WrapError(
			errors.ErrServiceUnavailable,
			errors.CodeUnavailable,
			"no authentication providers registered",
		)
	}
	
	// Create authentication context with request ID
	authCtx := &providers.AuthContext{
		OriginalContext: ctx,
		RequestID:       uuid.New().String(),
		RequestMetadata: make(map[string]interface{}),
	}
	
	// Extract client information from context if available
	if clientIP, ok := ctx.Value("client_ip").(string); ok {
		authCtx.ClientIP = clientIP
	}
	
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		authCtx.UserAgent = userAgent
	}
	
	// Find all providers that support this credential type
	var supportingProviders []providers.AuthProvider
	for _, provider := range m.providers {
		if provider.Supports(credentials) {
			supportingProviders = append(supportingProviders, provider)
		}
	}
	
	if len(supportingProviders) == 0 {
		return nil, errors.WrapError(
			errors.ErrUnsupported,
			errors.CodeUnsupported,
			fmt.Sprintf("no provider supports credentials of type %s", credentials.GetType()),
		)
	}
	
	// Try each provider until one succeeds or all fail
	var lastError error
	var combinedResult *providers.AuthResult
	
	for _, provider := range supportingProviders {
		result, err := provider.Authenticate(authCtx, credentials)
		
		// Return immediately on success
		if err == nil && result.Success {
			return result, nil
		}
		
		// Store last error for context
		lastError = err
		
		// Combine results (for MFA requirements, etc.)
		if combinedResult == nil {
			combinedResult = result
		} else if result != nil {
			// Collect MFA providers across results
			if result.RequiresMFA && len(result.MFAProviders) > 0 {
				if combinedResult.MFAProviders == nil {
					combinedResult.MFAProviders = make([]string, 0)
				}
				combinedResult.MFAProviders = append(combinedResult.MFAProviders, result.MFAProviders...)
			}
			
			// Collect extra data
			if result.Extra != nil {
				if combinedResult.Extra == nil {
					combinedResult.Extra = make(map[string]interface{})
				}
				for k, v := range result.Extra {
					combinedResult.Extra[k] = v
				}
			}
		}
	}
	
	// If all providers failed, return the combined result with the last error
	if combinedResult == nil {
		combinedResult = &providers.AuthResult{
			Success: false,
			Error:   lastError,
		}
	} else {
		combinedResult.Error = lastError
	}
	
	return combinedResult, lastError
}

// AuthenticateWithProviderID authenticates a user with a specific provider
func (m *Manager) AuthenticateWithProviderID(ctx context.Context, providerID string, credentials providers.Credentials) (*providers.AuthResult, error) {
	provider, err := m.GetProvider(providerID)
	if err != nil {
		return nil, err
	}
	
	if !provider.Supports(credentials) {
		return nil, errors.WrapError(
			errors.ErrUnsupported,
			errors.CodeUnsupported,
			fmt.Sprintf("provider %s does not support credentials of type %s", 
				providerID, credentials.GetType()),
		)
	}
	
	// Create authentication context with request ID
	authCtx := &providers.AuthContext{
		OriginalContext: ctx,
		RequestID:       uuid.New().String(),
		RequestMetadata: make(map[string]interface{}),
	}
	
	// Extract client information from context if available
	if clientIP, ok := ctx.Value("client_ip").(string); ok {
		authCtx.ClientIP = clientIP
	}
	
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		authCtx.UserAgent = userAgent
	}
	
	return provider.Authenticate(authCtx, credentials)
}

// ValidateConfig validates the manager configuration
func (m *Manager) ValidateConfig() error {
	if m.Config.DefaultProviderID != "" {
		if _, err := m.GetProvider(m.Config.DefaultProviderID); err != nil {
			return errors.WrapError(
				err,
				errors.CodeConfiguration,
				fmt.Sprintf("default provider %s not registered", m.Config.DefaultProviderID),
			)
		}
	}
	
	return nil
}

// Initialize initializes all registered providers
func (m *Manager) Initialize(ctx context.Context, configs map[string]interface{}) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	var errs []error
	
	// Initialize all registered providers
	for id, provider := range m.providers {
		// Get provider-specific configuration
		configKey := fmt.Sprintf("auth.%s", id)
		config, ok := configs[configKey]
		if !ok {
			// Use nil config if not provided
			config = nil
		}
		
		// Initialize the provider
		if err := provider.Initialize(ctx, config); err != nil {
			errs = append(errs, errors.NewPluginError(
				err,
				string(metadata.ProviderTypeAuth),
				id,
				"provider initialization failed",
			))
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("provider initialization errors: %v", errs)
	}
	
	return nil
}