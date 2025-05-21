package providers

import (
	"context"
	"fmt"
	"sync"

	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/plugin/factory"
)

// Registry manages registered authentication providers and factories
type Registry interface {
	// RegisterAuthProvider registers an authentication provider
	RegisterAuthProvider(provider AuthProvider) error

	// GetAuthProvider returns an authentication provider by ID
	GetAuthProvider(id string) (AuthProvider, error)

	// RegisterAuthProviderFactory registers an authentication provider factory
	RegisterAuthProviderFactory(id string, factory factory.Factory) error

	// GetAuthProviderFactory returns an authentication provider factory by ID
	GetAuthProviderFactory(id string) (factory.Factory, error)

	// ListAuthProviders returns all registered authentication providers
	ListAuthProviders() []AuthProvider

	// CreateAuthProvider creates a new authentication provider using a registered factory
	CreateAuthProvider(ctx context.Context, factoryID, providerID string, config interface{}) (AuthProvider, error)
}

// DefaultRegistry is the default implementation of the Registry interface
type DefaultRegistry struct {
	// providers is a map of provider ID to provider
	providers map[string]AuthProvider

	// factories is a map of factory ID to factory
	factories map[string]factory.Factory

	// Thread safety
	mu sync.RWMutex
}

// NewDefaultRegistry creates a new DefaultRegistry
func NewDefaultRegistry() *DefaultRegistry {
	return &DefaultRegistry{
		providers: make(map[string]AuthProvider),
		factories: make(map[string]factory.Factory),
	}
}

// RegisterAuthProvider registers an authentication provider
func (r *DefaultRegistry) RegisterAuthProvider(provider AuthProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := provider.GetMetadata().ID
	if _, exists := r.providers[id]; exists {
		return errors.NewPluginError(
			errors.ErrProviderExists,
			"auth",
			id,
			"provider already registered",
		)
	}

	r.providers[id] = provider
	return nil
}

// GetAuthProvider returns an authentication provider by ID
func (r *DefaultRegistry) GetAuthProvider(id string) (AuthProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, exists := r.providers[id]
	if !exists {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			"auth",
			id,
			"provider not found",
		)
	}

	return provider, nil
}

// RegisterAuthProviderFactory registers an authentication provider factory
func (r *DefaultRegistry) RegisterAuthProviderFactory(id string, factory factory.Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[id]; exists {
		return errors.NewPluginError(
			errors.ErrProviderExists,
			"auth",
			id,
			"factory already registered",
		)
	}

	r.factories[id] = factory
	return nil
}

// GetAuthProviderFactory returns an authentication provider factory by ID
func (r *DefaultRegistry) GetAuthProviderFactory(id string) (factory.Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	f, exists := r.factories[id]
	if !exists {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			"auth",
			id,
			"factory not found",
		)
	}

	return f, nil
}

// ListAuthProviders returns all registered authentication providers
func (r *DefaultRegistry) ListAuthProviders() []AuthProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]AuthProvider, 0, len(r.providers))
	for _, provider := range r.providers {
		result = append(result, provider)
	}

	return result
}

// CreateAuthProvider creates a new authentication provider using a registered factory
func (r *DefaultRegistry) CreateAuthProvider(ctx context.Context, factoryID, providerID string, config interface{}) (AuthProvider, error) {
	r.mu.RLock()
	factory, exists := r.factories[factoryID]
	r.mu.RUnlock()

	if !exists {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			"auth",
			factoryID,
			"factory not found",
		)
	}

	// Create the provider
	provider, err := factory.Create(providerID, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	// Type assertion
	authProvider, ok := provider.(AuthProvider)
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrIncompatiblePlugin,
			"auth",
			providerID,
			"factory did not return an AuthProvider",
		)
	}

	return authProvider, nil
}