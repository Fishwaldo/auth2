package registry

import (
	"context"
	"fmt"
	"sync"
	
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Registry manages registered providers
type Registry struct {
	// Maps for different provider types
	providers map[metadata.ProviderType]map[string]metadata.Provider
	
	// Thread safety
	mu sync.RWMutex
}

// NewRegistry creates a new provider registry
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[metadata.ProviderType]map[string]metadata.Provider),
	}
}

// RegisterProvider registers a provider with the registry
func (r *Registry) RegisterProvider(provider metadata.Provider) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	meta := provider.GetMetadata()
	
	// Validate provider metadata
	if err := metadata.ValidateMetadata(meta); err != nil {
		return errors.NewPluginError(err, string(meta.Type), meta.ID, "invalid metadata")
	}
	
	// Initialize the provider type map if it doesn't exist
	if _, ok := r.providers[meta.Type]; !ok {
		r.providers[meta.Type] = make(map[string]metadata.Provider)
	}
	
	// Check if provider is already registered
	if _, ok := r.providers[meta.Type][meta.ID]; ok {
		return errors.NewPluginError(
			errors.ErrIncompatiblePlugin,
			string(meta.Type),
			meta.ID,
			"provider already registered",
		)
	}
	
	// Register the provider
	r.providers[meta.Type][meta.ID] = provider
	
	return nil
}

// UnregisterProvider removes a provider from the registry
func (r *Registry) UnregisterProvider(providerType metadata.ProviderType, providerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Check if provider type exists
	if _, ok := r.providers[providerType]; !ok {
		return errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			providerID,
			"provider type not found",
		)
	}
	
	// Check if provider exists
	if _, ok := r.providers[providerType][providerID]; !ok {
		return errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			providerID,
			"provider not found",
		)
	}
	
	// Remove the provider
	delete(r.providers[providerType], providerID)
	
	return nil
}

// GetProvider returns a provider by type and ID
func (r *Registry) GetProvider(providerType metadata.ProviderType, providerID string) (metadata.Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if provider type exists
	providerMap, ok := r.providers[providerType]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			providerID,
			"provider type not registered",
		)
	}
	
	// Check if provider exists
	provider, ok := providerMap[providerID]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			providerID,
			"provider not found",
		)
	}
	
	return provider, nil
}

// GetProviders returns all registered providers of a given type
func (r *Registry) GetProviders(providerType metadata.ProviderType) (map[string]metadata.Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if provider type exists
	providerMap, ok := r.providers[providerType]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			"",
			"provider type not registered",
		)
	}
	
	// Create a copy of the provider map to prevent concurrent modification
	result := make(map[string]metadata.Provider, len(providerMap))
	for id, provider := range providerMap {
		result[id] = provider
	}
	
	return result, nil
}

// ListProviderTypes returns all registered provider types
func (r *Registry) ListProviderTypes() []metadata.ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var types []metadata.ProviderType
	for t := range r.providers {
		types = append(types, t)
	}
	
	return types
}

// GetProviderMetadata returns metadata for all registered providers of a given type
func (r *Registry) GetProviderMetadata(providerType metadata.ProviderType) ([]metadata.ProviderMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if provider type exists
	providerMap, ok := r.providers[providerType]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			"",
			"provider type not registered",
		)
	}
	
	// Extract metadata from all providers
	var metadataList []metadata.ProviderMetadata
	for _, provider := range providerMap {
		metadataList = append(metadataList, provider.GetMetadata())
	}
	
	return metadataList, nil
}

// ValidateProviders validates all registered providers
func (r *Registry) ValidateProviders(ctx context.Context) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var errs []error
	
	// Validate all registered providers
	for providerType, providerMap := range r.providers {
		for providerID, provider := range providerMap {
			if err := provider.Validate(ctx); err != nil {
				errs = append(errs, errors.NewPluginError(
					err,
					string(providerType),
					providerID,
					"provider validation failed",
				))
			}
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("provider validation errors: %v", errs)
	}
	
	return nil
}

// InitializeProviders initializes all registered providers with their configurations
func (r *Registry) InitializeProviders(ctx context.Context, configs map[string]interface{}) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var errs []error
	
	// Initialize all registered providers
	for providerType, providerMap := range r.providers {
		for providerID, provider := range providerMap {
			// Get provider-specific configuration
			configKey := fmt.Sprintf("%s.%s", providerType, providerID)
			config, ok := configs[configKey]
			if !ok {
				// Use nil config if not provided
				config = nil
			}
			
			// Initialize the provider
			if err := provider.Initialize(ctx, config); err != nil {
				errs = append(errs, errors.NewPluginError(
					err,
					string(providerType),
					providerID,
					"provider initialization failed",
				))
			}
		}
	}
	
	if len(errs) > 0 {
		return fmt.Errorf("provider initialization errors: %v", errs)
	}
	
	return nil
}