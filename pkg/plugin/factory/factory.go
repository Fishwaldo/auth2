package factory

import (
	"fmt"
	"sync"
	
	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Factory defines the interface for creating provider instances
type Factory interface {
	// Create creates a new provider instance with the given ID and configuration
	Create(id string, config interface{}) (metadata.Provider, error)
	
	// GetType returns the type of provider this factory creates
	GetType() metadata.ProviderType
	
	// GetMetadata returns metadata about the providers this factory can create
	GetMetadata() []metadata.ProviderMetadata
}

// BaseFactory provides a base implementation of the Factory interface
type BaseFactory struct {
	// providerType is the type of provider this factory creates
	providerType metadata.ProviderType
	
	// creator is a function that creates a new provider instance
	creator func(id string, config interface{}) (metadata.Provider, error)
	
	// availableProviders is a list of provider metadata for providers this factory can create
	availableProviders []metadata.ProviderMetadata
}

// NewBaseFactory creates a new BaseFactory
func NewBaseFactory(
	providerType metadata.ProviderType,
	creator func(id string, config interface{}) (metadata.Provider, error),
	availableProviders []metadata.ProviderMetadata,
) *BaseFactory {
	return &BaseFactory{
		providerType:       providerType,
		creator:            creator,
		availableProviders: availableProviders,
	}
}

// Create creates a new provider instance with the given ID and configuration
func (f *BaseFactory) Create(id string, config interface{}) (metadata.Provider, error) {
	// Validate that the factory can create a provider with the given ID
	for _, meta := range f.availableProviders {
		if meta.ID == id {
			return f.creator(id, config)
		}
	}
	
	return nil, errors.NewPluginError(
		errors.ErrPluginNotFound,
		string(f.providerType),
		id,
		"provider ID not supported by this factory",
	)
}

// GetType returns the type of provider this factory creates
func (f *BaseFactory) GetType() metadata.ProviderType {
	return f.providerType
}

// GetMetadata returns metadata about the providers this factory can create
func (f *BaseFactory) GetMetadata() []metadata.ProviderMetadata {
	return f.availableProviders
}

// FactoryRegistry manages provider factories
type FactoryRegistry struct {
	// factories is a map of provider type to a map of factory ID to factory
	factories map[metadata.ProviderType]map[string]Factory
	
	// Thread safety
	mu sync.RWMutex
}

// NewFactoryRegistry creates a new FactoryRegistry
func NewFactoryRegistry() *FactoryRegistry {
	return &FactoryRegistry{
		factories: make(map[metadata.ProviderType]map[string]Factory),
	}
}

// RegisterFactory registers a factory with the registry
func (r *FactoryRegistry) RegisterFactory(factoryID string, factory Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	providerType := factory.GetType()
	
	// Initialize the factory map for this provider type if it doesn't exist
	if _, ok := r.factories[providerType]; !ok {
		r.factories[providerType] = make(map[string]Factory)
	}
	
	// Check if factory is already registered
	if _, ok := r.factories[providerType][factoryID]; ok {
		return errors.NewPluginError(
			errors.ErrIncompatiblePlugin,
			string(providerType),
			factoryID,
			"factory already registered",
		)
	}
	
	// Register the factory
	r.factories[providerType][factoryID] = factory
	
	return nil
}

// GetFactory returns a factory by type and ID
func (r *FactoryRegistry) GetFactory(providerType metadata.ProviderType, factoryID string) (Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if factory type exists
	factoryMap, ok := r.factories[providerType]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			factoryID,
			"factory type not registered",
		)
	}
	
	// Check if factory exists
	factory, ok := factoryMap[factoryID]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			factoryID,
			"factory not found",
		)
	}
	
	return factory, nil
}

// GetFactories returns all registered factories of a given type
func (r *FactoryRegistry) GetFactories(providerType metadata.ProviderType) (map[string]Factory, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if factory type exists
	factoryMap, ok := r.factories[providerType]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			"",
			"factory type not registered",
		)
	}
	
	// Create a copy of the factory map to prevent concurrent modification
	result := make(map[string]Factory, len(factoryMap))
	for id, factory := range factoryMap {
		result[id] = factory
	}
	
	return result, nil
}

// ListProviderTypes returns all registered provider types
func (r *FactoryRegistry) ListProviderTypes() []metadata.ProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var types []metadata.ProviderType
	for t := range r.factories {
		types = append(types, t)
	}
	
	return types
}

// GetAvailableProviders returns metadata for all providers that can be created by registered factories
func (r *FactoryRegistry) GetAvailableProviders(providerType metadata.ProviderType) ([]metadata.ProviderMetadata, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check if factory type exists
	factoryMap, ok := r.factories[providerType]
	if !ok {
		return nil, errors.NewPluginError(
			errors.ErrPluginNotFound,
			string(providerType),
			"",
			"factory type not registered",
		)
	}
	
	// Collect metadata from all factories
	var result []metadata.ProviderMetadata
	for _, factory := range factoryMap {
		result = append(result, factory.GetMetadata()...)
	}
	
	return result, nil
}

// CreateProvider creates a new provider instance using a registered factory
func (r *FactoryRegistry) CreateProvider(
	providerType metadata.ProviderType,
	factoryID string,
	providerID string,
	config interface{},
) (metadata.Provider, error) {
	// Get the factory
	factory, err := r.GetFactory(providerType, factoryID)
	if err != nil {
		return nil, err
	}
	
	// Create the provider
	provider, err := factory.Create(providerID, config)
	if err != nil {
		return nil, errors.NewPluginError(
			err,
			string(providerType),
			providerID,
			fmt.Sprintf("failed to create provider using factory %s", factoryID),
		)
	}
	
	return provider, nil
}