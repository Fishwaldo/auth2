package discovery

import (
	"github.com/Fishwaldo/auth2/pkg/plugin/factory"
	"github.com/Fishwaldo/auth2/pkg/plugin/metadata"
	"github.com/Fishwaldo/auth2/pkg/plugin/registry"
)

// DiscoveryService manages provider discovery
type DiscoveryService struct {
	// Registry is the provider registry
	Registry *registry.Registry
	
	// FactoryRegistry is the factory registry
	FactoryRegistry *factory.FactoryRegistry
}

// NewDiscoveryService creates a new DiscoveryService
func NewDiscoveryService(reg *registry.Registry, factoryReg *factory.FactoryRegistry) *DiscoveryService {
	return &DiscoveryService{
		Registry:        reg,
		FactoryRegistry: factoryReg,
	}
}

// ListAuthProviders returns metadata for all registered authentication providers
func (s *DiscoveryService) ListAuthProviders() ([]metadata.ProviderMetadata, error) {
	return s.Registry.GetProviderMetadata(metadata.ProviderTypeAuth)
}

// ListMFAProviders returns metadata for all registered MFA providers
func (s *DiscoveryService) ListMFAProviders() ([]metadata.ProviderMetadata, error) {
	return s.Registry.GetProviderMetadata(metadata.ProviderTypeMFA)
}

// ListStorageProviders returns metadata for all registered storage providers
func (s *DiscoveryService) ListStorageProviders() ([]metadata.ProviderMetadata, error) {
	return s.Registry.GetProviderMetadata(metadata.ProviderTypeStorage)
}

// ListHTTPProviders returns metadata for all registered HTTP providers
func (s *DiscoveryService) ListHTTPProviders() ([]metadata.ProviderMetadata, error) {
	return s.Registry.GetProviderMetadata(metadata.ProviderTypeHTTP)
}

// ListAvailableAuthProviders returns metadata for all authentication providers that can be created
func (s *DiscoveryService) ListAvailableAuthProviders() ([]metadata.ProviderMetadata, error) {
	return s.FactoryRegistry.GetAvailableProviders(metadata.ProviderTypeAuth)
}

// ListAvailableMFAProviders returns metadata for all MFA providers that can be created
func (s *DiscoveryService) ListAvailableMFAProviders() ([]metadata.ProviderMetadata, error) {
	return s.FactoryRegistry.GetAvailableProviders(metadata.ProviderTypeMFA)
}

// ListAvailableStorageProviders returns metadata for all storage providers that can be created
func (s *DiscoveryService) ListAvailableStorageProviders() ([]metadata.ProviderMetadata, error) {
	return s.FactoryRegistry.GetAvailableProviders(metadata.ProviderTypeStorage)
}

// ListAvailableHTTPProviders returns metadata for all HTTP providers that can be created
func (s *DiscoveryService) ListAvailableHTTPProviders() ([]metadata.ProviderMetadata, error) {
	return s.FactoryRegistry.GetAvailableProviders(metadata.ProviderTypeHTTP)
}

// GetAuthProviderFactories returns all authentication provider factories
func (s *DiscoveryService) GetAuthProviderFactories() (map[string]factory.Factory, error) {
	return s.FactoryRegistry.GetFactories(metadata.ProviderTypeAuth)
}

// GetMFAProviderFactories returns all MFA provider factories
func (s *DiscoveryService) GetMFAProviderFactories() (map[string]factory.Factory, error) {
	return s.FactoryRegistry.GetFactories(metadata.ProviderTypeMFA)
}

// GetStorageProviderFactories returns all storage provider factories
func (s *DiscoveryService) GetStorageProviderFactories() (map[string]factory.Factory, error) {
	return s.FactoryRegistry.GetFactories(metadata.ProviderTypeStorage)
}

// GetHTTPProviderFactories returns all HTTP provider factories
func (s *DiscoveryService) GetHTTPProviderFactories() (map[string]factory.Factory, error) {
	return s.FactoryRegistry.GetFactories(metadata.ProviderTypeHTTP)
}

// CreateAuthProvider creates a new authentication provider instance
func (s *DiscoveryService) CreateAuthProvider(factoryID, providerID string, config interface{}) (metadata.AuthProvider, error) {
	provider, err := s.FactoryRegistry.CreateProvider(metadata.ProviderTypeAuth, factoryID, providerID, config)
	if err != nil {
		return nil, err
	}
	
	authProvider, ok := provider.(metadata.AuthProvider)
	if !ok {
		return nil, metadata.NewProviderError(
			providerID,
			string(metadata.ProviderTypeAuth),
			"provider does not implement AuthProvider interface",
		)
	}
	
	return authProvider, nil
}

// CreateMFAProvider creates a new MFA provider instance
func (s *DiscoveryService) CreateMFAProvider(factoryID, providerID string, config interface{}) (metadata.MFAProvider, error) {
	provider, err := s.FactoryRegistry.CreateProvider(metadata.ProviderTypeMFA, factoryID, providerID, config)
	if err != nil {
		return nil, err
	}
	
	mfaProvider, ok := provider.(metadata.MFAProvider)
	if !ok {
		return nil, metadata.NewProviderError(
			providerID,
			string(metadata.ProviderTypeMFA),
			"provider does not implement MFAProvider interface",
		)
	}
	
	return mfaProvider, nil
}

// CreateStorageProvider creates a new storage provider instance
func (s *DiscoveryService) CreateStorageProvider(factoryID, providerID string, config interface{}) (metadata.StorageProvider, error) {
	provider, err := s.FactoryRegistry.CreateProvider(metadata.ProviderTypeStorage, factoryID, providerID, config)
	if err != nil {
		return nil, err
	}
	
	storageProvider, ok := provider.(metadata.StorageProvider)
	if !ok {
		return nil, metadata.NewProviderError(
			providerID,
			string(metadata.ProviderTypeStorage),
			"provider does not implement StorageProvider interface",
		)
	}
	
	return storageProvider, nil
}

// CreateHTTPProvider creates a new HTTP provider instance
func (s *DiscoveryService) CreateHTTPProvider(factoryID, providerID string, config interface{}) (metadata.HTTPProvider, error) {
	provider, err := s.FactoryRegistry.CreateProvider(metadata.ProviderTypeHTTP, factoryID, providerID, config)
	if err != nil {
		return nil, err
	}
	
	httpProvider, ok := provider.(metadata.HTTPProvider)
	if !ok {
		return nil, metadata.NewProviderError(
			providerID,
			string(metadata.ProviderTypeHTTP),
			"provider does not implement HTTPProvider interface",
		)
	}
	
	return httpProvider, nil
}