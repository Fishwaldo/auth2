// Package plugin implements a flexible, interface-based plugin system for the auth2 library.
//
// The plugin system is designed around core principles:
//
// 1. Type Safety: All plugins are type-checked at compile time
// 2. Flexibility: Plugins can be added, removed, and configured at runtime
// 3. Extensibility: New plugin types can be added without modifying core code
// 4. Discoverability: Plugins provide metadata about their capabilities
// 5. Versioning: Plugin compatibility is checked against API versions
//
// The system consists of three main components:
//
// 1. Provider Interfaces: Define the contract for each plugin type
// 2. Registry: Manages registered plugin instances
// 3. Factory: Creates and configures plugin instances
//
// Example usage:
//
//	// Create a registry
//	registry := registry.NewRegistry()
//
//	// Register a provider
//	registry.RegisterProvider(myAuthProvider)
//
//	// Get a provider
//	provider, err := registry.GetProvider(metadata.ProviderTypeAuth, "basic")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use the provider
//	err = provider.Initialize(ctx, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
package plugin