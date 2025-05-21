package bruteforce_test

import (
	"context"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/security/bruteforce"
)

func TestProvider_Basics(t *testing.T) {
	// Create storage and notification service
	storage := bruteforce.NewMemoryStorage()
	notification := bruteforce.NewMockNotificationService()
	config := bruteforce.DefaultConfig()

	// Create provider
	provider := bruteforce.NewProvider(storage, config, notification)

	// Check provider metadata
	metadata := provider.GetMetadata()
	if metadata.ID != bruteforce.PluginID {
		t.Errorf("Expected plugin ID %s, got %s", bruteforce.PluginID, metadata.ID)
	}
	if metadata.Type != "security" {
		t.Errorf("Expected plugin type security, got %s", metadata.Type)
	}

	// Initialize and validate provider
	err := provider.Initialize(context.Background(), nil)
	if err != nil {
		t.Fatalf("Unexpected error initializing provider: %v", err)
	}

	err = provider.Validate(context.Background())
	if err != nil {
		t.Fatalf("Unexpected error validating provider: %v", err)
	}

	// Check that we can get the protection manager and auth integration
	manager := provider.GetProtectionManager()
	if manager == nil {
		t.Errorf("Expected non-nil protection manager")
	}

	integration := provider.GetAuthIntegration()
	if integration == nil {
		t.Errorf("Expected non-nil auth integration")
	}

	// Stop the provider
	provider.Stop()
}