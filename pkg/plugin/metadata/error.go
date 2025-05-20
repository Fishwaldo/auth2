package metadata

import "fmt"

// ProviderError represents an error related to a specific provider
type ProviderError struct {
	// ProviderID is the ID of the provider that caused the error
	ProviderID string
	
	// ProviderType is the type of the provider that caused the error
	ProviderType string
	
	// Message is the error message
	Message string
}

// Error returns a string representation of the error
func (e *ProviderError) Error() string {
	if e.ProviderID != "" && e.ProviderType != "" {
		return fmt.Sprintf("provider error [%s:%s]: %s", e.ProviderType, e.ProviderID, e.Message)
	} else if e.ProviderType != "" {
		return fmt.Sprintf("provider error [%s]: %s", e.ProviderType, e.Message)
	}
	return fmt.Sprintf("provider error: %s", e.Message)
}

// NewProviderError creates a new ProviderError
func NewProviderError(providerID, providerType, message string) *ProviderError {
	return &ProviderError{
		ProviderID:   providerID,
		ProviderType: providerType,
		Message:      message,
	}
}