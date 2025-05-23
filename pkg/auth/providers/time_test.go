package providers_test

import (
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/auth/providers"
	"github.com/stretchr/testify/assert"
)

// mockTimeProvider for testing
type mockTimeProvider struct {
	currentTime time.Time
}

func (m *mockTimeProvider) Now() time.Time {
	return m.currentTime
}

func TestDefaultTimeProvider_Now(t *testing.T) {
	// Test the Now() function which uses the default time provider
	before := time.Now()
	result := providers.Now()
	after := time.Now()
	
	// The result should be between before and after
	assert.True(t, !result.Before(before))
	assert.True(t, !result.After(after))
}

func TestNow(t *testing.T) {
	// Save the original provider
	originalProvider := providers.CurrentTimeProvider
	defer func() {
		providers.CurrentTimeProvider = originalProvider
	}()
	
	// Test with default provider
	before := time.Now()
	result := providers.Now()
	after := time.Now()
	
	// The result should be between before and after
	assert.True(t, !result.Before(before))
	assert.True(t, !result.After(after))
	
	// Test with mock provider
	mockTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	mockProvider := &mockTimeProvider{currentTime: mockTime}
	providers.CurrentTimeProvider = mockProvider
	
	result = providers.Now()
	assert.Equal(t, mockTime, result)
}

func TestTimeProvider_Interface(t *testing.T) {
	// Ensure CurrentTimeProvider is not nil and implements TimeProvider
	assert.NotNil(t, providers.CurrentTimeProvider)
	
	// Test that it returns a valid time
	now := providers.CurrentTimeProvider.Now()
	assert.False(t, now.IsZero())
}

func TestCurrentTimeProvider_Default(t *testing.T) {
	// Save the original provider
	originalProvider := providers.CurrentTimeProvider
	defer func() {
		providers.CurrentTimeProvider = originalProvider
	}()
	
	// CurrentTimeProvider should already be set by default
	
	// CurrentTimeProvider should be set by default
	assert.NotNil(t, providers.CurrentTimeProvider)
	
	// It should return a reasonable time
	now := providers.CurrentTimeProvider.Now()
	assert.WithinDuration(t, time.Now(), now, time.Second)
}