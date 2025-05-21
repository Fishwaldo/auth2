package password

import "time"

// TimeProviderFunc is a function type that returns the current time
type TimeProviderFunc func() time.Time

// DefaultTimeProvider returns the current time
func DefaultTimeProvider() time.Time {
	return time.Now()
}

// TimeProvider is the provider used to get the current time
// This can be overridden in tests to provide a deterministic time
var TimeProvider TimeProviderFunc = DefaultTimeProvider

// GetCurrentTime returns the current time using the configured provider
func GetCurrentTime() time.Time {
	return TimeProvider()
}