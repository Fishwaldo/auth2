package providers

import "time"

// TimeProvider defines an interface for providing time functions
// TODO: Replace this interface so testing can be done without mocking
type TimeProvider interface {
	Now() time.Time
}

// DefaultTimeProvider returns the current time using the system clock
type defaultTimeProvider struct{}

func (p *defaultTimeProvider) Now() time.Time {
	return time.Now()
}

// CurrentTimeProvider is the active time provider instance
// Can be replaced in tests to mock time
var CurrentTimeProvider TimeProvider = &defaultTimeProvider{}

// Now returns the current time using the configured time provider
// This function is used by providers for time-related operations
func Now() time.Time {
	return CurrentTimeProvider.Now()
}