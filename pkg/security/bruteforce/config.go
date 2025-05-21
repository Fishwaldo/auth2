package bruteforce

import "time"

// Config defines the configuration for bruteforce protection
type Config struct {
	// MaxAttempts is the maximum number of failed attempts before locking an account
	MaxAttempts int `json:"max_attempts" yaml:"max_attempts"`

	// LockoutDuration is the duration for which an account is locked after exceeding MaxAttempts
	LockoutDuration time.Duration `json:"lockout_duration" yaml:"lockout_duration"`

	// AttemptWindowDuration is the time window during which failed attempts are counted
	AttemptWindowDuration time.Duration `json:"attempt_window_duration" yaml:"attempt_window_duration"`

	// AutoUnlock determines if accounts should be automatically unlocked after LockoutDuration
	AutoUnlock bool `json:"auto_unlock" yaml:"auto_unlock"`

	// CleanupInterval is the interval at which expired locks are cleaned up
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`

	// IncreaseTimeFactor specifies if lockout duration should increase exponentially with repeated lockouts
	IncreaseTimeFactor bool `json:"increase_time_factor" yaml:"increase_time_factor"`

	// IPRateLimit specifies how many attempts an IP address can make in IPRateLimitWindow
	IPRateLimit int `json:"ip_rate_limit" yaml:"ip_rate_limit"`

	// IPRateLimitWindow is the time window for IP-based rate limiting
	IPRateLimitWindow time.Duration `json:"ip_rate_limit_window" yaml:"ip_rate_limit_window"`

	// GlobalRateLimit specifies a global rate limit for all login attempts
	GlobalRateLimit int `json:"global_rate_limit" yaml:"global_rate_limit"`

	// GlobalRateLimitWindow is the time window for global rate limiting
	GlobalRateLimitWindow time.Duration `json:"global_rate_limit_window" yaml:"global_rate_limit_window"`

	// EmailNotification determines if email notifications should be sent on account lockout
	EmailNotification bool `json:"email_notification" yaml:"email_notification"`

	// ResetAttemptsOnSuccess determines if failed attempts should be reset on successful login
	ResetAttemptsOnSuccess bool `json:"reset_attempts_on_success" yaml:"reset_attempts_on_success"`
}

// DefaultConfig returns a default configuration for bruteforce protection
func DefaultConfig() *Config {
	return &Config{
		MaxAttempts:            5,
		LockoutDuration:        15 * time.Minute,
		AttemptWindowDuration:  30 * time.Minute,
		AutoUnlock:             true,
		CleanupInterval:        1 * time.Hour,
		IncreaseTimeFactor:     true,
		IPRateLimit:            20,
		IPRateLimitWindow:      1 * time.Hour,
		GlobalRateLimit:        1000,
		GlobalRateLimitWindow:  1 * time.Hour,
		EmailNotification:      true,
		ResetAttemptsOnSuccess: true,
	}
}