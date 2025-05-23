package config

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Fishwaldo/auth2/internal/errors"
	"github.com/Fishwaldo/auth2/pkg/log"
)

// Config holds the main configuration for the auth2 library
type Config struct {
	// General settings
	AppName     string `json:"app_name"`
	Environment string `json:"environment"` // "development", "production", "testing"

	// Logging configuration
	Logging *LoggingConfig `json:"logging"`

	// Authentication settings
	Auth *AuthConfig `json:"auth"`

	// Session management
	Session *SessionConfig `json:"session"`

	// RBAC configuration
	RBAC *RBACConfig `json:"rbac"`

	// Security settings
	Security *SecurityConfig `json:"security"`

	// Storage configuration
	Storage *StorageConfig `json:"storage"`
}

// LoggingConfig holds logging-specific configuration
type LoggingConfig struct {
	Level     string   `json:"level"` // "debug", "info", "warn", "error"
	Format    string   `json:"format"` // "json", "text"
	AddSource bool     `json:"add_source"`
	Fields    []string `json:"fields"` // Additional fields to log from context
}

// AuthConfig holds authentication-specific configuration
type AuthConfig struct {
	PasswordPolicy         *PasswordPolicy `json:"password_policy"`
	RequireEmailVerification bool          `json:"require_email_verification"`
	MaxLoginAttempts       int             `json:"max_login_attempts"`
	LockoutDuration        time.Duration   `json:"lockout_duration"`
	MFAEnabled             bool            `json:"mfa_enabled"`
	DefaultMFAType         string          `json:"default_mfa_type"` // "totp", "webauthn", "email", "backup"
	VerificationExpiry     time.Duration   `json:"verification_expiry"`
}

// PasswordPolicy defines password requirements
type PasswordPolicy struct {
	MinLength         int  `json:"min_length"`
	RequireUppercase  bool `json:"require_uppercase"`
	RequireLowercase  bool `json:"require_lowercase"`
	RequireDigits     bool `json:"require_digits"`
	RequireSpecial    bool `json:"require_special"`
	MaxRepeatedChars  int  `json:"max_repeated_chars"`
	PreventReuse      bool `json:"prevent_reuse"`
	PreventReuseCount int  `json:"prevent_reuse_count"`
}

// SessionConfig holds session-specific configuration
type SessionConfig struct {
	Type               string        `json:"type"` // "cookie", "jwt", "token"
	Duration           time.Duration `json:"duration"`
	RefreshEnabled     bool          `json:"refresh_enabled"`
	RefreshDuration    time.Duration `json:"refresh_duration"`
	Cookie             *CookieConfig `json:"cookie"`
	JWT                *JWTConfig    `json:"jwt"`
	RedisEnabled       bool          `json:"redis_enabled"`
	RedisAddress       string        `json:"redis_address"`
	RedisPassword      string        `json:"redis_password"`
	RedisDB            int           `json:"redis_db"`
	DisableIPTracking  bool          `json:"disable_ip_tracking"`
}

// CookieConfig holds cookie-specific configuration
type CookieConfig struct {
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	Path       string `json:"path"`
	Secure     bool   `json:"secure"`
	HTTPOnly   bool   `json:"http_only"`
	SameSite   string `json:"same_site"` // "strict", "lax", "none"
	Encryption bool   `json:"encryption"`
}

// JWTConfig holds JWT-specific configuration
type JWTConfig struct {
	SigningMethod string `json:"signing_method"` // "HS256", "HS384", "HS512", "RS256", "RS384", "RS512"
	SigningKey    string `json:"signing_key"`
	PublicKey     string `json:"public_key"`
	PrivateKey    string `json:"private_key"`
	KeyFile       string `json:"key_file"`
	KeyRotation   bool   `json:"key_rotation"`
	KeyRotationInterval time.Duration `json:"key_rotation_interval"`
}

// RBACConfig holds RBAC-specific configuration
type RBACConfig struct {
	EnableHierarchy    bool          `json:"enable_hierarchy"`
	EnableGroups       bool          `json:"enable_groups"`
	CacheEnabled       bool          `json:"cache_enabled"`
	CacheDuration      time.Duration `json:"cache_duration"`
	DefaultRole        string        `json:"default_role"`
	SystemRoles        []string      `json:"system_roles"`
	DisablePermissions bool          `json:"disable_permissions"`
}

// SecurityConfig holds security-specific configuration
type SecurityConfig struct {
	CSRFEnabled           bool          `json:"csrf_enabled"`
	CSRFTokenExpiry       time.Duration `json:"csrf_token_expiry"`
	RateLimitEnabled      bool          `json:"rate_limit_enabled"`
	RateLimitRequests     int           `json:"rate_limit_requests"`
	RateLimitDuration     time.Duration `json:"rate_limit_duration"`
	BruteForceEnabled     bool          `json:"brute_force_enabled"`
	BruteForceMaxAttempts int           `json:"brute_force_max_attempts"`
	BruteForceWindow      time.Duration `json:"brute_force_window"`
	BruteForceCooldown    time.Duration `json:"brute_force_cooldown"`
}

// StorageConfig holds storage-specific configuration
type StorageConfig struct {
	Type             string        `json:"type"` // "memory", "sql", "gorm", "ent"
	ConnectionString string        `json:"connection_string"`
	MaxConnections   int           `json:"max_connections"`
	ConnTimeout      time.Duration `json:"conn_timeout"`
	QueryTimeout     time.Duration `json:"query_timeout"`
	SQLDriver        string        `json:"sql_driver"` // "postgres", "mysql", "sqlite"
	MigrationsPath   string        `json:"migrations_path"`
	AutoMigrate      bool          `json:"auto_migrate"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		AppName:     "auth2",
		Environment: "development",
		Logging: &LoggingConfig{
			Level:     "info",
			Format:    "json",
			AddSource: false,
		},
		Auth: &AuthConfig{
			PasswordPolicy: &PasswordPolicy{
				MinLength:        8,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireDigits:    true,
				RequireSpecial:   true,
				MaxRepeatedChars: 3,
				PreventReuse:     true,
				PreventReuseCount: 5,
			},
			RequireEmailVerification: true,
			MaxLoginAttempts:       5,
			LockoutDuration:        15 * time.Minute,
			MFAEnabled:             false,
			DefaultMFAType:         "totp",
			VerificationExpiry:     24 * time.Hour,
		},
		Session: &SessionConfig{
			Type:            "cookie",
			Duration:        24 * time.Hour,
			RefreshEnabled:  true,
			RefreshDuration: 7 * 24 * time.Hour,
			Cookie: &CookieConfig{
				Name:     "auth2_session",
				Path:     "/",
				Secure:   true,
				HTTPOnly: true,
				SameSite: "lax",
				Encryption: true,
			},
			JWT: &JWTConfig{
				SigningMethod:       "HS256",
				KeyRotation:         false,
				KeyRotationInterval: 24 * time.Hour,
			},
			DisableIPTracking: false,
		},
		RBAC: &RBACConfig{
			EnableHierarchy: true,
			EnableGroups:    true,
			CacheEnabled:    true,
			CacheDuration:   5 * time.Minute,
			DefaultRole:     "user",
			SystemRoles:     []string{"admin", "user", "guest"},
		},
		Security: &SecurityConfig{
			CSRFEnabled:           true,
			CSRFTokenExpiry:       1 * time.Hour,
			RateLimitEnabled:      true,
			RateLimitRequests:     100,
			RateLimitDuration:     1 * time.Minute,
			BruteForceEnabled:     true,
			BruteForceMaxAttempts: 5,
			BruteForceWindow:      10 * time.Minute,
			BruteForceCooldown:    30 * time.Minute,
		},
		Storage: &StorageConfig{
			Type:           "memory",
			MaxConnections: 10,
			ConnTimeout:    5 * time.Second,
			QueryTimeout:   10 * time.Second,
			AutoMigrate:    true,
		},
	}
}

// LoadFromFile loads configuration from a JSON file
func LoadFromFile(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open config file")
	}
	defer file.Close()

	config := DefaultConfig()
	if err := json.NewDecoder(file).Decode(config); err != nil {
		return nil, errors.Wrap(err, "failed to decode config file")
	}

	return config, nil
}

// Save writes the configuration to a file in JSON format
func (c *Config) Save(path string) error {
	file, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "failed to create config file")
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(c); err != nil {
		return errors.Wrap(err, "failed to encode config")
	}

	return nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate logging configuration
	if c.Logging != nil {
		level := c.Logging.Level
		if level != "debug" && level != "info" && level != "warn" && level != "error" {
			return errors.NewValidationError(
				errors.ErrInvalidArgument, 
				"logging.level", 
				level, 
				"must be one of: debug, info, warn, error",
			)
		}

		format := c.Logging.Format
		if format != "json" && format != "text" {
			return errors.NewValidationError(
				errors.ErrInvalidArgument, 
				"logging.format", 
				format, 
				"must be one of: json, text",
			)
		}
	}

	// Validate authentication configuration
	if c.Auth != nil {
		if c.Auth.PasswordPolicy != nil {
			if c.Auth.PasswordPolicy.MinLength < 6 {
				return errors.NewValidationError(
					errors.ErrInvalidArgument, 
					"auth.password_policy.min_length", 
					c.Auth.PasswordPolicy.MinLength, 
					"must be at least 6",
				)
			}
		}

		if c.Auth.MaxLoginAttempts < 1 {
			return errors.NewValidationError(
				errors.ErrInvalidArgument, 
				"auth.max_login_attempts", 
				c.Auth.MaxLoginAttempts, 
				"must be at least 1",
			)
		}

		if c.Auth.MFAEnabled {
			mfaType := c.Auth.DefaultMFAType
			if mfaType != "totp" && mfaType != "webauthn" && mfaType != "email" && mfaType != "backup" {
				return errors.NewValidationError(
					errors.ErrInvalidArgument, 
					"auth.default_mfa_type", 
					mfaType, 
					"must be one of: totp, webauthn, email, backup",
				)
			}
		}
	}

	// Validate session configuration
	if c.Session != nil {
		sessionType := c.Session.Type
		if sessionType != "cookie" && sessionType != "jwt" && sessionType != "token" {
			return errors.NewValidationError(
				errors.ErrInvalidArgument, 
				"session.type", 
				sessionType, 
				"must be one of: cookie, jwt, token",
			)
		}

		if c.Session.Cookie != nil && c.Session.Type == "cookie" {
			sameSite := c.Session.Cookie.SameSite
			if sameSite != "strict" && sameSite != "lax" && sameSite != "none" {
				return errors.NewValidationError(
					errors.ErrInvalidArgument, 
					"session.cookie.same_site", 
					sameSite, 
					"must be one of: strict, lax, none",
				)
			}
		}

		if c.Session.JWT != nil && c.Session.Type == "jwt" {
			method := c.Session.JWT.SigningMethod
			validMethods := map[string]bool{
				"HS256": true, "HS384": true, "HS512": true,
				"RS256": true, "RS384": true, "RS512": true,
			}
			if !validMethods[method] {
				return errors.NewValidationError(
					errors.ErrInvalidArgument, 
					"session.jwt.signing_method", 
					method, 
					"must be one of: HS256, HS384, HS512, RS256, RS384, RS512",
				)
			}
		}
	}

	// Validate storage configuration
	if c.Storage != nil {
		storageType := c.Storage.Type
		if storageType != "memory" && storageType != "sql" && storageType != "gorm" && storageType != "ent" {
			return errors.NewValidationError(
				errors.ErrInvalidArgument, 
				"storage.type", 
				storageType, 
				"must be one of: memory, sql, gorm, ent",
			)
		}

		if storageType == "sql" && c.Storage.SQLDriver == "" {
			return errors.NewValidationError(
				errors.ErrInvalidArgument, 
				"storage.sql_driver", 
				c.Storage.SQLDriver, 
				"cannot be empty when storage.type is 'sql'",
			)
		}
	}

	return nil
}

// ConfigureLogging sets up the logging system based on the configuration
func (c *Config) ConfigureLogging() *log.Logger {
	var level log.Level
	switch c.Logging.Level {
	case "debug":
		level = log.LevelDebug
	case "info":
		level = log.LevelInfo
	case "warn":
		level = log.LevelWarn
	case "error":
		level = log.LevelError
	default:
		level = log.LevelInfo
	}

	logConfig := &log.Config{
		Level:       level,
		Format:      c.Logging.Format,
		AddSource:   c.Logging.AddSource,
		ContextKeys: c.Logging.Fields,
		Writer:      os.Stderr, // Default to stderr
	}

	logger := log.New(logConfig)
	log.SetDefault(logger)

	return logger
}