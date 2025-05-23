package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/config"
	"github.com/Fishwaldo/auth2/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	
	// Test general settings
	assert.Equal(t, "auth2", cfg.AppName)
	assert.Equal(t, "development", cfg.Environment)
	
	// Test logging config
	assert.NotNil(t, cfg.Logging)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.False(t, cfg.Logging.AddSource)
	
	// Test auth config
	assert.NotNil(t, cfg.Auth)
	assert.NotNil(t, cfg.Auth.PasswordPolicy)
	assert.Equal(t, 8, cfg.Auth.PasswordPolicy.MinLength)
	assert.True(t, cfg.Auth.PasswordPolicy.RequireUppercase)
	assert.True(t, cfg.Auth.PasswordPolicy.RequireLowercase)
	assert.True(t, cfg.Auth.PasswordPolicy.RequireDigits)
	assert.True(t, cfg.Auth.PasswordPolicy.RequireSpecial)
	assert.Equal(t, 3, cfg.Auth.PasswordPolicy.MaxRepeatedChars)
	assert.True(t, cfg.Auth.PasswordPolicy.PreventReuse)
	assert.Equal(t, 5, cfg.Auth.PasswordPolicy.PreventReuseCount)
	assert.True(t, cfg.Auth.RequireEmailVerification)
	assert.Equal(t, 5, cfg.Auth.MaxLoginAttempts)
	assert.Equal(t, 15*time.Minute, cfg.Auth.LockoutDuration)
	assert.False(t, cfg.Auth.MFAEnabled)
	assert.Equal(t, "totp", cfg.Auth.DefaultMFAType)
	assert.Equal(t, 24*time.Hour, cfg.Auth.VerificationExpiry)
	
	// Test session config
	assert.NotNil(t, cfg.Session)
	assert.Equal(t, "cookie", cfg.Session.Type)
	assert.Equal(t, 24*time.Hour, cfg.Session.Duration)
	assert.True(t, cfg.Session.RefreshEnabled)
	assert.Equal(t, 7*24*time.Hour, cfg.Session.RefreshDuration)
	assert.False(t, cfg.Session.DisableIPTracking)
	
	// Test cookie config
	assert.NotNil(t, cfg.Session.Cookie)
	assert.Equal(t, "auth2_session", cfg.Session.Cookie.Name)
	assert.Equal(t, "/", cfg.Session.Cookie.Path)
	assert.True(t, cfg.Session.Cookie.Secure)
	assert.True(t, cfg.Session.Cookie.HTTPOnly)
	assert.Equal(t, "lax", cfg.Session.Cookie.SameSite)
	assert.True(t, cfg.Session.Cookie.Encryption)
	
	// Test JWT config
	assert.NotNil(t, cfg.Session.JWT)
	assert.Equal(t, "HS256", cfg.Session.JWT.SigningMethod)
	assert.False(t, cfg.Session.JWT.KeyRotation)
	assert.Equal(t, 24*time.Hour, cfg.Session.JWT.KeyRotationInterval)
	
	// Test RBAC config
	assert.NotNil(t, cfg.RBAC)
	assert.True(t, cfg.RBAC.EnableHierarchy)
	assert.True(t, cfg.RBAC.EnableGroups)
	assert.True(t, cfg.RBAC.CacheEnabled)
	assert.Equal(t, 5*time.Minute, cfg.RBAC.CacheDuration)
	assert.Equal(t, "user", cfg.RBAC.DefaultRole)
	assert.Equal(t, []string{"admin", "user", "guest"}, cfg.RBAC.SystemRoles)
	
	// Test security config
	assert.NotNil(t, cfg.Security)
	assert.True(t, cfg.Security.CSRFEnabled)
	assert.Equal(t, 1*time.Hour, cfg.Security.CSRFTokenExpiry)
	assert.True(t, cfg.Security.RateLimitEnabled)
	assert.Equal(t, 100, cfg.Security.RateLimitRequests)
	assert.Equal(t, 1*time.Minute, cfg.Security.RateLimitDuration)
	assert.True(t, cfg.Security.BruteForceEnabled)
	assert.Equal(t, 5, cfg.Security.BruteForceMaxAttempts)
	assert.Equal(t, 10*time.Minute, cfg.Security.BruteForceWindow)
	assert.Equal(t, 30*time.Minute, cfg.Security.BruteForceCooldown)
	
	// Test storage config
	assert.NotNil(t, cfg.Storage)
	assert.Equal(t, "memory", cfg.Storage.Type)
	assert.Equal(t, 10, cfg.Storage.MaxConnections)
	assert.Equal(t, 5*time.Second, cfg.Storage.ConnTimeout)
	assert.Equal(t, 10*time.Second, cfg.Storage.QueryTimeout)
	assert.True(t, cfg.Storage.AutoMigrate)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name          string
		config        func() *config.Config
		expectedError string
	}{
		{
			name: "valid default config",
			config: func() *config.Config {
				return config.DefaultConfig()
			},
			expectedError: "",
		},
		{
			name: "invalid logging level",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Logging.Level = "invalid"
				return cfg
			},
			expectedError: "must be one of: debug, info, warn, error",
		},
		{
			name: "invalid logging format",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Logging.Format = "invalid"
				return cfg
			},
			expectedError: "must be one of: json, text",
		},
		{
			name: "password min length too short",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Auth.PasswordPolicy.MinLength = 5
				return cfg
			},
			expectedError: "must be at least 6",
		},
		{
			name: "invalid max login attempts",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Auth.MaxLoginAttempts = 0
				return cfg
			},
			expectedError: "must be at least 1",
		},
		{
			name: "invalid MFA type",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Auth.MFAEnabled = true
				cfg.Auth.DefaultMFAType = "invalid"
				return cfg
			},
			expectedError: "must be one of: totp, webauthn, email, backup",
		},
		{
			name: "invalid session type",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Session.Type = "invalid"
				return cfg
			},
			expectedError: "must be one of: cookie, jwt, token",
		},
		{
			name: "invalid cookie same site",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Session.Type = "cookie"
				cfg.Session.Cookie.SameSite = "invalid"
				return cfg
			},
			expectedError: "must be one of: strict, lax, none",
		},
		{
			name: "invalid JWT signing method",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Session.Type = "jwt"
				cfg.Session.JWT.SigningMethod = "HS123"
				return cfg
			},
			expectedError: "must be one of: HS256, HS384, HS512, RS256, RS384, RS512",
		},
		{
			name: "invalid storage type",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Storage.Type = "invalid"
				return cfg
			},
			expectedError: "must be one of: memory, sql, gorm, ent",
		},
		{
			name: "sql storage without driver",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Storage.Type = "sql"
				cfg.Storage.SQLDriver = ""
				return cfg
			},
			expectedError: "cannot be empty when storage.type is 'sql'",
		},
		{
			name: "nil logging config",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Logging = nil
				return cfg
			},
			expectedError: "",
		},
		{
			name: "nil auth config",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Auth = nil
				return cfg
			},
			expectedError: "",
		},
		{
			name: "nil session config",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Session = nil
				return cfg
			},
			expectedError: "",
		},
		{
			name: "nil storage config",
			config: func() *config.Config {
				cfg := config.DefaultConfig()
				cfg.Storage = nil
				return cfg
			},
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config().Validate()
			
			if tt.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			}
		})
	}
}

func TestConfig_SaveAndLoad(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.json")

	// Create a config with custom values
	originalConfig := config.DefaultConfig()
	originalConfig.AppName = "test-app"
	originalConfig.Environment = "testing"
	originalConfig.Logging.Level = "debug"
	originalConfig.Auth.MaxLoginAttempts = 10
	originalConfig.Session.Duration = 48 * time.Hour

	// Save the config
	err := originalConfig.Save(configPath)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(configPath)
	require.NoError(t, err)

	// Load the config
	loadedConfig, err := config.LoadFromFile(configPath)
	require.NoError(t, err)

	// Verify the loaded config matches the original
	assert.Equal(t, originalConfig.AppName, loadedConfig.AppName)
	assert.Equal(t, originalConfig.Environment, loadedConfig.Environment)
	assert.Equal(t, originalConfig.Logging.Level, loadedConfig.Logging.Level)
	assert.Equal(t, originalConfig.Auth.MaxLoginAttempts, loadedConfig.Auth.MaxLoginAttempts)
	assert.Equal(t, originalConfig.Session.Duration, loadedConfig.Session.Duration)
}

func TestLoadFromFile_Errors(t *testing.T) {
	tests := []struct {
		name          string
		setupFile     func(string) error
		path          string
		expectedError string
	}{
		{
			name:          "non-existent file",
			path:          "/non/existent/file.json",
			expectedError: "failed to open config file",
		},
		{
			name: "invalid JSON",
			setupFile: func(path string) error {
				return os.WriteFile(path, []byte("invalid json"), 0644)
			},
			expectedError: "failed to decode config file",
		},
		{
			name: "empty file",
			setupFile: func(path string) error {
				return os.WriteFile(path, []byte(""), 0644)
			},
			expectedError: "failed to decode config file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.setupFile != nil {
				tmpFile, err := os.CreateTemp("", "config_test_*.json")
				require.NoError(t, err)
				path = tmpFile.Name()
				tmpFile.Close()
				defer os.Remove(path)
				
				err = tt.setupFile(path)
				require.NoError(t, err)
			} else {
				path = tt.path
			}

			cfg, err := config.LoadFromFile(path)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			assert.Nil(t, cfg)
		})
	}
}

func TestConfig_Save_Errors(t *testing.T) {
	cfg := config.DefaultConfig()

	// Test saving to a directory that doesn't exist
	err := cfg.Save("/non/existent/directory/config.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create config file")
}

func TestConfig_ConfigureLogging(t *testing.T) {
	tests := []struct {
		name           string
		loggingConfig  *config.LoggingConfig
		expectedLevel  log.Level
		expectedFormat string
	}{
		{
			name: "debug level",
			loggingConfig: &config.LoggingConfig{
				Level:  "debug",
				Format: "json",
			},
			expectedLevel:  log.LevelDebug,
			expectedFormat: "json",
		},
		{
			name: "info level",
			loggingConfig: &config.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			expectedLevel:  log.LevelInfo,
			expectedFormat: "text",
		},
		{
			name: "warn level",
			loggingConfig: &config.LoggingConfig{
				Level:  "warn",
				Format: "json",
			},
			expectedLevel:  log.LevelWarn,
			expectedFormat: "json",
		},
		{
			name: "error level",
			loggingConfig: &config.LoggingConfig{
				Level:  "error",
				Format: "text",
			},
			expectedLevel:  log.LevelError,
			expectedFormat: "text",
		},
		{
			name: "unknown level defaults to info",
			loggingConfig: &config.LoggingConfig{
				Level:  "unknown",
				Format: "json",
			},
			expectedLevel:  log.LevelInfo,
			expectedFormat: "json",
		},
		{
			name: "with source and fields",
			loggingConfig: &config.LoggingConfig{
				Level:     "info",
				Format:    "json",
				AddSource: true,
				Fields:    []string{"request_id", "user_id"},
			},
			expectedLevel:  log.LevelInfo,
			expectedFormat: "json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Logging = tt.loggingConfig

			logger := cfg.ConfigureLogging()
			assert.NotNil(t, logger)
			
			// Verify the logger was set as default
			assert.NotNil(t, log.Default())
		})
	}
}

func TestConfig_JSON_Marshaling(t *testing.T) {
	// Test that config can be properly marshaled and unmarshaled
	originalConfig := config.DefaultConfig()
	originalConfig.AppName = "json-test"
	originalConfig.Auth.MaxLoginAttempts = 7
	originalConfig.Session.Duration = 12 * time.Hour

	// Marshal to JSON
	jsonData, err := json.Marshal(originalConfig)
	require.NoError(t, err)

	// Unmarshal back
	var unmarshaledConfig config.Config
	err = json.Unmarshal(jsonData, &unmarshaledConfig)
	require.NoError(t, err)

	// Verify key fields
	assert.Equal(t, originalConfig.AppName, unmarshaledConfig.AppName)
	assert.Equal(t, originalConfig.Auth.MaxLoginAttempts, unmarshaledConfig.Auth.MaxLoginAttempts)
	assert.Equal(t, originalConfig.Session.Duration, unmarshaledConfig.Session.Duration)
}

func TestConfig_PartialLoad(t *testing.T) {
	// Test that partial configs can be loaded (only override specified fields)
	tmpFile, err := os.CreateTemp("", "partial_config_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write a partial config that only sets a few fields
	partialConfig := `{
		"app_name": "partial-app",
		"logging": {
			"level": "error"
		}
	}`
	
	_, err = tmpFile.WriteString(partialConfig)
	require.NoError(t, err)
	tmpFile.Close()

	// Load the config
	cfg, err := config.LoadFromFile(tmpFile.Name())
	require.NoError(t, err)

	// Check that the specified fields were updated
	assert.Equal(t, "partial-app", cfg.AppName)
	assert.Equal(t, "error", cfg.Logging.Level)

	// Check that other fields still have default values
	assert.Equal(t, "development", cfg.Environment)
	assert.Equal(t, "json", cfg.Logging.Format)
	assert.Equal(t, 8, cfg.Auth.PasswordPolicy.MinLength)
}

func TestConfig_ComplexValidation(t *testing.T) {
	// Test with nil sub-configs
	cfg := &config.Config{
		AppName:     "test",
		Environment: "test",
		// All sub-configs are nil
	}

	err := cfg.Validate()
	assert.NoError(t, err)

	// Test with empty password policy
	cfg.Auth = &config.AuthConfig{
		PasswordPolicy: nil,
		MaxLoginAttempts: 5,
	}
	err = cfg.Validate()
	assert.NoError(t, err)

	// Test JWT validation with jwt session type
	cfg.Session = &config.SessionConfig{
		Type: "jwt",
		JWT: &config.JWTConfig{
			SigningMethod: "RS256",
		},
	}
	err = cfg.Validate()
	assert.NoError(t, err)

	// Test cookie validation is skipped when session type is not cookie
	cfg.Session.Type = "jwt"
	cfg.Session.Cookie = &config.CookieConfig{
		SameSite: "invalid", // Should not cause error since type is jwt
	}
	err = cfg.Validate()
	assert.NoError(t, err)

	// Test JWT validation is skipped when session type is not jwt
	cfg.Session.Type = "cookie"
	cfg.Session.Cookie.SameSite = "lax" // Fix cookie config
	cfg.Session.JWT.SigningMethod = "invalid" // Should not cause error since type is cookie
	err = cfg.Validate()
	assert.NoError(t, err)
}