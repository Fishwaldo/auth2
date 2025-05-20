package common_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/common"
)

// TestConfig is a test configuration struct
type TestConfig struct {
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Timeout      int      `json:"timeout"`
	Rate         float64  `json:"rate"`
	Tags         []string `json:"tags"`
	IgnoredField string   `json:"-"`
	Nested       struct {
		Value string `json:"value"`
		Count int    `json:"count"`
	} `json:"nested"`
}

// TestLoadConfig tests the LoadConfig function
func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	
	// Create a test config
	config := TestConfig{
		Name:    "TestService",
		Enabled: true,
		Timeout: 30,
		Rate:    0.5,
		Tags:    []string{"test", "example"},
	}
	config.Nested.Value = "nested value"
	config.Nested.Count = 10
	
	// Save the config to file
	err := common.SaveConfig(configPath, config)
	if err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	
	// Load the config
	var loadedConfig TestConfig
	err = common.LoadConfig(configPath, &loadedConfig)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	
	// Verify loaded config matches original
	if loadedConfig.Name != config.Name {
		t.Errorf("LoadConfig() Name = %v, want %v", loadedConfig.Name, config.Name)
	}
	
	if loadedConfig.Enabled != config.Enabled {
		t.Errorf("LoadConfig() Enabled = %v, want %v", loadedConfig.Enabled, config.Enabled)
	}
	
	if loadedConfig.Timeout != config.Timeout {
		t.Errorf("LoadConfig() Timeout = %v, want %v", loadedConfig.Timeout, config.Timeout)
	}
	
	if loadedConfig.Rate != config.Rate {
		t.Errorf("LoadConfig() Rate = %v, want %v", loadedConfig.Rate, config.Rate)
	}
	
	if len(loadedConfig.Tags) != len(config.Tags) {
		t.Errorf("LoadConfig() Tags length = %v, want %v", len(loadedConfig.Tags), len(config.Tags))
	} else {
		for i, tag := range config.Tags {
			if loadedConfig.Tags[i] != tag {
				t.Errorf("LoadConfig() Tags[%d] = %v, want %v", i, loadedConfig.Tags[i], tag)
			}
		}
	}
	
	if loadedConfig.Nested.Value != config.Nested.Value {
		t.Errorf("LoadConfig() Nested.Value = %v, want %v", loadedConfig.Nested.Value, config.Nested.Value)
	}
	
	if loadedConfig.Nested.Count != config.Nested.Count {
		t.Errorf("LoadConfig() Nested.Count = %v, want %v", loadedConfig.Nested.Count, config.Nested.Count)
	}
}

// TestDefaults tests applying default values
func TestDefaults(t *testing.T) {
	// Create a temporary config file with minimal values
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "minimal.json")
	
	minimalConfig := struct {
		Name string `json:"name"`
	}{
		Name: "MinimalService",
	}
	
	err := common.SaveConfig(configPath, minimalConfig)
	if err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	
	// Create default values
	defaults := TestConfig{
		Name:    "DefaultService",
		Enabled: true,
		Timeout: 30,
		Rate:    0.5,
		Tags:    []string{"default", "example"},
	}
	defaults.Nested.Value = "default nested value"
	defaults.Nested.Count = 5
	
	// Load the config with defaults
	var loadedConfig TestConfig
	err = common.LoadConfig(configPath, &loadedConfig, common.WithDefaults(defaults))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	
	// Verify loaded config has file values where specified and defaults where not
	if loadedConfig.Name != "MinimalService" {
		t.Errorf("LoadConfig() Name = %v, want \"MinimalService\"", loadedConfig.Name)
	}
	
	if loadedConfig.Enabled != defaults.Enabled {
		t.Errorf("LoadConfig() Enabled = %v, want %v", loadedConfig.Enabled, defaults.Enabled)
	}
	
	if loadedConfig.Timeout != defaults.Timeout {
		t.Errorf("LoadConfig() Timeout = %v, want %v", loadedConfig.Timeout, defaults.Timeout)
	}
	
	if loadedConfig.Rate != defaults.Rate {
		t.Errorf("LoadConfig() Rate = %v, want %v", loadedConfig.Rate, defaults.Rate)
	}
	
	if len(loadedConfig.Tags) != len(defaults.Tags) {
		t.Errorf("LoadConfig() Tags length = %v, want %v", len(loadedConfig.Tags), len(defaults.Tags))
	} else {
		for i, tag := range defaults.Tags {
			if loadedConfig.Tags[i] != tag {
				t.Errorf("LoadConfig() Tags[%d] = %v, want %v", i, loadedConfig.Tags[i], tag)
			}
		}
	}
	
	if loadedConfig.Nested.Value != defaults.Nested.Value {
		t.Errorf("LoadConfig() Nested.Value = %v, want %v", loadedConfig.Nested.Value, defaults.Nested.Value)
	}
	
	if loadedConfig.Nested.Count != defaults.Nested.Count {
		t.Errorf("LoadConfig() Nested.Count = %v, want %v", loadedConfig.Nested.Count, defaults.Nested.Count)
	}
}

// TestValidation tests validation of configuration
func TestValidation(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	
	// Create a test config
	config := TestConfig{
		Name:    "TestService",
		Enabled: true,
		Timeout: -1, // Invalid value
		Rate:    0.5,
	}
	
	err := common.SaveConfig(configPath, config)
	if err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	
	// Create a validator
	validator := func(config interface{}) error {
		c, ok := config.(*TestConfig)
		if !ok {
			return nil
		}
		
		if c.Timeout < 0 {
			return fmt.Errorf("invalid timeout value: %d, must be non-negative", c.Timeout)
		}
		
		return nil
	}
	
	// Load the config with validation
	var loadedConfig TestConfig
	err = common.LoadConfig(configPath, &loadedConfig, common.WithValidation(validator))
	
	// Verify validation error
	if err == nil {
		t.Errorf("LoadConfig() error = nil, want error")
	}
	
	// Fix the config
	config.Timeout = 30
	err = common.SaveConfig(configPath, config)
	if err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	
	// Load again
	err = common.LoadConfig(configPath, &loadedConfig, common.WithValidation(validator))
	if err != nil {
		t.Errorf("LoadConfig() error = %v, want nil", err)
	}
}

// TestMultipleOptions tests applying multiple options
func TestMultipleOptions(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	
	// Create a test config
	config := TestConfig{
		Name:    "TestService",
		Enabled: true,
		// Timeout intentionally omitted to test default
		Rate: 0.5,
	}
	
	err := common.SaveConfig(configPath, config)
	if err != nil {
		t.Fatalf("SaveConfig() error = %v", err)
	}
	
	// Create defaults
	defaults := TestConfig{
		Timeout: 30,
	}
	
	// Create a validator
	validator := func(config interface{}) error {
		return nil // Always valid for this test
	}
	
	// Load the config with multiple options
	var loadedConfig TestConfig
	err = common.LoadConfig(
		configPath,
		&loadedConfig,
		common.WithDefaults(defaults),
		common.WithValidation(validator),
	)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	
	// Verify loaded config has file values where specified and defaults where not
	if loadedConfig.Name != "TestService" {
		t.Errorf("LoadConfig() Name = %v, want \"TestService\"", loadedConfig.Name)
	}
	
	if loadedConfig.Timeout != 30 {
		t.Errorf("LoadConfig() Timeout = %v, want 30 (from default)", loadedConfig.Timeout)
	}
}