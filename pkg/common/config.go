package common

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// ConfigurationLoader defines the interface for configuration loading
type ConfigurationLoader interface {
	// Load loads configuration from a source
	Load(source string, config interface{}) error
}

// JSONConfigLoader implements ConfigurationLoader for JSON files
type JSONConfigLoader struct{}

// Load loads configuration from a JSON file
func (l *JSONConfigLoader) Load(source string, config interface{}) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	
	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse JSON config: %w", err)
	}
	
	return nil
}

// ConfigOption represents a configuration option
type ConfigOption func(config interface{}) error

// WithDefaults applies default values to configuration
func WithDefaults(defaults interface{}) ConfigOption {
	return func(config interface{}) error {
		return applyDefaults(config, defaults)
	}
}

// WithValidation applies validation to configuration
func WithValidation(validator func(interface{}) error) ConfigOption {
	return func(config interface{}) error {
		return validator(config)
	}
}

// LoadConfig loads configuration from a file with options
func LoadConfig(filePath string, config interface{}, options ...ConfigOption) error {
	// Determine the loader based on file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	var loader ConfigurationLoader
	
	switch ext {
	case ".json":
		loader = &JSONConfigLoader{}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}
	
	// Load the configuration
	if err := loader.Load(filePath, config); err != nil {
		return err
	}
	
	// Apply options
	for _, option := range options {
		if err := option(config); err != nil {
			return err
		}
	}
	
	return nil
}

// SaveConfig saves configuration to a file
func SaveConfig(filePath string, config interface{}) error {
	// Determine the format based on file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	
	var data []byte
	var err error
	
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}
	
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// applyDefaults applies default values to configuration
func applyDefaults(config, defaults interface{}) error {
	configValue := reflect.ValueOf(config)
	defaultsValue := reflect.ValueOf(defaults)
	
	// If config is a pointer, get the value it points to
	if configValue.Kind() == reflect.Ptr {
		configValue = configValue.Elem()
	}
	
	// If defaults is a pointer, get the value it points to
	if defaultsValue.Kind() == reflect.Ptr {
		defaultsValue = defaultsValue.Elem()
	}
	
	// Only structs are supported
	if configValue.Kind() != reflect.Struct || defaultsValue.Kind() != reflect.Struct {
		return fmt.Errorf("both config and defaults must be structs")
	}
	
	// Check if types are compatible
	if configValue.Type() != defaultsValue.Type() {
		return fmt.Errorf("config and defaults must be of the same type")
	}
	
	t := configValue.Type()
	
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		configField := configValue.Field(i)
		defaultField := defaultsValue.Field(i)
		
		// Skip unexported fields
		if !configField.CanSet() {
			continue
		}
		
		// Skip fields marked with json:"-"
		if jsonTag := field.Tag.Get("json"); jsonTag == "-" {
			continue
		}
		
		// Apply defaults based on field type
		switch configField.Kind() {
		case reflect.Struct:
			// For nested structs, we need to handle them recursively
			// Create a new struct to hold the field's value
			newConfig := reflect.New(configField.Type()).Elem()
			newConfig.Set(configField)
			
			// Create a new struct to hold the default's value
			newDefaults := reflect.New(defaultField.Type()).Elem()
			newDefaults.Set(defaultField)
			
			// Recursively apply defaults
			if err := applyDefaults(newConfig.Addr().Interface(), newDefaults.Addr().Interface()); err != nil {
				return err
			}
			
			// Set the field to the updated value
			configField.Set(newConfig)
			
		case reflect.Ptr:
			// Handle nil pointers
			if configField.IsNil() && !defaultField.IsNil() {
				configField.Set(defaultField)
			} else if !configField.IsNil() && !defaultField.IsNil() && configField.Elem().Kind() == reflect.Struct {
				// Recurse into pointers to structs
				if err := applyDefaults(configField.Interface(), defaultField.Interface()); err != nil {
					return err
				}
			}
		default:
			// For zero values, use the default
			if isZeroValue(configField) {
				configField.Set(defaultField)
			}
		}
	}
	
	return nil
}

// isZeroValue checks if a value is the zero value for its type
func isZeroValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Func, reflect.Map, reflect.Slice:
		return v.IsNil()
	case reflect.Array:
		z := true
		for i := 0; i < v.Len(); i++ {
			z = z && isZeroValue(v.Index(i))
		}
		return z
	case reflect.Struct:
		z := true
		for i := 0; i < v.NumField(); i++ {
			z = z && isZeroValue(v.Field(i))
		}
		return z
	}
	
	// Compare to zero value for the type
	z := reflect.Zero(v.Type())
	return v.Interface() == z.Interface()
}