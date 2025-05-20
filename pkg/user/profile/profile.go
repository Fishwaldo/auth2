package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Profile represents a user's profile
type Profile struct {
	// UserID is the ID of the user
	UserID string
	
	// Fields contains the profile fields
	Fields map[string]interface{}
	
	// CreatedAt is the timestamp when the profile was created
	CreatedAt time.Time
	
	// UpdatedAt is the timestamp when the profile was last updated
	UpdatedAt time.Time
}

// Store defines the interface for profile storage operations
type Store interface {
	// Get retrieves a profile by user ID
	Get(ctx context.Context, userID string) (*Profile, error)
	
	// Update updates a profile
	Update(ctx context.Context, profile *Profile) error
	
	// Delete deletes a profile
	Delete(ctx context.Context, userID string) error
}

// Manager is responsible for profile management
type Manager struct {
	store       Store
	validators  []Validator
	fieldSchema map[string]*FieldSchema
}

// NewManager creates a new profile manager
func NewManager(store Store) *Manager {
	return &Manager{
		store:       store,
		validators:  make([]Validator, 0),
		fieldSchema: make(map[string]*FieldSchema),
	}
}

// AddValidator adds a validator to the profile manager
func (m *Manager) AddValidator(validator Validator) {
	m.validators = append(m.validators, validator)
}

// DefineField defines a field schema
func (m *Manager) DefineField(fieldName string, schema *FieldSchema) {
	m.fieldSchema[fieldName] = schema
}

// Get retrieves a profile
func (m *Manager) Get(ctx context.Context, userID string) (*Profile, error) {
	return m.store.Get(ctx, userID)
}

// Update updates a profile
func (m *Manager) Update(ctx context.Context, profile *Profile) error {
	// Validate the profile
	if err := m.validateProfile(ctx, profile); err != nil {
		return err
	}
	
	// Update the profile
	profile.UpdatedAt = time.Now()
	return m.store.Update(ctx, profile)
}

// Delete deletes a profile
func (m *Manager) Delete(ctx context.Context, userID string) error {
	return m.store.Delete(ctx, userID)
}

// GetField retrieves a specific field from a profile
func (m *Manager) GetField(ctx context.Context, userID, fieldName string) (interface{}, error) {
	profile, err := m.store.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	
	if value, ok := profile.Fields[fieldName]; ok {
		return value, nil
	}
	
	return nil, ErrFieldNotFound
}

// SetField sets a specific field in a profile
func (m *Manager) SetField(ctx context.Context, userID, fieldName string, value interface{}) error {
	profile, err := m.store.Get(ctx, userID)
	if err != nil {
		return err
	}
	
	// Validate the field value against its schema
	if schema, ok := m.fieldSchema[fieldName]; ok {
		if err := schema.Validate(value); err != nil {
			return err
		}
	}
	
	// Set the field
	profile.Fields[fieldName] = value
	profile.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, profile)
}

// validateProfile validates a profile
func (m *Manager) validateProfile(ctx context.Context, profile *Profile) error {
	// Validate required fields and field types
	for fieldName, schema := range m.fieldSchema {
		if schema.Required {
			value, exists := profile.Fields[fieldName]
			if !exists {
				return fmt.Errorf("required field %s is missing", fieldName)
			}
			
			if err := schema.Validate(value); err != nil {
				return err
			}
		}
	}
	
	// Run additional validators
	for _, validator := range m.validators {
		if err := validator.ValidateProfile(ctx, profile); err != nil {
			return err
		}
	}
	
	return nil
}

// FieldType defines the supported field types
type FieldType string

const (
	// TypeString is a string field
	TypeString FieldType = "string"
	
	// TypeInt is an integer field
	TypeInt FieldType = "int"
	
	// TypeFloat is a floating-point field
	TypeFloat FieldType = "float"
	
	// TypeBoolean is a boolean field
	TypeBoolean FieldType = "boolean"
	
	// TypeDateTime is a date-time field
	TypeDateTime FieldType = "datetime"
	
	// TypeObject is an object field
	TypeObject FieldType = "object"
	
	// TypeArray is an array field
	TypeArray FieldType = "array"
)

// FieldSchema defines the schema for a profile field
type FieldSchema struct {
	// Type is the field type
	Type FieldType
	
	// Required indicates if the field is required
	Required bool
	
	// DefaultValue is the default value for the field
	DefaultValue interface{}
	
	// MinLength is the minimum length for string fields
	MinLength int
	
	// MaxLength is the maximum length for string fields
	MaxLength int
	
	// MinValue is the minimum value for numeric fields
	MinValue float64
	
	// MaxValue is the maximum value for numeric fields
	MaxValue float64
	
	// Pattern is a regular expression pattern for string validation
	Pattern string
	
	// Enum is a list of valid values for the field
	Enum []interface{}
	
	// ItemType is the type of items in an array
	ItemType FieldType
	
	// Properties is a map of property names to schemas for object fields
	Properties map[string]*FieldSchema
}

// Validate validates a value against the field schema
func (s *FieldSchema) Validate(value interface{}) error {
	// Handle nil value
	if value == nil {
		if s.Required {
			return fmt.Errorf("field is required but value is nil")
		}
		return nil
	}
	
	// Type validation
	switch s.Type {
	case TypeString:
		str, ok := value.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", value)
		}
		
		// Length validation
		if s.MinLength > 0 && len(str) < s.MinLength {
			return fmt.Errorf("string length must be at least %d", s.MinLength)
		}
		
		if s.MaxLength > 0 && len(str) > s.MaxLength {
			return fmt.Errorf("string length must not exceed %d", s.MaxLength)
		}
		
		// Pattern validation would be implemented here
		
		// Enum validation
		if len(s.Enum) > 0 {
			valid := false
			for _, enum := range s.Enum {
				if enumStr, ok := enum.(string); ok && enumStr == str {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("value is not one of the allowed values")
			}
		}
		
	case TypeInt:
		var num int
		switch v := value.(type) {
		case int:
			num = v
		case int32:
			num = int(v)
		case int64:
			num = int(v)
		case float64:
			if v != float64(int(v)) {
				return fmt.Errorf("expected integer, got float with decimal part")
			}
			num = int(v)
		default:
			return fmt.Errorf("expected integer, got %T", value)
		}
		
		// Range validation
		if s.MinValue != 0 && float64(num) < s.MinValue {
			return fmt.Errorf("value must be at least %f", s.MinValue)
		}
		
		if s.MaxValue != 0 && float64(num) > s.MaxValue {
			return fmt.Errorf("value must not exceed %f", s.MaxValue)
		}
		
	case TypeFloat:
		var num float64
		switch v := value.(type) {
		case float32:
			num = float64(v)
		case float64:
			num = v
		case int:
			num = float64(v)
		case int32:
			num = float64(v)
		case int64:
			num = float64(v)
		default:
			return fmt.Errorf("expected float, got %T", value)
		}
		
		// Range validation
		if s.MinValue != 0 && num < s.MinValue {
			return fmt.Errorf("value must be at least %f", s.MinValue)
		}
		
		if s.MaxValue != 0 && num > s.MaxValue {
			return fmt.Errorf("value must not exceed %f", s.MaxValue)
		}
		
	case TypeBoolean:
		_, ok := value.(bool)
		if !ok {
			return fmt.Errorf("expected boolean, got %T", value)
		}
		
	case TypeDateTime:
		_, ok := value.(time.Time)
		if !ok {
			return fmt.Errorf("expected datetime, got %T", value)
		}
		
	case TypeObject:
		obj, ok := value.(map[string]interface{})
		if !ok {
			// Try to convert a JSON object to a map
			if str, ok := value.(string); ok {
				var m map[string]interface{}
				if err := json.Unmarshal([]byte(str), &m); err == nil {
					obj = m
				} else {
					return fmt.Errorf("expected object, got %T", value)
				}
			} else {
				return fmt.Errorf("expected object, got %T", value)
			}
		}
		
		// Validate properties
		for name, schema := range s.Properties {
			if propValue, ok := obj[name]; ok {
				if err := schema.Validate(propValue); err != nil {
					return fmt.Errorf("invalid property %s: %w", name, err)
				}
			} else if schema.Required {
				return fmt.Errorf("required property %s is missing", name)
			}
		}
		
	case TypeArray:
		arr, ok := value.([]interface{})
		if !ok {
			// Try to convert a JSON array to a slice
			if str, ok := value.(string); ok {
				var a []interface{}
				if err := json.Unmarshal([]byte(str), &a); err == nil {
					arr = a
				} else {
					return fmt.Errorf("expected array, got %T", value)
				}
			} else {
				return fmt.Errorf("expected array, got %T", value)
			}
		}
		
		// Validate array items
		if s.ItemType != "" {
			itemSchema := &FieldSchema{Type: s.ItemType}
			for i, item := range arr {
				if err := itemSchema.Validate(item); err != nil {
					return fmt.Errorf("invalid item at index %d: %w", i, err)
				}
			}
		}
	}
	
	return nil
}

// Validator defines the interface for profile validation
type Validator interface {
	// ValidateProfile validates a profile
	ValidateProfile(ctx context.Context, profile *Profile) error
}

// Common errors
var (
	ErrProfileNotFound = fmt.Errorf("profile not found")
	ErrFieldNotFound   = fmt.Errorf("field not found")
)