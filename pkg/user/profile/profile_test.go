package profile_test

import (
	"context"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/user/profile"
)

// mockStore is a mock implementation of profile.Store for testing
type mockStore struct {
	get     func(ctx context.Context, userID string) (*profile.Profile, error)
	update  func(ctx context.Context, profile *profile.Profile) error
	delete  func(ctx context.Context, userID string) error
}

func (m *mockStore) Get(ctx context.Context, userID string) (*profile.Profile, error) {
	if m.get != nil {
		return m.get(ctx, userID)
	}
	return &profile.Profile{
		UserID:    userID,
		Fields:    make(map[string]interface{}),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (m *mockStore) Update(ctx context.Context, p *profile.Profile) error {
	if m.update != nil {
		return m.update(ctx, p)
	}
	return nil
}

func (m *mockStore) Delete(ctx context.Context, userID string) error {
	if m.delete != nil {
		return m.delete(ctx, userID)
	}
	return nil
}

// mockValidator is a mock implementation of profile.Validator for testing
type mockValidator struct {
	validateProfile func(ctx context.Context, profile *profile.Profile) error
}

func (m *mockValidator) ValidateProfile(ctx context.Context, p *profile.Profile) error {
	if m.validateProfile != nil {
		return m.validateProfile(ctx, p)
	}
	return nil
}

// TestProfileManager tests the profile manager functionality
func TestProfileManager(t *testing.T) {
	// Create a mock store
	store := &mockStore{}
	
	// Create a profile manager
	manager := profile.NewManager(store)
	
	// Test Get method
	t.Run("Get", func(t *testing.T) {
		// Set up mock store
		store.get = func(ctx context.Context, userID string) (*profile.Profile, error) {
			if userID == "user1" {
				return &profile.Profile{
					UserID: "user1",
					Fields: map[string]interface{}{
						"firstName": "John",
						"lastName":  "Doe",
						"age":       30,
					},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}, nil
			}
			return nil, profile.ErrProfileNotFound
		}
		
		// Test with existing profile
		ctx := context.Background()
		p, err := manager.Get(ctx, "user1")
		if err != nil {
			t.Errorf("Get() error = %v", err)
		}
		
		if p.UserID != "user1" {
			t.Errorf("Get() userID = %v, want %v", p.UserID, "user1")
		}
		
		if p.Fields["firstName"] != "John" {
			t.Errorf("Get() firstName = %v, want %v", p.Fields["firstName"], "John")
		}
		
		// Test with non-existent profile
		_, err = manager.Get(ctx, "nonexistent")
		if err == nil {
			t.Errorf("Get() error = nil, want error")
		}
	})
	
	// Test Update method
	t.Run("Update", func(t *testing.T) {
		// Set up mock store
		var updatedProfile *profile.Profile
		store.update = func(ctx context.Context, p *profile.Profile) error {
			updatedProfile = p
			return nil
		}
		
		// Test successful update
		ctx := context.Background()
		p := &profile.Profile{
			UserID: "user1",
			Fields: map[string]interface{}{
				"firstName": "Jane",
				"lastName":  "Doe",
				"age":       25,
			},
		}
		
		err := manager.Update(ctx, p)
		if err != nil {
			t.Errorf("Update() error = %v", err)
		}
		
		if updatedProfile == nil {
			t.Fatalf("Update() did not call store.Update")
		}
		
		if updatedProfile.UserID != "user1" {
			t.Errorf("Update() userID = %v, want %v", updatedProfile.UserID, "user1")
		}
		
		if updatedProfile.Fields["firstName"] != "Jane" {
			t.Errorf("Update() firstName = %v, want %v", updatedProfile.Fields["firstName"], "Jane")
		}
		
		// Test with validator
		validator := &mockValidator{
			validateProfile: func(ctx context.Context, p *profile.Profile) error {
				if p.UserID == "invalid" {
					return profile.ErrProfileNotFound
				}
				return nil
			},
		}
		
		manager.AddValidator(validator)
		
		// Test with valid profile
		err = manager.Update(ctx, p)
		if err != nil {
			t.Errorf("Update() error = %v", err)
		}
		
		// Test with invalid profile
		p.UserID = "invalid"
		err = manager.Update(ctx, p)
		if err == nil {
			t.Errorf("Update() error = nil, want error")
		}
	})
	
	// Test GetField and SetField methods
	t.Run("GetField_SetField", func(t *testing.T) {
		// Set up mock store
		p := &profile.Profile{
			UserID: "user1",
			Fields: map[string]interface{}{
				"firstName": "John",
				"lastName":  "Doe",
				"age":       30,
			},
		}
		
		store.get = func(ctx context.Context, userID string) (*profile.Profile, error) {
			if userID == "user1" {
				return p, nil
			}
			return nil, profile.ErrProfileNotFound
		}
		
		store.update = func(ctx context.Context, profile *profile.Profile) error {
			// Update our reference profile
			p = profile
			return nil
		}
		
		// Test GetField with existing field
		ctx := context.Background()
		value, err := manager.GetField(ctx, "user1", "firstName")
		if err != nil {
			t.Errorf("GetField() error = %v", err)
		}
		
		if value != "John" {
			t.Errorf("GetField() value = %v, want %v", value, "John")
		}
		
		// Test GetField with non-existent field
		_, err = manager.GetField(ctx, "user1", "nonexistent")
		if err == nil {
			t.Errorf("GetField() error = nil, want error")
		}
		
		// Define a field schema
		manager.DefineField("hobby", &profile.FieldSchema{
			Type:      profile.TypeString,
			Required:  false,
			MinLength: 2,
			MaxLength: 50,
		})
		
		// Test SetField with valid value
		err = manager.SetField(ctx, "user1", "hobby", "reading")
		if err != nil {
			t.Errorf("SetField() error = %v", err)
		}
		
		// Verify the field was set
		if p.Fields["hobby"] != "reading" {
			t.Errorf("SetField() hobby = %v, want %v", p.Fields["hobby"], "reading")
		}
		
		// Test SetField with invalid value (too short)
		err = manager.SetField(ctx, "user1", "hobby", "a")
		if err == nil {
			t.Errorf("SetField() error = nil, want error")
		}
	})
}

// TestFieldSchema tests the field schema validation functionality
func TestFieldSchema(t *testing.T) {
	testCases := []struct {
		name    string
		schema  profile.FieldSchema
		value   interface{}
		wantErr bool
	}{
		{
			name: "String - Valid",
			schema: profile.FieldSchema{
				Type:      profile.TypeString,
				MinLength: 2,
				MaxLength: 10,
			},
			value:   "valid",
			wantErr: false,
		},
		{
			name: "String - Too Short",
			schema: profile.FieldSchema{
				Type:      profile.TypeString,
				MinLength: 2,
				MaxLength: 10,
			},
			value:   "a",
			wantErr: true,
		},
		{
			name: "String - Too Long",
			schema: profile.FieldSchema{
				Type:      profile.TypeString,
				MinLength: 2,
				MaxLength: 10,
			},
			value:   "thisiswaytoolong",
			wantErr: true,
		},
		{
			name: "String - Wrong Type",
			schema: profile.FieldSchema{
				Type: profile.TypeString,
			},
			value:   123,
			wantErr: true,
		},
		{
			name: "Int - Valid",
			schema: profile.FieldSchema{
				Type:     profile.TypeInt,
				MinValue: 1,
				MaxValue: 100,
			},
			value:   50,
			wantErr: false,
		},
		{
			name: "Int - Too Small",
			schema: profile.FieldSchema{
				Type:     profile.TypeInt,
				MinValue: 1,
				MaxValue: 100,
			},
			value:   0,
			wantErr: true,
		},
		{
			name: "Int - Too Large",
			schema: profile.FieldSchema{
				Type:     profile.TypeInt,
				MinValue: 1,
				MaxValue: 100,
			},
			value:   101,
			wantErr: true,
		},
		{
			name: "Int - Wrong Type",
			schema: profile.FieldSchema{
				Type: profile.TypeInt,
			},
			value:   "not an int",
			wantErr: true,
		},
		{
			name: "Boolean - Valid",
			schema: profile.FieldSchema{
				Type: profile.TypeBoolean,
			},
			value:   true,
			wantErr: false,
		},
		{
			name: "Boolean - Wrong Type",
			schema: profile.FieldSchema{
				Type: profile.TypeBoolean,
			},
			value:   "not a boolean",
			wantErr: true,
		},
		{
			name: "Enum - Valid",
			schema: profile.FieldSchema{
				Type: profile.TypeString,
				Enum: []interface{}{"red", "green", "blue"},
			},
			value:   "red",
			wantErr: false,
		},
		{
			name: "Enum - Invalid",
			schema: profile.FieldSchema{
				Type: profile.TypeString,
				Enum: []interface{}{"red", "green", "blue"},
			},
			value:   "yellow",
			wantErr: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.schema.Validate(tc.value)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}