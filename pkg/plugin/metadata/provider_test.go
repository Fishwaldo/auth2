package metadata

import (
	"context"
	"testing"
)

func TestValidateMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata ProviderMetadata
		wantErr  bool
	}{
		{
			name: "Valid metadata",
			metadata: ProviderMetadata{
				ID:      "test-provider",
				Type:    ProviderTypeAuth,
				Version: "1.0.0",
				Name:    "Test Provider",
			},
			wantErr: false,
		},
		{
			name: "Missing ID",
			metadata: ProviderMetadata{
				Type:    ProviderTypeAuth,
				Version: "1.0.0",
				Name:    "Test Provider",
			},
			wantErr: true,
		},
		{
			name: "Missing Type",
			metadata: ProviderMetadata{
				ID:      "test-provider",
				Version: "1.0.0",
				Name:    "Test Provider",
			},
			wantErr: true,
		},
		{
			name: "Missing Version",
			metadata: ProviderMetadata{
				ID:   "test-provider",
				Type: ProviderTypeAuth,
				Name: "Test Provider",
			},
			wantErr: true,
		},
		{
			name: "Missing Name",
			metadata: ProviderMetadata{
				ID:      "test-provider",
				Type:    ProviderTypeAuth,
				Version: "1.0.0",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMetadata(tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMetadata() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBaseProvider(t *testing.T) {
	metadata := ProviderMetadata{
		ID:      "test-provider",
		Type:    ProviderTypeAuth,
		Version: "1.0.0",
		Name:    "Test Provider",
		VersionConstraint: VersionConstraint{
			MinVersion: "1.0.0",
			MaxVersion: "2.0.0",
		},
	}

	provider := NewBaseProvider(metadata)

	// Test GetMetadata
	if provider.GetMetadata().ID != "test-provider" {
		t.Errorf("GetMetadata().ID = %v, want %v", provider.GetMetadata().ID, "test-provider")
	}

	// Test Initialize
	if err := provider.Initialize(context.Background(), nil); err != nil {
		t.Errorf("Initialize() error = %v, want nil", err)
	}

	// Test Validate
	if err := provider.Validate(context.Background()); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}

	// Test IsCompatibleVersion
	tests := []struct {
		version string
		want    bool
	}{
		{"0.9.0", false},
		{"1.0.0", true},
		{"1.5.0", true},
		{"2.0.0", true},
		{"2.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := provider.IsCompatibleVersion(tt.version); got != tt.want {
				t.Errorf("IsCompatibleVersion(%v) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}