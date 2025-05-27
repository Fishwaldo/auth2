package oauth2_test

import (
	"testing"

	"github.com/Fishwaldo/auth2/pkg/auth/providers/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoogleProfileMapping(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *oauth2.UserInfo
	}{
		{
			name: "complete Google profile with id",
			data: map[string]interface{}{
				"id":              "123456789",
				"email":           "test@gmail.com",
				"email_verified":  true,
				"name":            "Test User",
				"given_name":      "Test",
				"family_name":     "User",
				"picture":         "https://example.com/photo.jpg",
				"locale":          "en-US",
			},
			expected: &oauth2.UserInfo{
				ID:            "123456789",
				ProviderID:    "123456789",
				Email:         "test@gmail.com",
				EmailVerified: true,
				Name:          "Test User",
				GivenName:     "Test",
				FamilyName:    "User",
				Picture:       "https://example.com/photo.jpg",
				Locale:        "en-US",
				ProviderName:  "google",
			},
		},
		{
			name: "Google profile with sub instead of id",
			data: map[string]interface{}{
				"sub":            "123456789",
				"email":          "test@gmail.com",
				"verified_email": true,
				"name":           "Test User",
			},
			expected: &oauth2.UserInfo{
				ID:            "123456789",
				ProviderID:    "123456789",
				Email:         "test@gmail.com",
				EmailVerified: true,
				Name:          "Test User",
				ProviderName:  "google",
			},
		},
		{
			name: "minimal Google profile",
			data: map[string]interface{}{
				"id":    "123456789",
				"email": "test@gmail.com",
			},
			expected: &oauth2.UserInfo{
				ID:           "123456789",
				ProviderID:   "123456789",
				Email:        "test@gmail.com",
				ProviderName: "google",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := oauth2.GoogleProfileMapping(tt.data)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.ProviderID, result.ProviderID)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.EmailVerified, result.EmailVerified)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.GivenName, result.GivenName)
			assert.Equal(t, tt.expected.FamilyName, result.FamilyName)
			assert.Equal(t, tt.expected.Picture, result.Picture)
			assert.Equal(t, tt.expected.Locale, result.Locale)
			assert.Equal(t, tt.expected.ProviderName, result.ProviderName)
			assert.Equal(t, tt.data, result.Raw)
		})
	}
}

func TestGitHubProfileMapping(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *oauth2.UserInfo
	}{
		{
			name: "complete GitHub profile",
			data: map[string]interface{}{
				"id":         float64(12345),
				"email":      "test@github.com",
				"name":       "Test User",
				"login":      "testuser",
				"avatar_url": "https://avatars.githubusercontent.com/u/12345",
			},
			expected: &oauth2.UserInfo{
				ID:            "12345",
				ProviderID:    "12345",
				Email:         "test@github.com",
				EmailVerified: true,
				Name:          "Test User",
				Picture:       "https://avatars.githubusercontent.com/u/12345",
				ProviderName:  "github",
			},
		},
		{
			name: "GitHub profile without name",
			data: map[string]interface{}{
				"id":    float64(12345),
				"email": "test@github.com",
				"login": "testuser",
			},
			expected: &oauth2.UserInfo{
				ID:            "12345",
				ProviderID:    "12345",
				Email:         "test@github.com",
				EmailVerified: true,
				Name:          "testuser",
				ProviderName:  "github",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := oauth2.GitHubProfileMapping(tt.data)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.ProviderID, result.ProviderID)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.EmailVerified, result.EmailVerified)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Picture, result.Picture)
			assert.Equal(t, tt.expected.ProviderName, result.ProviderName)
			assert.Equal(t, tt.data, result.Raw)
		})
	}
}

func TestMicrosoftProfileMapping(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *oauth2.UserInfo
	}{
		{
			name: "complete Microsoft profile with mail",
			data: map[string]interface{}{
				"id":          "123456789",
				"mail":        "test@outlook.com",
				"displayName": "Test User",
				"givenName":   "Test",
				"surname":     "User",
			},
			expected: &oauth2.UserInfo{
				ID:            "123456789",
				ProviderID:    "123456789",
				Email:         "test@outlook.com",
				EmailVerified: true,
				Name:          "Test User",
				GivenName:     "Test",
				FamilyName:    "User",
				ProviderName:  "microsoft",
			},
		},
		{
			name: "Microsoft profile with userPrincipalName",
			data: map[string]interface{}{
				"id":                "123456789",
				"userPrincipalName": "test@contoso.com",
				"displayName":       "Test User",
			},
			expected: &oauth2.UserInfo{
				ID:            "123456789",
				ProviderID:    "123456789",
				Email:         "test@contoso.com",
				EmailVerified: true,
				Name:          "Test User",
				ProviderName:  "microsoft",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := oauth2.MicrosoftProfileMapping(tt.data)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.ProviderID, result.ProviderID)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.EmailVerified, result.EmailVerified)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.GivenName, result.GivenName)
			assert.Equal(t, tt.expected.FamilyName, result.FamilyName)
			assert.Equal(t, tt.expected.ProviderName, result.ProviderName)
			assert.Equal(t, tt.data, result.Raw)
		})
	}
}

func TestFacebookProfileMapping(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *oauth2.UserInfo
	}{
		{
			name: "complete Facebook profile",
			data: map[string]interface{}{
				"id":         "123456789",
				"email":      "test@facebook.com",
				"name":       "Test User",
				"first_name": "Test",
				"last_name":  "User",
				"picture": map[string]interface{}{
					"data": map[string]interface{}{
						"url": "https://example.com/photo.jpg",
					},
				},
			},
			expected: &oauth2.UserInfo{
				ID:            "123456789",
				ProviderID:    "123456789",
				Email:         "test@facebook.com",
				EmailVerified: true,
				Name:          "Test User",
				GivenName:     "Test",
				FamilyName:    "User",
				Picture:       "https://example.com/photo.jpg",
				ProviderName:  "facebook",
			},
		},
		{
			name: "Facebook profile without picture",
			data: map[string]interface{}{
				"id":    "123456789",
				"email": "test@facebook.com",
				"name":  "Test User",
			},
			expected: &oauth2.UserInfo{
				ID:            "123456789",
				ProviderID:    "123456789",
				Email:         "test@facebook.com",
				EmailVerified: true,
				Name:          "Test User",
				ProviderName:  "facebook",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := oauth2.FacebookProfileMapping(tt.data)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.ProviderID, result.ProviderID)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.EmailVerified, result.EmailVerified)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.GivenName, result.GivenName)
			assert.Equal(t, tt.expected.FamilyName, result.FamilyName)
			assert.Equal(t, tt.expected.Picture, result.Picture)
			assert.Equal(t, tt.expected.ProviderName, result.ProviderName)
			assert.Equal(t, tt.data, result.Raw)
		})
	}
}

func TestDefaultProfileMapping(t *testing.T) {
	tests := []struct {
		name     string
		data     map[string]interface{}
		expected *oauth2.UserInfo
	}{
		{
			name: "various field names",
			data: map[string]interface{}{
				"user_id":      "123456789",
				"email":        "test@example.com",
				"display_name": "Test User",
				"avatar_url":   "https://example.com/avatar.jpg",
			},
			expected: &oauth2.UserInfo{
				ID:         "123456789",
				ProviderID: "123456789",
				Email:      "test@example.com",
				Name:       "Test User",
				Picture:    "https://example.com/avatar.jpg",
			},
		},
		{
			name: "alternative field names",
			data: map[string]interface{}{
				"sub":           "987654321",
				"Email":         "test2@example.com",
				"full_name":     "Another User",
				"profile_image": "https://example.com/profile.jpg",
			},
			expected: &oauth2.UserInfo{
				ID:         "987654321",
				ProviderID: "987654321",
				Email:      "test2@example.com",
				Name:       "Another User",
				Picture:    "https://example.com/profile.jpg",
			},
		},
		{
			name: "no matching fields",
			data: map[string]interface{}{
				"unknown_field": "value",
			},
			expected: &oauth2.UserInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := oauth2.DefaultProfileMapping(tt.data)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.ProviderID, result.ProviderID)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.Name, result.Name)
			assert.Equal(t, tt.expected.Picture, result.Picture)
			assert.Equal(t, tt.data, result.Raw)
		})
	}
}