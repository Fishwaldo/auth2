package password_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/user/password"
)

// TestPasswordHashing tests password hashing and verification
func TestPasswordHashing(t *testing.T) {
	// Create a password utils with default parameters
	utils := password.NewUtils(nil, nil, password.Argon2id)
	
	// Test password hashing
	ctx := context.Background()
	testPassword := "TestPassword123!"
	
	// Hash the password
	hash, err := utils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// Verify the hash format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("HashPassword() hash = %v, want prefix $argon2id$", hash)
	}
	
	// Verify the correct password
	valid, err := utils.VerifyPassword(ctx, testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() valid = %v, want true", valid)
	}
	
	// Verify an incorrect password
	valid, err = utils.VerifyPassword(ctx, "WrongPassword", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if valid {
		t.Errorf("VerifyPassword() valid = %v, want false", valid)
	}
}

// TestPasswordGeneration tests password generation
func TestPasswordGeneration(t *testing.T) {
	// Create a password utils with a policy requiring complexity
	policy := &password.Policy{
		MinLength:       12,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
	
	utils := password.NewUtils(policy, nil, password.Argon2id)
	
	// Generate a password
	ctx := context.Background()
	generatedPassword, err := utils.GeneratePassword(ctx, 16)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	
	// Verify the password meets the policy requirements
	if len(generatedPassword) < policy.MinLength {
		t.Errorf("GeneratePassword() length = %v, want at least %v", len(generatedPassword), policy.MinLength)
	}
	
	// Check for uppercase
	if !strings.ContainsAny(generatedPassword, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Errorf("GeneratePassword() missing uppercase letter")
	}
	
	// Check for lowercase
	if !strings.ContainsAny(generatedPassword, "abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("GeneratePassword() missing lowercase letter")
	}
	
	// Check for digit
	if !strings.ContainsAny(generatedPassword, "0123456789") {
		t.Errorf("GeneratePassword() missing digit")
	}
	
	// Check for special character
	if !strings.ContainsAny(generatedPassword, "!@#$%^&*()-_=+[]{}|;:,.<>?") {
		t.Errorf("GeneratePassword() missing special character")
	}
}

// TestPasswordPolicyValidation tests password policy validation
func TestPasswordPolicyValidation(t *testing.T) {
	// Create a password utils with a policy requiring complexity
	policy := &password.Policy{
		MinLength:       8,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
		MaxRepeatedChars: 2,
	}
	
	utils := password.NewUtils(policy, nil, password.Argon2id)
	
	// Test cases
	testCases := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid password",
			password: "Valid123!",
			wantErr:  false,
		},
		{
			name:     "Too short",
			password: "Short1!",
			wantErr:  true,
		},
		{
			name:     "No uppercase",
			password: "nouppercase123!",
			wantErr:  true,
		},
		{
			name:     "No lowercase",
			password: "NOLOWERCASE123!",
			wantErr:  true,
		},
		{
			name:     "No digit",
			password: "NoDigit!@#",
			wantErr:  true,
		},
		{
			name:     "No special",
			password: "NoSpecial123",
			wantErr:  true,
		},
		{
			name:     "Too many repeated characters",
			password: "Repeat111!",
			wantErr:  true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := utils.ValidatePolicy(context.Background(), tc.password)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePolicy() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestTokenGeneration tests token generation
func TestTokenGeneration(t *testing.T) {
	// Create a password utils
	utils := password.NewUtils(nil, nil, password.Argon2id)
	
	// Generate a reset token
	ctx := context.Background()
	resetToken, err := utils.GenerateResetToken(ctx)
	if err != nil {
		t.Fatalf("GenerateResetToken() error = %v", err)
	}
	
	// Verify the token is not empty
	if resetToken == "" {
		t.Errorf("GenerateResetToken() token is empty")
	}
	
	// Generate a verification token
	verificationToken, err := utils.GenerateVerificationToken(ctx)
	if err != nil {
		t.Fatalf("GenerateVerificationToken() error = %v", err)
	}
	
	// Verify the token is not empty
	if verificationToken == "" {
		t.Errorf("GenerateVerificationToken() token is empty")
	}
	
	// Verify the tokens are different
	if resetToken == verificationToken {
		t.Errorf("Tokens are identical, should be different")
	}
}

// TestArgon2Params tests Argon2 parameter configuration
func TestArgon2Params(t *testing.T) {
	// Create custom Argon2 params
	params := &password.Argon2Params{
		Memory:      32 * 1024, // 32 MB
		Iterations:  2,
		Parallelism: 2,
		SaltLength:  8,
		KeyLength:   16,
	}
	
	// Create a password utils with custom params
	utils := password.NewUtils(nil, params, password.Argon2id)
	
	// Hash a password
	ctx := context.Background()
	testPassword := "TestPassword123!"
	
	hash, err := utils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// Verify the hash includes the custom parameters
	if !strings.Contains(hash, "m=32768") {
		t.Errorf("Hash does not contain expected memory parameter: %s", hash)
	}
	
	if !strings.Contains(hash, "t=2") {
		t.Errorf("Hash does not contain expected iterations parameter: %s", hash)
	}
	
	if !strings.Contains(hash, "p=2") {
		t.Errorf("Hash does not contain expected parallelism parameter: %s", hash)
	}
	
	// Verify the password still validates
	valid, err := utils.VerifyPassword(ctx, testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() valid = %v, want true", valid)
	}
}