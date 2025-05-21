package password_test

import (
	"context"
	"strings"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/user/password"
	"golang.org/x/crypto/bcrypt"
)

// TestArgon2idHashing tests Argon2id password hashing and verification
func TestArgon2idHashing(t *testing.T) {
	// Create a password utils with default parameters
	utils := password.NewUtils(nil, nil, nil, password.Argon2id)
	
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
	
	// Test with empty password
	_, err = utils.HashPassword(ctx, "")
	if err != nil {
		t.Fatalf("HashPassword() with empty password should not error, got %v", err)
	}
	
	// Test verification with empty password
	valid, err = utils.VerifyPassword(ctx, "", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() with empty password error = %v", err)
	}
	if valid {
		t.Errorf("VerifyPassword() with empty password valid = %v, want false", valid)
	}
}

// TestBcryptHashing tests bcrypt password hashing and verification
func TestBcryptHashing(t *testing.T) {
	// Create a password utils with bcrypt algorithm
	utils := password.NewUtils(nil, nil, nil, password.Bcrypt)
	
	// Test password hashing
	ctx := context.Background()
	testPassword := "TestPassword123!"
	
	// Hash the password
	hash, err := utils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// Verify the hash format (bcrypt uses $2a$, $2b$, or $2y$ prefix)
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("HashPassword() hash = %v, want prefix $2", hash)
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
	
	// Test with empty password (should work but never validate)
	_, err = utils.HashPassword(ctx, "")
	if err != nil {
		t.Fatalf("HashPassword() with empty password should not error, got %v", err)
	}
	
	// Test verification with empty password against a valid hash
	valid, err = utils.VerifyPassword(ctx, "", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() with empty password error = %v", err)
	}
	if valid {
		t.Errorf("VerifyPassword() with empty password valid = %v, want false", valid)
	}
}

// TestBcryptWithExternalHash tests bcrypt verification with externally generated hash
func TestBcryptWithExternalHash(t *testing.T) {
	utils := password.NewUtils(nil, nil, nil, password.Bcrypt)
	ctx := context.Background()
	testPassword := "TestExternalHash!"
	
	// Generate a hash using the standard bcrypt package directly
	externalHash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword() error = %v", err)
	}
	
	// Verify our Utils can validate against an externally generated hash
	valid, err := utils.VerifyPassword(ctx, testPassword, string(externalHash))
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !valid {
		t.Errorf("VerifyPassword() should validate external bcrypt hash, got valid = %v", valid)
	}
}

// TestHashVerifyCompatibility tests that hashes generated with one algorithm are verified correctly
func TestHashVerifyCompatibility(t *testing.T) {
	// Hash with Argon2id, verify with both algorithms
	argon2Utils := password.NewUtils(nil, nil, nil, password.Argon2id)
	bcryptUtils := password.NewUtils(nil, nil, nil, password.Bcrypt)
	compatUtils := password.NewUtils(nil, nil, nil, "") // Default to Argon2id
	
	ctx := context.Background()
	testPassword := "CompatibilityTest123!"
	
	// Generate Argon2id hash
	argon2Hash, err := argon2Utils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword(Argon2id) error = %v", err)
	}
	
	// Generate bcrypt hash
	bcryptHash, err := bcryptUtils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword(Bcrypt) error = %v", err)
	}
	
	// Verify Argon2id hash with all utils instances
	valid, err := argon2Utils.VerifyPassword(ctx, testPassword, argon2Hash)
	if err != nil || !valid {
		t.Errorf("VerifyPassword() argon2Utils with argon2Hash failed, err = %v, valid = %v", err, valid)
	}
	
	valid, err = bcryptUtils.VerifyPassword(ctx, testPassword, argon2Hash)
	if err != nil || !valid {
		t.Errorf("VerifyPassword() bcryptUtils with argon2Hash failed, err = %v, valid = %v", err, valid)
	}
	
	valid, err = compatUtils.VerifyPassword(ctx, testPassword, argon2Hash)
	if err != nil || !valid {
		t.Errorf("VerifyPassword() compatUtils with argon2Hash failed, err = %v, valid = %v", err, valid)
	}
	
	// Verify bcrypt hash with all utils instances
	valid, err = argon2Utils.VerifyPassword(ctx, testPassword, bcryptHash)
	if err != nil || !valid {
		t.Errorf("VerifyPassword() argon2Utils with bcryptHash failed, err = %v, valid = %v", err, valid)
	}
	
	valid, err = bcryptUtils.VerifyPassword(ctx, testPassword, bcryptHash)
	if err != nil || !valid {
		t.Errorf("VerifyPassword() bcryptUtils with bcryptHash failed, err = %v, valid = %v", err, valid)
	}
	
	valid, err = compatUtils.VerifyPassword(ctx, testPassword, bcryptHash)
	if err != nil || !valid {
		t.Errorf("VerifyPassword() compatUtils with bcryptHash failed, err = %v, valid = %v", err, valid)
	}
}

// TestInvalidHashes tests verification with invalid hash formats
func TestInvalidHashes(t *testing.T) {
	utils := password.NewUtils(nil, nil, nil, password.Argon2id)
	ctx := context.Background()
	
	testCases := []struct {
		name     string
		hash     string
		wantErr  bool
	}{
		{
			name:    "Empty hash",
			hash:    "",
			wantErr: true,
		},
		{
			name:    "Invalid format (no $ separator)",
			hash:    "invalid-hash-format",
			wantErr: true,
		},
		{
			name:    "Invalid format (only one part)",
			hash:    "$invalid",
			wantErr: true,
		},
		{
			name:    "Unknown algorithm",
			hash:    "$unknown$v=1$params$salt$hash",
			wantErr: true,
		},
		{
			name:    "Invalid Argon2id format",
			hash:    "$argon2id$invalid-params$salt$hash",
			wantErr: true,
		},
		{
			name:    "Invalid bcrypt format",
			hash:    "$2z$10$invalidbcrypthashformat",
			wantErr: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := utils.VerifyPassword(ctx, "password", tc.hash)
			if (err != nil) != tc.wantErr {
				t.Errorf("VerifyPassword() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
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
	
	utils := password.NewUtils(policy, nil, nil, password.Argon2id)
	
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
	
	// Test with length shorter than policy
	shortPassword, err := utils.GeneratePassword(ctx, 8)
	if err != nil {
		t.Fatalf("GeneratePassword() with short length error = %v", err)
	}
	if len(shortPassword) < policy.MinLength {
		t.Errorf("GeneratePassword() with short length should default to policy minimum")
	}
	
	// Test with zero length
	zeroPassword, err := utils.GeneratePassword(ctx, 0)
	if err != nil {
		t.Fatalf("GeneratePassword() with zero length error = %v", err)
	}
	if len(zeroPassword) < policy.MinLength {
		t.Errorf("GeneratePassword() with zero length should default to policy minimum")
	}
}

// TestMinimalPolicy tests password generation with minimal policy
func TestMinimalPolicy(t *testing.T) {
	// Create a minimal policy with no requirements
	policy := &password.Policy{
		MinLength:       6,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireDigit:     false,
		RequireSpecial:   false,
	}
	
	utils := password.NewUtils(policy, nil, nil, password.Argon2id)
	
	// Generate a password
	ctx := context.Background()
	generatedPassword, err := utils.GeneratePassword(ctx, 8)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	
	// Verify the password length
	if len(generatedPassword) < policy.MinLength {
		t.Errorf("GeneratePassword() length = %v, want at least %v", len(generatedPassword), policy.MinLength)
	}
	
	// Should still validate against policy
	err = utils.ValidatePolicy(ctx, generatedPassword)
	if err != nil {
		t.Errorf("ValidatePolicy() error = %v on generated password", err)
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
	
	utils := password.NewUtils(policy, nil, nil, password.Argon2id)
	
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
		{
			name:     "Empty password",
			password: "",
			wantErr:  true,
		},
		{
			name:     "Very long password",
			password: strings.Repeat("A1b@", 25), // 100 chars
			wantErr:  false,
		},
		{
			name:     "Only repeated characters but within limit",
			password: "Ab1!Ab1!Ab1!",
			wantErr:  false,
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
	utils := password.NewUtils(nil, nil, nil, password.Argon2id)
	
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
	
	// Test multiple generations to ensure uniqueness
	tokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		token, err := utils.GenerateResetToken(ctx)
		if err != nil {
			t.Fatalf("GenerateResetToken() error = %v at iteration %d", err, i)
		}
		
		if tokens[token] {
			t.Errorf("GenerateResetToken() generated duplicate token: %s", token)
		}
		
		tokens[token] = true
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
	utils := password.NewUtils(nil, params, nil, password.Argon2id)
	
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
	
	// Test extremes 
	extremeParams := &password.Argon2Params{
		Memory:      1024,      // 1 MB (very low)
		Iterations:  1,         // Minimum
		Parallelism: 1,         // Minimum
		SaltLength:  4,         // Very short salt
		KeyLength:   8,         // Very short key
	}
	
	extremeUtils := password.NewUtils(nil, extremeParams, nil, password.Argon2id)
	
	extremeHash, err := extremeUtils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() with extreme params error = %v", err)
	}
	
	valid, err = extremeUtils.VerifyPassword(ctx, testPassword, extremeHash)
	if err != nil {
		t.Fatalf("VerifyPassword() with extreme params error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() with extreme params valid = %v, want true", valid)
	}
}

// TestBcryptParams tests Bcrypt parameter configuration
func TestBcryptParams(t *testing.T) {
	// Create custom Bcrypt params
	params := &password.BcryptParams{
		Cost: 10, // Lower cost for faster tests
	}
	
	// Create a password utils with custom params
	utils := password.NewUtils(nil, nil, params, password.Bcrypt)
	
	// Hash a password
	ctx := context.Background()
	testPassword := "TestPassword123!"
	
	hash, err := utils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	// Verify the password still validates
	valid, err := utils.VerifyPassword(ctx, testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() valid = %v, want true", valid)
	}
	
	// Test with minimum cost
	minCostParams := &password.BcryptParams{
		Cost: bcrypt.MinCost, // 4
	}
	
	minCostUtils := password.NewUtils(nil, nil, minCostParams, password.Bcrypt)
	
	minCostHash, err := minCostUtils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() with min cost error = %v", err)
	}
	
	valid, err = minCostUtils.VerifyPassword(ctx, testPassword, minCostHash)
	if err != nil {
		t.Fatalf("VerifyPassword() with min cost error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() with min cost valid = %v, want true", valid)
	}
	
	// Test with maximum cost (only if test environment can handle it)
	if testing.Short() {
		t.Skip("Skipping max cost bcrypt test in short mode")
	}
	
	maxCostParams := &password.BcryptParams{
		Cost: 15, // Not using bcrypt.MaxCost (31) as it would be too slow for tests
	}
	
	maxCostUtils := password.NewUtils(nil, nil, maxCostParams, password.Bcrypt)
	
	maxCostHash, err := maxCostUtils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() with max cost error = %v", err)
	}
	
	valid, err = maxCostUtils.VerifyPassword(ctx, testPassword, maxCostHash)
	if err != nil {
		t.Fatalf("VerifyPassword() with max cost error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() with max cost valid = %v, want true", valid)
	}
}

// TestUnsupportedAlgorithm tests handling of unsupported hashing algorithms
func TestUnsupportedAlgorithm(t *testing.T) {
	// Create a utils with an unsupported algorithm
	utils := password.NewUtils(nil, nil, nil, "unsupported")
	
	ctx := context.Background()
	_, err := utils.HashPassword(ctx, "test")
	if err == nil {
		t.Errorf("HashPassword() with unsupported algorithm should error")
	}
}

// TestDefaultUtilsCreation tests creating Utils with default values
func TestDefaultUtilsCreation(t *testing.T) {
	// Create a utils with nil parameters (should use defaults)
	utils := password.NewUtils(nil, nil, nil, "")
	
	ctx := context.Background()
	testPassword := "DefaultTest123!"
	
	// Should default to Argon2id
	hash, err := utils.HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("HashPassword() should default to Argon2id, got hash = %v", hash)
	}
	
	// Should be able to verify the password
	valid, err := utils.VerifyPassword(ctx, testPassword, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	
	if !valid {
		t.Errorf("VerifyPassword() valid = %v, want true", valid)
	}
	
	// Generate a password with default policy
	generatedPassword, err := utils.GeneratePassword(ctx, 0)
	if err != nil {
		t.Fatalf("GeneratePassword() error = %v", err)
	}
	
	// Default policy min length is 8
	if len(generatedPassword) < 8 {
		t.Errorf("GeneratePassword() with default policy should have min length 8, got %d", len(generatedPassword))
	}
}