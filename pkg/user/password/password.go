package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
	
	"golang.org/x/crypto/argon2"
)

// HashingAlgorithm defines the supported password hashing algorithms
type HashingAlgorithm string

const (
	// Argon2id is the recommended algorithm for password hashing
	Argon2id HashingAlgorithm = "argon2id"
)

// Policy defines a password policy
type Policy struct {
	// MinLength is the minimum password length
	MinLength int
	
	// RequireUppercase requires at least one uppercase letter
	RequireUppercase bool
	
	// RequireLowercase requires at least one lowercase letter
	RequireLowercase bool
	
	// RequireDigit requires at least one numeric digit
	RequireDigit bool
	
	// RequireSpecial requires at least one special character
	RequireSpecial bool
	
	// MaxRepeatedChars is the maximum number of repeated characters allowed
	MaxRepeatedChars int
	
	// DisallowCommonPasswords disallows common passwords
	DisallowCommonPasswords bool
	
	// DisallowPersonalInfo disallows personal information in passwords
	DisallowPersonalInfo bool
	
	// RequiredPasswordHistory is the number of previous passwords that cannot be reused
	RequiredPasswordHistory int
}

// DefaultPolicy returns a default password policy
func DefaultPolicy() *Policy {
	return &Policy{
		MinLength:              8,
		RequireUppercase:       true,
		RequireLowercase:       true,
		RequireDigit:           true,
		RequireSpecial:         true,
		MaxRepeatedChars:       3,
		DisallowCommonPasswords: true,
		DisallowPersonalInfo:   true,
		RequiredPasswordHistory: 3,
	}
}

// Argon2Params defines parameters for Argon2 password hashing
type Argon2Params struct {
	// Memory is the amount of memory to use (in KiB)
	Memory uint32
	
	// Iterations is the number of iterations
	Iterations uint32
	
	// Parallelism is the number of threads to use
	Parallelism uint8
	
	// SaltLength is the length of the salt in bytes
	SaltLength uint32
	
	// KeyLength is the length of the key in bytes
	KeyLength uint32
}

// DefaultArgon2Params returns recommended Argon2 parameters
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Utils implements password utilities
type Utils struct {
	policy         *Policy
	argon2Params   *Argon2Params
	hashingAlgo    HashingAlgorithm
	tokenGenerator *TokenGenerator
}

// NewUtils creates a new password utilities instance
func NewUtils(policy *Policy, argon2Params *Argon2Params, hashingAlgo HashingAlgorithm) *Utils {
	if policy == nil {
		policy = DefaultPolicy()
	}
	
	if argon2Params == nil {
		argon2Params = DefaultArgon2Params()
	}
	
	if hashingAlgo == "" {
		hashingAlgo = Argon2id
	}
	
	return &Utils{
		policy:         policy,
		argon2Params:   argon2Params,
		hashingAlgo:    hashingAlgo,
		tokenGenerator: NewTokenGenerator(),
	}
}

// HashPassword hashes a password
func (u *Utils) HashPassword(ctx context.Context, password string) (string, error) {
	switch u.hashingAlgo {
	case Argon2id:
		return u.hashArgon2id(password)
	default:
		return "", fmt.Errorf("unsupported hashing algorithm: %s", u.hashingAlgo)
	}
}

// VerifyPassword verifies a password against a hash
func (u *Utils) VerifyPassword(ctx context.Context, password, hash string) (bool, error) {
	// Extract the algorithm from the hash
	parts := strings.Split(hash, "$")
	if len(parts) < 2 {
		return false, fmt.Errorf("invalid hash format")
	}
	
	// Verify based on the algorithm used for hashing
	switch parts[1] {
	case "argon2id":
		return u.verifyArgon2id(password, hash)
	default:
		return false, fmt.Errorf("unsupported hashing algorithm: %s", parts[1])
	}
}

// GeneratePassword generates a secure random password
func (u *Utils) GeneratePassword(ctx context.Context, length int) (string, error) {
	if length < u.policy.MinLength {
		length = u.policy.MinLength
	}
	
	// Define character sets
	upperChars := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars := "abcdefghijklmnopqrstuvwxyz"
	digitChars := "0123456789"
	specialChars := "!@#$%^&*()-_=+[]{}|;:,.<>?"
	
	// Create a combined character set based on policy
	chars := ""
	if u.policy.RequireUppercase {
		chars += upperChars
	}
	if u.policy.RequireLowercase {
		chars += lowerChars
	}
	if u.policy.RequireDigit {
		chars += digitChars
	}
	if u.policy.RequireSpecial {
		chars += specialChars
	}
	
	// If no character sets were selected, use a default
	if chars == "" {
		chars = lowerChars + digitChars
	}
	
	// Generate the random password
	result := make([]byte, length)
	charsLen := len(chars)
	
	// Generate random bytes
	if _, err := rand.Read(result); err != nil {
		return "", err
	}
	
	// Map random bytes to characters
	for i := range result {
		result[i] = chars[int(result[i])%charsLen]
	}
	
	// Ensure the password meets the policy requirements
	password := string(result)
	
	// Make sure at least one character from each required set is included
	if u.policy.RequireUppercase && !strings.ContainsAny(password, upperChars) {
		idx := int(result[0]) % length
		result[idx] = upperChars[int(result[idx])%len(upperChars)]
	}
	
	if u.policy.RequireLowercase && !strings.ContainsAny(password, lowerChars) {
		idx := int(result[1]%byte(length))
		result[idx] = lowerChars[int(result[idx])%len(lowerChars)]
	}
	
	if u.policy.RequireDigit && !strings.ContainsAny(password, digitChars) {
		idx := int(result[2]%byte(length))
		result[idx] = digitChars[int(result[idx])%len(digitChars)]
	}
	
	if u.policy.RequireSpecial && !strings.ContainsAny(password, specialChars) {
		idx := int(result[3]%byte(length))
		result[idx] = specialChars[int(result[idx])%len(specialChars)]
	}
	
	return string(result), nil
}

// GenerateResetToken generates a password reset token
func (u *Utils) GenerateResetToken(ctx context.Context) (string, error) {
	return u.tokenGenerator.GenerateToken(32)
}

// GenerateVerificationToken generates an email verification token
func (u *Utils) GenerateVerificationToken(ctx context.Context) (string, error) {
	return u.tokenGenerator.GenerateToken(32)
}

// ValidatePolicy validates a password against the policy
func (u *Utils) ValidatePolicy(ctx context.Context, password string) error {
	// Check minimum length
	if len(password) < u.policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", u.policy.MinLength)
	}
	
	// Check character requirements
	if u.policy.RequireUppercase && !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	
	if u.policy.RequireLowercase && !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	
	if u.policy.RequireDigit && !strings.ContainsAny(password, "0123456789") {
		return fmt.Errorf("password must contain at least one digit")
	}
	
	if u.policy.RequireSpecial && !strings.ContainsAny(password, "!@#$%^&*()-_=+[]{}|;:,.<>?") {
		return fmt.Errorf("password must contain at least one special character")
	}
	
	// Check for repeated characters
	if u.policy.MaxRepeatedChars > 0 {
		for i := 0; i < len(password)-u.policy.MaxRepeatedChars; i++ {
			repeated := true
			for j := 1; j <= u.policy.MaxRepeatedChars; j++ {
				if password[i] != password[i+j-1] {
					repeated = false
					break
				}
			}
			if repeated {
				return fmt.Errorf("password cannot contain more than %d consecutive identical characters", u.policy.MaxRepeatedChars)
			}
		}
	}
	
	// Additional checks would be implemented here:
	// - Check against common passwords
	// - Check against personal information
	// - Check against password history
	
	return nil
}

// hashArgon2id hashes a password using Argon2id
func (u *Utils) hashArgon2id(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, u.argon2Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	
	// Hash the password
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		u.argon2Params.Iterations,
		u.argon2Params.Memory,
		u.argon2Params.Parallelism,
		u.argon2Params.KeyLength,
	)
	
	// Encode the parameters, salt, and key
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	
	// Format: $argon2id$v=19$m=memory,t=iterations,p=parallelism$salt$hash
	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		u.argon2Params.Memory,
		u.argon2Params.Iterations,
		u.argon2Params.Parallelism,
		b64Salt,
		b64Hash,
	)
	
	return encodedHash, nil
}

// verifyArgon2id verifies a password against an Argon2id hash
func (u *Utils) verifyArgon2id(password, encodedHash string) (bool, error) {
	// Extract the parameters, salt, and hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format")
	}
	
	// Extract the Argon2 parameters
	var version int
	var memory, iterations uint32
	var parallelism uint8
	
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, err
	}
	
	// Decode the salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	
	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	
	// Compute the hash of the provided password
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		uint32(len(decodedHash)),
	)
	
	// Compare the computed hash with the decoded hash
	return subtle.ConstantTimeCompare(computedHash, decodedHash) == 1, nil
}

// TokenGenerator generates secure tokens
type TokenGenerator struct{}

// NewTokenGenerator creates a new token generator
func NewTokenGenerator() *TokenGenerator {
	return &TokenGenerator{}
}

// GenerateToken generates a secure random token
func (g *TokenGenerator) GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}