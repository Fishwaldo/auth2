package user

import (
	"context"
	"time"
)

// User represents a user in the authentication system
type User struct {
	// ID is the unique identifier for the user
	ID string
	
	// Username is the username for the user
	Username string
	
	// Email is the email address for the user
	Email string
	
	// PasswordHash is the hashed password for the user (if applicable)
	PasswordHash string
	
	// Enabled indicates if the user account is enabled
	Enabled bool
	
	// Locked indicates if the user account is locked
	Locked bool
	
	// EmailVerified indicates if the user's email has been verified
	EmailVerified bool
	
	// MFAEnabled indicates if multi-factor authentication is enabled for the user
	MFAEnabled bool
	
	// MFAMethods contains the methods configured for multi-factor authentication
	MFAMethods []string
	
	// LastLogin is the timestamp of the last successful login
	LastLogin time.Time
	
	// FailedLoginAttempts is the number of consecutive failed login attempts
	FailedLoginAttempts int
	
	// LastFailedLogin is the timestamp of the last failed login attempt
	LastFailedLogin time.Time
	
	// LockoutTime is the timestamp when the user account was locked (if applicable)
	LockoutTime time.Time
	
	// LockoutReason contains the reason why the account was locked (if applicable)
	LockoutReason string
	
	// RequirePasswordChange indicates if the user must change their password at next login
	RequirePasswordChange bool
	
	// CreatedAt is the timestamp when the user was created
	CreatedAt time.Time
	
	// UpdatedAt is the timestamp when the user was last updated
	UpdatedAt time.Time
	
	// Profile contains additional user profile information
	Profile map[string]interface{}
	
	// Metadata contains system-related user metadata
	Metadata map[string]interface{}
}

// Store defines the interface for user data storage operations
type Store interface {
	// Create creates a new user
	Create(ctx context.Context, user *User) error
	
	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id string) (*User, error)
	
	// GetByUsername retrieves a user by username
	GetByUsername(ctx context.Context, username string) (*User, error)
	
	// GetByEmail retrieves a user by email
	GetByEmail(ctx context.Context, email string) (*User, error)
	
	// Update updates an existing user
	Update(ctx context.Context, user *User) error
	
	// Delete deletes a user
	Delete(ctx context.Context, id string) error
	
	// List retrieves users based on a filter
	List(ctx context.Context, filter map[string]interface{}, offset, limit int) ([]*User, error)
	
	// Count counts users based on a filter
	Count(ctx context.Context, filter map[string]interface{}) (int, error)
}

// Service provides user management operations
type Service interface {
	// Register registers a new user
	Register(ctx context.Context, username, email, password string) (*User, error)
	
	// Authenticate authenticates a user with the provided credentials
	Authenticate(ctx context.Context, username, password string) (*User, error)
	
	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, id string) (*User, error)
	
	// UpdateUser updates user information
	UpdateUser(ctx context.Context, user *User) error
	
	// ChangePassword changes a user's password
	ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error
	
	// ResetPassword resets a user's password (for password recovery)
	ResetPassword(ctx context.Context, userID, token, newPassword string) error
	
	// InitiatePasswordReset initiates the password reset process
	InitiatePasswordReset(ctx context.Context, email string) error
	
	// LockUser locks a user account
	LockUser(ctx context.Context, userID, reason string) error
	
	// UnlockUser unlocks a user account
	UnlockUser(ctx context.Context, userID string) error
	
	// VerifyEmail verifies a user's email
	VerifyEmail(ctx context.Context, userID, token string) error
	
	// SendVerificationEmail sends an email verification to the user
	SendVerificationEmail(ctx context.Context, userID string) error
	
	// EnableMFA enables multi-factor authentication for a user
	EnableMFA(ctx context.Context, userID, method string) error
	
	// DisableMFA disables multi-factor authentication for a user
	DisableMFA(ctx context.Context, userID, method string) error
	
	// TrackLoginAttempt tracks a login attempt (successful or failed)
	TrackLoginAttempt(ctx context.Context, userID string, successful bool) error
}

// Manager is responsible for user management
type Manager struct {
	store         Store
	passwordUtils PasswordUtils
	profileStore  ProfileStore
	validators    []Validator
}

// NewManager creates a new user manager
func NewManager(store Store, passwordUtils PasswordUtils, profileStore ProfileStore) *Manager {
	return &Manager{
		store:         store,
		passwordUtils: passwordUtils,
		profileStore:  profileStore,
		validators:    make([]Validator, 0),
	}
}

// AddValidator adds a validator to the user manager
func (m *Manager) AddValidator(validator Validator) {
	m.validators = append(m.validators, validator)
}

// Register registers a new user
func (m *Manager) Register(ctx context.Context, username, email, password string) (*User, error) {
	// Create a new user
	user := &User{
		Username:     username,
		Email:        email,
		Enabled:      true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Profile:      make(map[string]interface{}),
		Metadata:     make(map[string]interface{}),
	}
	
	// Validate the user
	for _, validator := range m.validators {
		if err := validator.ValidateNewUser(ctx, user, password); err != nil {
			return nil, err
		}
	}
	
	// Hash the password
	hashedPassword, err := m.passwordUtils.HashPassword(ctx, password)
	if err != nil {
		return nil, err
	}
	user.PasswordHash = hashedPassword
	
	// Create the user in the store
	if err := m.store.Create(ctx, user); err != nil {
		return nil, err
	}
	
	return user, nil
}

// Authenticate authenticates a user with the provided credentials
func (m *Manager) Authenticate(ctx context.Context, username, password string) (*User, error) {
	// Get the user by username
	user, err := m.store.GetByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	
	// Verify the password
	match, err := m.passwordUtils.VerifyPassword(ctx, password, user.PasswordHash)
	if err != nil {
		return nil, err
	}
	
	if !match {
		// Track failed login attempt
		if err := m.TrackLoginAttempt(ctx, user.ID, false); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	
	// Track successful login attempt
	if err := m.TrackLoginAttempt(ctx, user.ID, true); err != nil {
		return nil, err
	}
	
	return user, nil
}

// GetUser retrieves a user by ID
func (m *Manager) GetUser(ctx context.Context, id string) (*User, error) {
	return m.store.GetByID(ctx, id)
}

// UpdateUser updates user information
func (m *Manager) UpdateUser(ctx context.Context, user *User) error {
	// Validate the user update
	for _, validator := range m.validators {
		if err := validator.ValidateUserUpdate(ctx, user); err != nil {
			return err
		}
	}
	
	// Update the user
	user.UpdatedAt = time.Now()
	return m.store.Update(ctx, user)
}

// ChangePassword changes a user's password
func (m *Manager) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Verify the current password
	match, err := m.passwordUtils.VerifyPassword(ctx, currentPassword, user.PasswordHash)
	if err != nil {
		return err
	}
	
	if !match {
		return ErrInvalidCredentials
	}
	
	// Validate the new password
	for _, validator := range m.validators {
		if err := validator.ValidatePassword(ctx, user, newPassword); err != nil {
			return err
		}
	}
	
	// Hash and save the new password
	hashedPassword, err := m.passwordUtils.HashPassword(ctx, newPassword)
	if err != nil {
		return err
	}
	
	user.PasswordHash = hashedPassword
	user.RequirePasswordChange = false
	user.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, user)
}

// ResetPassword resets a user's password
func (m *Manager) ResetPassword(ctx context.Context, userID, token, newPassword string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Verify the reset token (implementation-specific)
	// This would typically involve checking the token against a stored token
	// and ensuring it hasn't expired
	if !m.verifyResetToken(ctx, user, token) {
		return ErrInvalidToken
	}
	
	// Validate the new password
	for _, validator := range m.validators {
		if err := validator.ValidatePassword(ctx, user, newPassword); err != nil {
			return err
		}
	}
	
	// Hash and save the new password
	hashedPassword, err := m.passwordUtils.HashPassword(ctx, newPassword)
	if err != nil {
		return err
	}
	
	user.PasswordHash = hashedPassword
	user.UpdatedAt = time.Now()
	
	// Clear any reset token metadata
	delete(user.Metadata, "password_reset_token")
	delete(user.Metadata, "password_reset_expiry")
	
	return m.store.Update(ctx, user)
}

// InitiatePasswordReset initiates the password reset process
func (m *Manager) InitiatePasswordReset(ctx context.Context, email string) error {
	// Get the user by email
	user, err := m.store.GetByEmail(ctx, email)
	if err != nil {
		// We intentionally return nil here to prevent email enumeration attacks
		// The user will receive the same message whether the email exists or not
		return nil
	}
	
	// Generate a reset token
	token, err := m.passwordUtils.GenerateResetToken(ctx)
	if err != nil {
		return err
	}
	
	// Store the token and expiry in the user's metadata
	expiry := time.Now().Add(24 * time.Hour) // 24-hour expiry
	
	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}
	
	user.Metadata["password_reset_token"] = token
	user.Metadata["password_reset_expiry"] = expiry.Unix()
	user.UpdatedAt = time.Now()
	
	if err := m.store.Update(ctx, user); err != nil {
		return err
	}
	
	// Send the reset email (implementation-specific)
	// This would typically involve sending an email with a link containing the token
	if err := m.sendPasswordResetEmail(ctx, user, token); err != nil {
		return err
	}
	
	return nil
}

// LockUser locks a user account
func (m *Manager) LockUser(ctx context.Context, userID, reason string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Lock the user
	user.Locked = true
	user.LockoutTime = time.Now()
	user.LockoutReason = reason
	user.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, user)
}

// UnlockUser unlocks a user account
func (m *Manager) UnlockUser(ctx context.Context, userID string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Unlock the user
	user.Locked = false
	user.LockoutTime = time.Time{}
	user.LockoutReason = ""
	user.FailedLoginAttempts = 0
	user.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, user)
}

// VerifyEmail verifies a user's email
func (m *Manager) VerifyEmail(ctx context.Context, userID, token string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Verify the email verification token (implementation-specific)
	if !m.verifyEmailToken(ctx, user, token) {
		return ErrInvalidToken
	}
	
	// Mark the email as verified
	user.EmailVerified = true
	user.UpdatedAt = time.Now()
	
	// Clear any verification token metadata
	delete(user.Metadata, "email_verification_token")
	delete(user.Metadata, "email_verification_expiry")
	
	return m.store.Update(ctx, user)
}

// SendVerificationEmail sends an email verification to the user
func (m *Manager) SendVerificationEmail(ctx context.Context, userID string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Generate a verification token
	token, err := m.passwordUtils.GenerateVerificationToken(ctx)
	if err != nil {
		return err
	}
	
	// Store the token and expiry in the user's metadata
	expiry := time.Now().Add(24 * time.Hour) // 24-hour expiry
	
	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}
	
	user.Metadata["email_verification_token"] = token
	user.Metadata["email_verification_expiry"] = expiry.Unix()
	user.UpdatedAt = time.Now()
	
	if err := m.store.Update(ctx, user); err != nil {
		return err
	}
	
	// Send the verification email (implementation-specific)
	if err := m.sendVerificationEmail(ctx, user, token); err != nil {
		return err
	}
	
	return nil
}

// EnableMFA enables multi-factor authentication for a user
func (m *Manager) EnableMFA(ctx context.Context, userID, method string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Check if MFA is already enabled for this method
	for _, m := range user.MFAMethods {
		if m == method {
			return ErrMFAAlreadyEnabled
		}
	}
	
	// Enable MFA for the specified method
	user.MFAMethods = append(user.MFAMethods, method)
	user.MFAEnabled = true
	user.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, user)
}

// DisableMFA disables multi-factor authentication for a user
func (m *Manager) DisableMFA(ctx context.Context, userID, method string) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	// Find and remove the specified MFA method
	found := false
	methods := make([]string, 0, len(user.MFAMethods))
	for _, m := range user.MFAMethods {
		if m != method {
			methods = append(methods, m)
		} else {
			found = true
		}
	}
	
	if !found {
		return ErrMFANotEnabled
	}
	
	user.MFAMethods = methods
	
	// If there are no MFA methods left, disable MFA entirely
	if len(methods) == 0 {
		user.MFAEnabled = false
	}
	
	user.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, user)
}

// TrackLoginAttempt tracks a login attempt (successful or failed)
func (m *Manager) TrackLoginAttempt(ctx context.Context, userID string, successful bool) error {
	// Get the user
	user, err := m.store.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	
	if successful {
		// Reset failed login attempts on successful login
		user.FailedLoginAttempts = 0
		user.LastLogin = time.Now()
	} else {
		// Increment failed login attempts
		user.FailedLoginAttempts++
		user.LastFailedLogin = time.Now()
		
		// Check if we need to lock the account
		if m.shouldLockAccount(ctx, user) {
			user.Locked = true
			user.LockoutTime = time.Now()
			user.LockoutReason = "Too many failed login attempts"
		}
	}
	
	user.UpdatedAt = time.Now()
	
	return m.store.Update(ctx, user)
}

// verifyResetToken verifies a password reset token
// Implementation-specific - would check token validity and expiry
func (m *Manager) verifyResetToken(ctx context.Context, user *User, token string) bool {
	storedToken, ok := user.Metadata["password_reset_token"].(string)
	if !ok {
		return false
	}
	
	expiryUnix, ok := user.Metadata["password_reset_expiry"].(int64)
	if !ok {
		return false
	}
	
	// Check if the token has expired
	expiry := time.Unix(expiryUnix, 0)
	if time.Now().After(expiry) {
		return false
	}
	
	// Compare the tokens (in practice, we might use a more secure comparison)
	return token == storedToken
}

// verifyEmailToken verifies an email verification token
// Implementation-specific - would check token validity and expiry
func (m *Manager) verifyEmailToken(ctx context.Context, user *User, token string) bool {
	storedToken, ok := user.Metadata["email_verification_token"].(string)
	if !ok {
		return false
	}
	
	expiryUnix, ok := user.Metadata["email_verification_expiry"].(int64)
	if !ok {
		return false
	}
	
	// Check if the token has expired
	expiry := time.Unix(expiryUnix, 0)
	if time.Now().After(expiry) {
		return false
	}
	
	// Compare the tokens (in practice, we might use a more secure comparison)
	return token == storedToken
}

// shouldLockAccount determines if an account should be locked due to failed login attempts
// This would typically be configurable
func (m *Manager) shouldLockAccount(ctx context.Context, user *User) bool {
	// Example: Lock after 5 failed attempts
	return user.FailedLoginAttempts >= 5
}

// sendPasswordResetEmail sends a password reset email
// Implementation-specific - would send an email with a link containing the token
func (m *Manager) sendPasswordResetEmail(ctx context.Context, user *User, token string) error {
	// This is a placeholder for the actual implementation
	// In a real implementation, this would use an email provider to send an email
	return nil
}

// sendVerificationEmail sends an email verification email
// Implementation-specific - would send an email with a link containing the token
func (m *Manager) sendVerificationEmail(ctx context.Context, user *User, token string) error {
	// This is a placeholder for the actual implementation
	// In a real implementation, this would use an email provider to send an email
	return nil
}

// PasswordUtils defines the interface for password-related operations
type PasswordUtils interface {
	// HashPassword hashes a password
	HashPassword(ctx context.Context, password string) (string, error)
	
	// VerifyPassword verifies a password against a hash
	VerifyPassword(ctx context.Context, password, hash string) (bool, error)
	
	// GeneratePassword generates a secure random password
	GeneratePassword(ctx context.Context, length int) (string, error)
	
	// GenerateResetToken generates a password reset token
	GenerateResetToken(ctx context.Context) (string, error)
	
	// GenerateVerificationToken generates an email verification token
	GenerateVerificationToken(ctx context.Context) (string, error)
}

// ProfileStore defines the interface for user profile operations
type ProfileStore interface {
	// GetProfile retrieves a user's profile
	GetProfile(ctx context.Context, userID string) (map[string]interface{}, error)
	
	// UpdateProfile updates a user's profile
	UpdateProfile(ctx context.Context, userID string, profile map[string]interface{}) error
}

// Validator defines the interface for user validation
type Validator interface {
	// ValidateNewUser validates a new user
	ValidateNewUser(ctx context.Context, user *User, password string) error
	
	// ValidateUserUpdate validates a user update
	ValidateUserUpdate(ctx context.Context, user *User) error
	
	// ValidatePassword validates a password
	ValidatePassword(ctx context.Context, user *User, password string) error
}

// Common errors
var (
	ErrUserNotFound        = &UserError{Code: "user_not_found", Message: "User not found"}
	ErrInvalidCredentials  = &UserError{Code: "invalid_credentials", Message: "Invalid credentials"}
	ErrInvalidToken        = &UserError{Code: "invalid_token", Message: "Invalid token"}
	ErrMFARequired         = &UserError{Code: "mfa_required", Message: "Multi-factor authentication required"}
	ErrMFAAlreadyEnabled   = &UserError{Code: "mfa_already_enabled", Message: "Multi-factor authentication already enabled"}
	ErrMFANotEnabled       = &UserError{Code: "mfa_not_enabled", Message: "Multi-factor authentication not enabled"}
	ErrAccountLocked       = &UserError{Code: "account_locked", Message: "Account is locked"}
	ErrAccountDisabled     = &UserError{Code: "account_disabled", Message: "Account is disabled"}
	ErrEmailNotVerified    = &UserError{Code: "email_not_verified", Message: "Email not verified"}
	ErrPasswordChangeRequired = &UserError{Code: "password_change_required", Message: "Password change required"}
	ErrUsernameExists      = &UserError{Code: "username_exists", Message: "Username already exists"}
	ErrEmailExists         = &UserError{Code: "email_exists", Message: "Email already exists"}
)

// UserError represents a user-related error
type UserError struct {
	Code    string
	Message string
	Cause   error
}

// Error implements the error interface
func (e *UserError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

// Unwrap returns the wrapped error
func (e *UserError) Unwrap() error {
	return e.Cause
}

// WithCause adds a cause to the error
func (e *UserError) WithCause(err error) *UserError {
	return &UserError{
		Code:    e.Code,
		Message: e.Message,
		Cause:   err,
	}
}