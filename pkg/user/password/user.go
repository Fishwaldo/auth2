package password

import (
	"context"
	"time"
)

// UserInfo contains user-related information for password management
type UserInfo struct {
	ID                    string
	PasswordLastChangedAt time.Time
	PasswordExpiresAt     time.Time
}

// IsPasswordExpired checks if a user's password has expired
func (u *Utils) IsPasswordExpired(ctx context.Context, user *UserInfo) bool {
	// If no policy is set or no expiry is configured, passwords never expire
	if u.policy == nil || u.policy.PasswordExpiry <= 0 {
		return false
	}
	
	// If password was never set, it's not expired
	if user.PasswordLastChangedAt.IsZero() {
		return false
	}
	
	// Calculate expiry date
	expiryDate := user.PasswordLastChangedAt.AddDate(0, 0, u.policy.PasswordExpiry)
	
	// Check if current time is after expiry date
	return GetCurrentTime().After(expiryDate)
}