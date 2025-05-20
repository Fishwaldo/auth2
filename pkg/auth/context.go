package auth

import (
	"context"
	"time"
	
	"github.com/Fishwaldo/auth2/pkg/user"
)

// contextKey is a type for context keys
type contextKey string

const (
	// userIDKey is the context key for user ID
	userIDKey contextKey = "auth2.user_id"
	
	// userKey is the context key for user object
	userKey contextKey = "auth2.user"
	
	// authTypeKey is the context key for authentication type
	authTypeKey contextKey = "auth2.auth_type"
	
	// sessionIDKey is the context key for session ID
	sessionIDKey contextKey = "auth2.session_id"
	
	// authenticatedAtKey is the context key for authentication time
	authenticatedAtKey contextKey = "auth2.authenticated_at"
	
	// expiresAtKey is the context key for session expiration time
	expiresAtKey contextKey = "auth2.expires_at"
	
	// permissionsKey is the context key for user permissions
	permissionsKey contextKey = "auth2.permissions"
	
	// rolesKey is the context key for user roles
	rolesKey contextKey = "auth2.roles"
	
	// groupsKey is the context key for user groups
	groupsKey contextKey = "auth2.groups"
	
	// scopesKey is the context key for authorized scopes
	scopesKey contextKey = "auth2.scopes"
	
	// mfaCompletedKey is the context key for MFA completion status
	mfaCompletedKey contextKey = "auth2.mfa_completed"
	
	// mfaMethodsKey is the context key for MFA methods used
	mfaMethodsKey contextKey = "auth2.mfa_methods"
	
	// authSourceKey is the context key for authentication source
	authSourceKey contextKey = "auth2.auth_source"
	
	// deviceIDKey is the context key for device ID
	deviceIDKey contextKey = "auth2.device_id"
	
	// ipAddressKey is the context key for IP address
	ipAddressKey contextKey = "auth2.ip_address"
	
	// userAgentKey is the context key for user agent
	userAgentKey contextKey = "auth2.user_agent"
)

// AuthType represents the type of authentication
type AuthType string

const (
	// AuthTypeBasic represents basic (username/password) authentication
	AuthTypeBasic AuthType = "basic"
	
	// AuthTypeOAuth represents OAuth authentication
	AuthTypeOAuth AuthType = "oauth"
	
	// AuthTypeSAML represents SAML authentication
	AuthTypeSAML AuthType = "saml"
	
	// AuthTypeWebAuthn represents WebAuthn authentication
	AuthTypeWebAuthn AuthType = "webauthn"
	
	// AuthTypeJWT represents JWT authentication
	AuthTypeJWT AuthType = "jwt"
	
	// AuthTypeSession represents session-based authentication
	AuthTypeSession AuthType = "session"
	
	// AuthTypeToken represents token-based authentication
	AuthTypeToken AuthType = "token"
)

// AuthContext represents the authentication context
type AuthContext struct {
	// Context is the base context
	ctx context.Context
}

// NewContext creates a new authentication context
func NewContext(ctx context.Context) *AuthContext {
	return &AuthContext{ctx: ctx}
}

// Context returns the base context
func (c *AuthContext) Context() context.Context {
	return c.ctx
}

// WithUserID adds a user ID to the context
func (c *AuthContext) WithUserID(userID string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, userIDKey, userID)
	return c
}

// UserID returns the user ID from the context
func (c *AuthContext) UserID() string {
	if val, ok := c.ctx.Value(userIDKey).(string); ok {
		return val
	}
	return ""
}

// WithUser adds a user to the context
func (c *AuthContext) WithUser(user *user.User) *AuthContext {
	c.ctx = context.WithValue(c.ctx, userKey, user)
	if user != nil {
		c.ctx = context.WithValue(c.ctx, userIDKey, user.ID)
	}
	return c
}

// User returns the user from the context
func (c *AuthContext) User() *user.User {
	if val, ok := c.ctx.Value(userKey).(*user.User); ok {
		return val
	}
	return nil
}

// WithAuthType adds an authentication type to the context
func (c *AuthContext) WithAuthType(authType AuthType) *AuthContext {
	c.ctx = context.WithValue(c.ctx, authTypeKey, authType)
	return c
}

// AuthType returns the authentication type from the context
func (c *AuthContext) AuthType() AuthType {
	if val, ok := c.ctx.Value(authTypeKey).(AuthType); ok {
		return val
	}
	return ""
}

// WithSessionID adds a session ID to the context
func (c *AuthContext) WithSessionID(sessionID string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, sessionIDKey, sessionID)
	return c
}

// SessionID returns the session ID from the context
func (c *AuthContext) SessionID() string {
	if val, ok := c.ctx.Value(sessionIDKey).(string); ok {
		return val
	}
	return ""
}

// WithAuthenticatedAt adds an authentication time to the context
func (c *AuthContext) WithAuthenticatedAt(authenticatedAt time.Time) *AuthContext {
	c.ctx = context.WithValue(c.ctx, authenticatedAtKey, authenticatedAt)
	return c
}

// AuthenticatedAt returns the authentication time from the context
func (c *AuthContext) AuthenticatedAt() time.Time {
	if val, ok := c.ctx.Value(authenticatedAtKey).(time.Time); ok {
		return val
	}
	return time.Time{}
}

// WithExpiresAt adds an expiration time to the context
func (c *AuthContext) WithExpiresAt(expiresAt time.Time) *AuthContext {
	c.ctx = context.WithValue(c.ctx, expiresAtKey, expiresAt)
	return c
}

// ExpiresAt returns the expiration time from the context
func (c *AuthContext) ExpiresAt() time.Time {
	if val, ok := c.ctx.Value(expiresAtKey).(time.Time); ok {
		return val
	}
	return time.Time{}
}

// WithPermissions adds permissions to the context
func (c *AuthContext) WithPermissions(permissions []string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, permissionsKey, permissions)
	return c
}

// Permissions returns the permissions from the context
func (c *AuthContext) Permissions() []string {
	if val, ok := c.ctx.Value(permissionsKey).([]string); ok {
		return val
	}
	return nil
}

// HasPermission checks if a specific permission is included in the context
func (c *AuthContext) HasPermission(permission string) bool {
	permissions := c.Permissions()
	if permissions == nil {
		return false
	}
	
	for _, p := range permissions {
		if p == permission {
			return true
		}
	}
	
	return false
}

// WithRoles adds roles to the context
func (c *AuthContext) WithRoles(roles []string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, rolesKey, roles)
	return c
}

// Roles returns the roles from the context
func (c *AuthContext) Roles() []string {
	if val, ok := c.ctx.Value(rolesKey).([]string); ok {
		return val
	}
	return nil
}

// HasRole checks if a specific role is included in the context
func (c *AuthContext) HasRole(role string) bool {
	roles := c.Roles()
	if roles == nil {
		return false
	}
	
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	
	return false
}

// WithGroups adds groups to the context
func (c *AuthContext) WithGroups(groups []string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, groupsKey, groups)
	return c
}

// Groups returns the groups from the context
func (c *AuthContext) Groups() []string {
	if val, ok := c.ctx.Value(groupsKey).([]string); ok {
		return val
	}
	return nil
}

// InGroup checks if a specific group is included in the context
func (c *AuthContext) InGroup(group string) bool {
	groups := c.Groups()
	if groups == nil {
		return false
	}
	
	for _, g := range groups {
		if g == group {
			return true
		}
	}
	
	return false
}

// WithScopes adds authorized scopes to the context
func (c *AuthContext) WithScopes(scopes []string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, scopesKey, scopes)
	return c
}

// Scopes returns the authorized scopes from the context
func (c *AuthContext) Scopes() []string {
	if val, ok := c.ctx.Value(scopesKey).([]string); ok {
		return val
	}
	return nil
}

// HasScope checks if a specific scope is included in the context
func (c *AuthContext) HasScope(scope string) bool {
	scopes := c.Scopes()
	if scopes == nil {
		return false
	}
	
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	
	return false
}

// WithMFACompleted adds MFA completion status to the context
func (c *AuthContext) WithMFACompleted(completed bool) *AuthContext {
	c.ctx = context.WithValue(c.ctx, mfaCompletedKey, completed)
	return c
}

// MFACompleted returns the MFA completion status from the context
func (c *AuthContext) MFACompleted() bool {
	if val, ok := c.ctx.Value(mfaCompletedKey).(bool); ok {
		return val
	}
	return false
}

// WithMFAMethods adds MFA methods to the context
func (c *AuthContext) WithMFAMethods(methods []string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, mfaMethodsKey, methods)
	return c
}

// MFAMethods returns the MFA methods from the context
func (c *AuthContext) MFAMethods() []string {
	if val, ok := c.ctx.Value(mfaMethodsKey).([]string); ok {
		return val
	}
	return nil
}

// WithAuthSource adds an authentication source to the context
func (c *AuthContext) WithAuthSource(source string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, authSourceKey, source)
	return c
}

// AuthSource returns the authentication source from the context
func (c *AuthContext) AuthSource() string {
	if val, ok := c.ctx.Value(authSourceKey).(string); ok {
		return val
	}
	return ""
}

// WithDeviceID adds a device ID to the context
func (c *AuthContext) WithDeviceID(deviceID string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, deviceIDKey, deviceID)
	return c
}

// DeviceID returns the device ID from the context
func (c *AuthContext) DeviceID() string {
	if val, ok := c.ctx.Value(deviceIDKey).(string); ok {
		return val
	}
	return ""
}

// WithIPAddress adds an IP address to the context
func (c *AuthContext) WithIPAddress(ipAddress string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, ipAddressKey, ipAddress)
	return c
}

// IPAddress returns the IP address from the context
func (c *AuthContext) IPAddress() string {
	if val, ok := c.ctx.Value(ipAddressKey).(string); ok {
		return val
	}
	return ""
}

// WithUserAgent adds a user agent to the context
func (c *AuthContext) WithUserAgent(userAgent string) *AuthContext {
	c.ctx = context.WithValue(c.ctx, userAgentKey, userAgent)
	return c
}

// UserAgent returns the user agent from the context
func (c *AuthContext) UserAgent() string {
	if val, ok := c.ctx.Value(userAgentKey).(string); ok {
		return val
	}
	return ""
}

// FromContext creates an AuthContext from a standard context
func FromContext(ctx context.Context) *AuthContext {
	return &AuthContext{ctx: ctx}
}

// IsAuthenticated checks if the context has a user ID
func (c *AuthContext) IsAuthenticated() bool {
	return c.UserID() != ""
}