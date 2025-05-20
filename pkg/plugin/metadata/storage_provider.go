package metadata

import (
	"context"
)

// StorageProvider defines the interface for storage providers
type StorageProvider interface {
	Provider
	
	// GetStateStore returns the state store for this storage provider
	GetStateStore() StateStore
	
	// GetUserStore returns the user store for this storage provider
	GetUserStore() UserStore
	
	// GetSessionStore returns the session store for this storage provider
	GetSessionStore() SessionStore
	
	// GetRBACStore returns the RBAC store for this storage provider
	GetRBACStore() RBACStore
	
	// Transaction executes the given function within a transaction
	// If the function returns an error, the transaction is rolled back
	// Otherwise, the transaction is committed
	Transaction(ctx context.Context, fn func(ctx context.Context) error) error
}

// StateStore defines the interface for plugin state storage
type StateStore interface {
	// StoreState stores plugin state for a specific entity
	StoreState(ctx context.Context, namespace string, entityID string, key string, value interface{}) error
	
	// GetState retrieves plugin state for a specific entity
	GetState(ctx context.Context, namespace string, entityID string, key string, valuePtr interface{}) error
	
	// DeleteState removes plugin state
	DeleteState(ctx context.Context, namespace string, entityID string, key string) error
	
	// ListStateKeys lists all state keys for a specific entity and namespace
	ListStateKeys(ctx context.Context, namespace string, entityID string) ([]string, error)
}

// User represents a user in the system
type User struct {
	// ID is the unique identifier for the user
	ID string
	
	// Username is the username for the user
	Username string
	
	// Email is the email address for the user
	Email string
	
	// PasswordHash is the hashed password for the user
	PasswordHash string
	
	// Enabled indicates if the user account is enabled
	Enabled bool
	
	// Locked indicates if the user account is locked
	Locked bool
	
	// EmailVerified indicates if the user's email has been verified
	EmailVerified bool
	
	// MFAEnabled indicates if MFA is enabled for the user
	MFAEnabled bool
	
	// MFAProviders is a list of MFA providers enabled for the user
	MFAProviders []string
	
	// Metadata contains additional user metadata
	Metadata map[string]interface{}
	
	// CreatedAt is the time the user was created
	CreatedAt int64
	
	// UpdatedAt is the time the user was last updated
	UpdatedAt int64
	
	// LastLoginAt is the time the user last logged in
	LastLoginAt int64
}

// UserStore defines the interface for user storage
type UserStore interface {
	// CreateUser creates a new user
	CreateUser(ctx context.Context, user User) (string, error)
	
	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, userID string) (User, error)
	
	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (User, error)
	
	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (User, error)
	
	// UpdateUser updates an existing user
	UpdateUser(ctx context.Context, user User) error
	
	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, userID string) error
	
	// ListUsers lists all users with optional filtering
	ListUsers(ctx context.Context, filter map[string]interface{}, offset, limit int) ([]User, error)
	
	// CountUsers counts users with optional filtering
	CountUsers(ctx context.Context, filter map[string]interface{}) (int, error)
}

// Session represents a user session
type Session struct {
	// ID is the unique identifier for the session
	ID string
	
	// UserID is the ID of the user who owns the session
	UserID string
	
	// Token is the session token
	Token string
	
	// ExpiresAt is the expiration time for the session
	ExpiresAt int64
	
	// Data contains session data
	Data map[string]interface{}
	
	// CreatedAt is the time the session was created
	CreatedAt int64
	
	// UpdatedAt is the time the session was last updated
	UpdatedAt int64
	
	// LastActivityAt is the time of the last activity in the session
	LastActivityAt int64
	
	// IP is the IP address associated with the session
	IP string
	
	// UserAgent is the user agent associated with the session
	UserAgent string
}

// SessionStore defines the interface for session storage
type SessionStore interface {
	// CreateSession creates a new session
	CreateSession(ctx context.Context, session Session) (string, error)
	
	// GetSession retrieves a session by ID
	GetSession(ctx context.Context, sessionID string) (Session, error)
	
	// GetSessionByToken retrieves a session by token
	GetSessionByToken(ctx context.Context, token string) (Session, error)
	
	// UpdateSession updates an existing session
	UpdateSession(ctx context.Context, session Session) error
	
	// DeleteSession deletes a session
	DeleteSession(ctx context.Context, sessionID string) error
	
	// DeleteSessionsByUserID deletes all sessions for a user
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	
	// ListSessionsByUserID lists all sessions for a user
	ListSessionsByUserID(ctx context.Context, userID string) ([]Session, error)
	
	// DeleteExpiredSessions deletes all expired sessions
	DeleteExpiredSessions(ctx context.Context) (int, error)
}

// Permission represents a permission in the RBAC system
type Permission struct {
	// ID is the unique identifier for the permission
	ID string
	
	// Name is the name of the permission
	Name string
	
	// Description is a description of the permission
	Description string
	
	// CreatedAt is the time the permission was created
	CreatedAt int64
	
	// UpdatedAt is the time the permission was last updated
	UpdatedAt int64
}

// Role represents a role in the RBAC system
type Role struct {
	// ID is the unique identifier for the role
	ID string
	
	// Name is the name of the role
	Name string
	
	// Description is a description of the role
	Description string
	
	// Permissions is a list of permission IDs assigned to the role
	Permissions []string
	
	// CreatedAt is the time the role was created
	CreatedAt int64
	
	// UpdatedAt is the time the role was last updated
	UpdatedAt int64
}

// Group represents a group in the RBAC system
type Group struct {
	// ID is the unique identifier for the group
	ID string
	
	// Name is the name of the group
	Name string
	
	// Description is a description of the group
	Description string
	
	// Roles is a list of role IDs assigned to the group
	Roles []string
	
	// CreatedAt is the time the group was created
	CreatedAt int64
	
	// UpdatedAt is the time the group was last updated
	UpdatedAt int64
}

// RBACStore defines the interface for RBAC storage
type RBACStore interface {
	// Permission management
	CreatePermission(ctx context.Context, permission Permission) (string, error)
	GetPermission(ctx context.Context, permissionID string) (Permission, error)
	GetPermissionByName(ctx context.Context, name string) (Permission, error)
	UpdatePermission(ctx context.Context, permission Permission) error
	DeletePermission(ctx context.Context, permissionID string) error
	ListPermissions(ctx context.Context) ([]Permission, error)
	
	// Role management
	CreateRole(ctx context.Context, role Role) (string, error)
	GetRole(ctx context.Context, roleID string) (Role, error)
	GetRoleByName(ctx context.Context, name string) (Role, error)
	UpdateRole(ctx context.Context, role Role) error
	DeleteRole(ctx context.Context, roleID string) error
	ListRoles(ctx context.Context) ([]Role, error)
	
	// Role-Permission management
	AddPermissionToRole(ctx context.Context, roleID, permissionID string) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID string) error
	ListRolePermissions(ctx context.Context, roleID string) ([]Permission, error)
	
	// Group management
	CreateGroup(ctx context.Context, group Group) (string, error)
	GetGroup(ctx context.Context, groupID string) (Group, error)
	GetGroupByName(ctx context.Context, name string) (Group, error)
	UpdateGroup(ctx context.Context, group Group) error
	DeleteGroup(ctx context.Context, groupID string) error
	ListGroups(ctx context.Context) ([]Group, error)
	
	// Group-Role management
	AddRoleToGroup(ctx context.Context, groupID, roleID string) error
	RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) error
	ListGroupRoles(ctx context.Context, groupID string) ([]Role, error)
	
	// User-Role management
	AssignRoleToUser(ctx context.Context, userID, roleID string) error
	RevokeRoleFromUser(ctx context.Context, userID, roleID string) error
	ListUserRoles(ctx context.Context, userID string) ([]Role, error)
	
	// User-Group management
	AddUserToGroup(ctx context.Context, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID string) error
	ListUserGroups(ctx context.Context, userID string) ([]Group, error)
	ListGroupUsers(ctx context.Context, groupID string) ([]string, error)
	
	// Permission checking
	HasPermission(ctx context.Context, userID, permissionID string) (bool, error)
	HasRole(ctx context.Context, userID, roleID string) (bool, error)
	IsInGroup(ctx context.Context, userID, groupID string) (bool, error)
}

// BaseStorageProvider provides a base implementation of the StorageProvider interface
type BaseStorageProvider struct {
	*BaseProvider
	stateStore   StateStore
	userStore    UserStore
	sessionStore SessionStore
	rbacStore    RBACStore
}

// NewBaseStorageProvider creates a new BaseStorageProvider
func NewBaseStorageProvider(
	metadata ProviderMetadata,
	stateStore StateStore,
	userStore UserStore,
	sessionStore SessionStore,
	rbacStore RBACStore,
) *BaseStorageProvider {
	return &BaseStorageProvider{
		BaseProvider: NewBaseProvider(metadata),
		stateStore:   stateStore,
		userStore:    userStore,
		sessionStore: sessionStore,
		rbacStore:    rbacStore,
	}
}

// GetStateStore returns the state store for this storage provider
func (p *BaseStorageProvider) GetStateStore() StateStore {
	return p.stateStore
}

// GetUserStore returns the user store for this storage provider
func (p *BaseStorageProvider) GetUserStore() UserStore {
	return p.userStore
}

// GetSessionStore returns the session store for this storage provider
func (p *BaseStorageProvider) GetSessionStore() SessionStore {
	return p.sessionStore
}

// GetRBACStore returns the RBAC store for this storage provider
func (p *BaseStorageProvider) GetRBACStore() RBACStore {
	return p.rbacStore
}

// Transaction provides a default implementation that executes the function without a transaction
func (p *BaseStorageProvider) Transaction(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}