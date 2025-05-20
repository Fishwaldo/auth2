package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/auth"
	"github.com/Fishwaldo/auth2/pkg/user"
)

// TestAuthContext tests the auth context functionality
func TestAuthContext(t *testing.T) {
	// Create a standard context
	ctx := context.Background()
	
	// Create an auth context
	authCtx := auth.NewContext(ctx)
	
	// Verify the auth context returns the original context
	if authCtx.Context() != ctx {
		t.Errorf("Context() = %v, want %v", authCtx.Context(), ctx)
	}
	
	// Test user ID
	t.Run("UserID", func(t *testing.T) {
		// Initially, user ID should be empty
		if userID := authCtx.UserID(); userID != "" {
			t.Errorf("UserID() = %v, want \"\"", userID)
		}
		
		// Add a user ID
		authCtx = authCtx.WithUserID("user123")
		
		// Verify user ID was set
		if userID := authCtx.UserID(); userID != "user123" {
			t.Errorf("UserID() = %v, want \"user123\"", userID)
		}
	})
	
	// Test user
	t.Run("User", func(t *testing.T) {
		// Initially, user should be nil
		if u := authCtx.User(); u != nil {
			t.Errorf("User() = %v, want nil", u)
		}
		
		// Create a test user
		testUser := &user.User{
			ID:       "user123",
			Username: "testuser",
			Email:    "test@example.com",
		}
		
		// Add the user
		authCtx = authCtx.WithUser(testUser)
		
		// Verify user was set
		u := authCtx.User()
		if u == nil {
			t.Fatalf("User() = nil, want %v", testUser)
		}
		
		if u.ID != "user123" {
			t.Errorf("User().ID = %v, want \"user123\"", u.ID)
		}
		
		if u.Username != "testuser" {
			t.Errorf("User().Username = %v, want \"testuser\"", u.Username)
		}
		
		// Verify user ID was updated
		if userID := authCtx.UserID(); userID != "user123" {
			t.Errorf("UserID() = %v, want \"user123\"", userID)
		}
	})
	
	// Test auth type
	t.Run("AuthType", func(t *testing.T) {
		// Initially, auth type should be empty
		if authType := authCtx.AuthType(); authType != "" {
			t.Errorf("AuthType() = %v, want \"\"", authType)
		}
		
		// Add an auth type
		authCtx = authCtx.WithAuthType(auth.AuthTypeBasic)
		
		// Verify auth type was set
		if authType := authCtx.AuthType(); authType != auth.AuthTypeBasic {
			t.Errorf("AuthType() = %v, want %v", authType, auth.AuthTypeBasic)
		}
	})
	
	// Test session ID
	t.Run("SessionID", func(t *testing.T) {
		// Initially, session ID should be empty
		if sessionID := authCtx.SessionID(); sessionID != "" {
			t.Errorf("SessionID() = %v, want \"\"", sessionID)
		}
		
		// Add a session ID
		authCtx = authCtx.WithSessionID("session123")
		
		// Verify session ID was set
		if sessionID := authCtx.SessionID(); sessionID != "session123" {
			t.Errorf("SessionID() = %v, want \"session123\"", sessionID)
		}
	})
	
	// Test timestamps
	t.Run("Timestamps", func(t *testing.T) {
		// Initially, timestamps should be zero
		if !authCtx.AuthenticatedAt().IsZero() {
			t.Errorf("AuthenticatedAt() = %v, want zero time", authCtx.AuthenticatedAt())
		}
		
		if !authCtx.ExpiresAt().IsZero() {
			t.Errorf("ExpiresAt() = %v, want zero time", authCtx.ExpiresAt())
		}
		
		// Set timestamps
		now := time.Now()
		expiry := now.Add(24 * time.Hour)
		
		authCtx = authCtx.WithAuthenticatedAt(now).WithExpiresAt(expiry)
		
		// Verify timestamps were set
		if authTime := authCtx.AuthenticatedAt(); !authTime.Equal(now) {
			t.Errorf("AuthenticatedAt() = %v, want %v", authTime, now)
		}
		
		if expiryTime := authCtx.ExpiresAt(); !expiryTime.Equal(expiry) {
			t.Errorf("ExpiresAt() = %v, want %v", expiryTime, expiry)
		}
	})
	
	// Test permissions
	t.Run("Permissions", func(t *testing.T) {
		// Initially, permissions should be nil
		if perms := authCtx.Permissions(); perms != nil {
			t.Errorf("Permissions() = %v, want nil", perms)
		}
		
		// Add permissions
		permissions := []string{"read", "write", "delete"}
		authCtx = authCtx.WithPermissions(permissions)
		
		// Verify permissions were set
		perms := authCtx.Permissions()
		if len(perms) != len(permissions) {
			t.Fatalf("Permissions() length = %v, want %v", len(perms), len(permissions))
		}
		
		for i, p := range permissions {
			if perms[i] != p {
				t.Errorf("Permissions()[%d] = %v, want %v", i, perms[i], p)
			}
		}
		
		// Test has permission
		if !authCtx.HasPermission("read") {
			t.Errorf("HasPermission(\"read\") = false, want true")
		}
		
		if authCtx.HasPermission("admin") {
			t.Errorf("HasPermission(\"admin\") = true, want false")
		}
	})
	
	// Test roles
	t.Run("Roles", func(t *testing.T) {
		// Initially, roles should be nil
		if roles := authCtx.Roles(); roles != nil {
			t.Errorf("Roles() = %v, want nil", roles)
		}
		
		// Add roles
		roles := []string{"user", "editor"}
		authCtx = authCtx.WithRoles(roles)
		
		// Verify roles were set
		r := authCtx.Roles()
		if len(r) != len(roles) {
			t.Fatalf("Roles() length = %v, want %v", len(r), len(roles))
		}
		
		for i, role := range roles {
			if r[i] != role {
				t.Errorf("Roles()[%d] = %v, want %v", i, r[i], role)
			}
		}
		
		// Test has role
		if !authCtx.HasRole("user") {
			t.Errorf("HasRole(\"user\") = false, want true")
		}
		
		if authCtx.HasRole("admin") {
			t.Errorf("HasRole(\"admin\") = true, want false")
		}
	})
	
	// Test groups
	t.Run("Groups", func(t *testing.T) {
		// Initially, groups should be nil
		if groups := authCtx.Groups(); groups != nil {
			t.Errorf("Groups() = %v, want nil", groups)
		}
		
		// Add groups
		groups := []string{"marketing", "finance"}
		authCtx = authCtx.WithGroups(groups)
		
		// Verify groups were set
		g := authCtx.Groups()
		if len(g) != len(groups) {
			t.Fatalf("Groups() length = %v, want %v", len(g), len(groups))
		}
		
		for i, group := range groups {
			if g[i] != group {
				t.Errorf("Groups()[%d] = %v, want %v", i, g[i], group)
			}
		}
		
		// Test in group
		if !authCtx.InGroup("marketing") {
			t.Errorf("InGroup(\"marketing\") = false, want true")
		}
		
		if authCtx.InGroup("engineering") {
			t.Errorf("InGroup(\"engineering\") = true, want false")
		}
	})
	
	// Test scopes
	t.Run("Scopes", func(t *testing.T) {
		// Initially, scopes should be nil
		if scopes := authCtx.Scopes(); scopes != nil {
			t.Errorf("Scopes() = %v, want nil", scopes)
		}
		
		// Add scopes
		scopes := []string{"profile", "email", "api"}
		authCtx = authCtx.WithScopes(scopes)
		
		// Verify scopes were set
		s := authCtx.Scopes()
		if len(s) != len(scopes) {
			t.Fatalf("Scopes() length = %v, want %v", len(s), len(scopes))
		}
		
		for i, scope := range scopes {
			if s[i] != scope {
				t.Errorf("Scopes()[%d] = %v, want %v", i, s[i], scope)
			}
		}
		
		// Test has scope
		if !authCtx.HasScope("profile") {
			t.Errorf("HasScope(\"profile\") = false, want true")
		}
		
		if authCtx.HasScope("admin") {
			t.Errorf("HasScope(\"admin\") = true, want false")
		}
	})
	
	// Test MFA
	t.Run("MFA", func(t *testing.T) {
		// Initially, MFA completed should be false
		if authCtx.MFACompleted() {
			t.Errorf("MFACompleted() = true, want false")
		}
		
		// Set MFA completed
		authCtx = authCtx.WithMFACompleted(true)
		
		// Verify MFA completed was set
		if !authCtx.MFACompleted() {
			t.Errorf("MFACompleted() = false, want true")
		}
		
		// Add MFA methods
		methods := []string{"totp", "webauthn"}
		authCtx = authCtx.WithMFAMethods(methods)
		
		// Verify MFA methods were set
		m := authCtx.MFAMethods()
		if len(m) != len(methods) {
			t.Fatalf("MFAMethods() length = %v, want %v", len(m), len(methods))
		}
		
		for i, method := range methods {
			if m[i] != method {
				t.Errorf("MFAMethods()[%d] = %v, want %v", i, m[i], method)
			}
		}
	})
	
	// Test additional context information
	t.Run("AdditionalInfo", func(t *testing.T) {
		// Test auth source
		authCtx = authCtx.WithAuthSource("web")
		if authSource := authCtx.AuthSource(); authSource != "web" {
			t.Errorf("AuthSource() = %v, want \"web\"", authSource)
		}
		
		// Test device ID
		authCtx = authCtx.WithDeviceID("device123")
		if deviceID := authCtx.DeviceID(); deviceID != "device123" {
			t.Errorf("DeviceID() = %v, want \"device123\"", deviceID)
		}
		
		// Test IP address
		authCtx = authCtx.WithIPAddress("192.168.1.1")
		if ipAddress := authCtx.IPAddress(); ipAddress != "192.168.1.1" {
			t.Errorf("IPAddress() = %v, want \"192.168.1.1\"", ipAddress)
		}
		
		// Test user agent
		authCtx = authCtx.WithUserAgent("Mozilla/5.0")
		if userAgent := authCtx.UserAgent(); userAgent != "Mozilla/5.0" {
			t.Errorf("UserAgent() = %v, want \"Mozilla/5.0\"", userAgent)
		}
	})
	
	// Test IsAuthenticated
	t.Run("IsAuthenticated", func(t *testing.T) {
		// Create a new auth context without a user ID
		emptyCtx := auth.NewContext(context.Background())
		
		// Verify not authenticated
		if emptyCtx.IsAuthenticated() {
			t.Errorf("IsAuthenticated() = true, want false")
		}
		
		// Add a user ID
		emptyCtx = emptyCtx.WithUserID("user123")
		
		// Verify authenticated
		if !emptyCtx.IsAuthenticated() {
			t.Errorf("IsAuthenticated() = false, want true")
		}
	})
	
	// Test FromContext
	t.Run("FromContext", func(t *testing.T) {
		// Create a context with user ID
		authCtx := auth.NewContext(context.Background()).WithUserID("user123")
		userCtx := authCtx.Context()
		
		// Get auth context from the standard context
		fromCtx := auth.FromContext(userCtx)
		
		// Verify context was created
		if fromCtx == nil {
			t.Fatalf("FromContext() = nil, want non-nil")
		}
	})
}