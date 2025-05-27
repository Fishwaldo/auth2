# OAuth2 Authentication Provider

The OAuth2 provider implements OAuth2-based authentication for the Auth2 library. It provides a flexible framework for integrating with any OAuth2-compliant authentication provider.

## Features

- **Generic OAuth2 Implementation**: Works with any OAuth2-compliant provider
- **Pre-configured Providers**: Built-in support for Google, GitHub, Microsoft, and Facebook
- **Security Features**:
  - CSRF protection via state parameter
  - Secure token storage using StateStore interface
  - Automatic token refresh
  - Token expiration handling
- **Profile Mapping**: Customizable user profile mapping for different providers
- **Extensible Design**: Easy to add new OAuth2 providers

## Usage

### Quick Start with Pre-configured Providers

```go
import (
    "github.com/Fishwaldo/auth2/pkg/auth/providers/oauth2"
    "github.com/Fishwaldo/auth2/pkg/plugin/metadata"
)

// Create a state store (use your preferred implementation)
var stateStore metadata.StateStore = NewMemoryStateStore()

// Create Google OAuth2 provider
googleProvider, err := oauth2.QuickGoogle(
    "your-client-id",
    "your-client-secret",
    "http://localhost:8080/auth/google/callback",
    stateStore,
)

// Create GitHub OAuth2 provider
githubProvider, err := oauth2.QuickGitHub(
    "your-client-id",
    "your-client-secret",
    "http://localhost:8080/auth/github/callback",
    stateStore,
)
```

### Custom OAuth2 Provider

```go
// Configure a custom OAuth2 provider
config := &oauth2.Config{
    ClientID:     "your-client-id",
    ClientSecret: "your-client-secret",
    RedirectURL:  "http://localhost:8080/auth/callback",
    
    // OAuth2 endpoints
    AuthURL:     "https://provider.com/oauth/authorize",
    TokenURL:    "https://provider.com/oauth/token",
    UserInfoURL: "https://provider.com/api/user",
    
    // Provider details
    ProviderName: "MyProvider",
    ProviderID:   "myprovider",
    
    // Scopes to request
    Scopes: []string{"read:user", "user:email"},
    
    // Security settings
    UseStateParam: true,
    StateTTL:      10 * time.Minute,
    
    // Storage
    StateStore: stateStore,
    
    // Custom profile mapping (optional)
    ProfileMap: func(data map[string]interface{}) (*oauth2.UserInfo, error) {
        return &oauth2.UserInfo{
            ID:    data["id"].(string),
            Email: data["email"].(string),
            Name:  data["name"].(string),
        }, nil
    },
}

provider, err := oauth2.NewProvider(config)
```

### Using the Factory

```go
factory := oauth2.NewFactory(stateStore)

// Create provider from configuration
provider, err := factory.Create(map[string]interface{}{
    "client_id":     "your-client-id",
    "client_secret": "your-client-secret",
    "redirect_url":  "http://localhost:8080/auth/callback",
    "auth_url":      "https://provider.com/oauth/authorize",
    "token_url":     "https://provider.com/oauth/token",
    "user_info_url": "https://provider.com/api/user",
})

// Or create a pre-configured provider
googleProvider, err := factory.CreateWithProvider("google", map[string]interface{}{
    "client_id":     "your-google-client-id",
    "client_secret": "your-google-client-secret",
    "redirect_url":  "http://localhost:8080/auth/google/callback",
})
```

## OAuth2 Flow Implementation

### 1. Generate Authorization URL

```go
// Generate authorization URL with CSRF protection
authURL, err := provider.GetAuthorizationURL(ctx, map[string]string{
    "prompt": "consent",  // Optional extra parameters
})
if err != nil {
    return err
}

// Redirect user to authURL
http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
```

### 2. Handle OAuth2 Callback

```go
// In your callback handler
code := r.URL.Query().Get("code")
state := r.URL.Query().Get("state")

// Authenticate using the authorization code
credentials := &providers.OAuthCredentials{
    Code:  code,
    State: state,
}

userID, err := provider.Authenticate(ctx, credentials)
if err != nil {
    // Handle authentication error
    return err
}

// User is authenticated with ID: userID
```

### 3. Retrieve User Information

```go
// Get cached user profile
userInfo, err := provider.(*oauth2.Provider).GetUserInfo(ctx, userID)
if err != nil {
    return err
}

fmt.Printf("User: %s (%s)\n", userInfo.Name, userInfo.Email)
```

### 4. Token Management

```go
// Refresh token if needed (handled automatically during authentication)
err := provider.(*oauth2.Provider).RefreshUserToken(ctx, userID)
if err != nil {
    return err
}

// Revoke token
err = provider.(*oauth2.Provider).RevokeUserToken(ctx, userID)
```

## Configuration Options

### Core Configuration

- `ClientID` (required): OAuth2 client ID
- `ClientSecret` (required): OAuth2 client secret
- `RedirectURL` (required): Callback URL for OAuth2 flow
- `AuthURL` (required): Authorization endpoint URL
- `TokenURL` (required): Token endpoint URL
- `UserInfoURL`: User information endpoint URL
- `Scopes`: List of OAuth2 scopes to request

### Security Settings

- `UseStateParam`: Enable CSRF protection via state parameter (default: true)
- `StateTTL`: Time-to-live for state parameters (default: 10 minutes)
- `UsePKCE`: Enable PKCE for public clients (default: false)
- `TokenRefreshThreshold`: Refresh tokens this long before expiry (default: 5 minutes)

### Additional Parameters

- `AuthParams`: Extra parameters to send to authorization endpoint
- `TokenParams`: Extra parameters to send to token endpoint

## Pre-configured Providers

### Google
- Scopes: `openid`, `email`, `profile`
- Endpoints: Google OAuth2 v2 endpoints
- Profile mapping: Maps Google user data to standard format

### GitHub
- Scopes: `read:user`, `user:email`
- Endpoints: GitHub OAuth endpoints
- Profile mapping: Maps GitHub user data including avatar URL

### Microsoft
- Scopes: `openid`, `email`, `profile`
- Endpoints: Microsoft v2.0 endpoints
- Profile mapping: Maps Microsoft Graph user data

### Facebook
- Scopes: `email`, `public_profile`
- Endpoints: Facebook Graph API v12.0
- Profile mapping: Maps Facebook user data including profile picture

## Security Considerations

1. **State Parameter**: Always use state parameter for CSRF protection
2. **HTTPS**: Always use HTTPS for redirect URLs in production
3. **Token Storage**: Tokens are stored securely using the StateStore interface
4. **Client Secret**: Keep client secrets secure and never expose them in client-side code
5. **Scope Minimization**: Only request the scopes you need

## Error Handling

The provider returns specific errors for different failure scenarios:

- `ErrInvalidState`: State parameter validation failed
- `ErrStateExpired`: State parameter has expired
- `ErrNoAuthorizationCode`: No authorization code provided
- `ErrTokenExpired`: Access token has expired
- `ErrNoRefreshToken`: No refresh token available
- `ErrProviderError`: Error response from OAuth2 provider

## Extending the Framework

### Custom Profile Mapping

```go
func MyProviderProfileMapping(data map[string]interface{}) (*oauth2.UserInfo, error) {
    return &oauth2.UserInfo{
        ID:            getString(data, "user_id"),
        Email:         getString(data, "email_address"),
        EmailVerified: getBool(data, "email_confirmed"),
        Name:          getString(data, "full_name"),
        Picture:       getString(data, "avatar_url"),
        ProviderName:  "myprovider",
        Raw:           data,
    }, nil
}

config.ProfileMap = MyProviderProfileMapping
```

### Adding a New Provider

1. Add provider configuration to `CommonProviderConfigs`
2. Create a profile mapping function
3. Optionally add a Quick* helper function

```go
// In config.go
CommonProviderConfigs["myprovider"] = ProviderConfig{
    Name:        "myprovider",
    AuthURL:     "https://myprovider.com/oauth/authorize",
    TokenURL:    "https://myprovider.com/oauth/token",
    UserInfoURL: "https://myprovider.com/api/user",
    Scopes:      []string{"user", "email"},
    ProfileMap:  MyProviderProfileMapping,
}
```

## Testing

The package includes comprehensive tests for all components:

```bash
go test ./pkg/auth/providers/oauth2/...
```

For integration testing with real OAuth2 providers, set up test applications and use environment variables for credentials:

```bash
export TEST_GOOGLE_CLIENT_ID=your-test-client-id
export TEST_GOOGLE_CLIENT_SECRET=your-test-client-secret
go test -tags=integration ./pkg/auth/providers/oauth2/...
```