# WebAuthn/FIDO2 Authentication Provider

This package implements WebAuthn/FIDO2 authentication for the Auth2 library, supporting both passwordless authentication and multi-factor authentication (MFA).

## Features

- **Dual-mode support**: Can function as both primary authentication (passwordless) and MFA
- **Full WebAuthn compliance**: Uses the official go-webauthn library
- **Flexible credential storage**: Uses the StateStore interface for persistence
- **Security features**:
  - Challenge validation with expiration
  - Counter validation to detect cloned authenticators
  - Configurable attestation requirements
  - User verification options

## Configuration

```go
config := &webauthn.Config{
    // Relying Party settings
    RPDisplayName: "My Application",
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com", "https://www.example.com"},
    
    // Security preferences
    AttestationPreference:   webauthn.AttestationNone,
    UserVerification:       webauthn.UserVerificationPreferred,
    ResidentKeyRequirement: webauthn.ResidentKeyPreferred,
    
    // Timeouts
    Timeout:          60 * time.Second,
    ChallengeTimeout: 5 * time.Minute,
    
    // Required: StateStore for persistence
    StateStore: stateStore,
}
```

## Usage

### As Primary Authentication (Passwordless)

```go
// Create provider
provider, err := webauthn.New(config)

// Registration flow
// 1. Begin registration
options, err := provider.BeginRegistration(ctx, userID, username, displayName)

// 2. Send options to client, receive response
// 3. Complete registration
err = provider.CompleteRegistration(ctx, userID, challengeID, response)

// Authentication flow
// 1. Begin authentication
options, err := provider.BeginAuthentication(ctx, userID)

// 2. Send options to client, receive response
// 3. Authenticate
result, err := provider.Authenticate(authCtx, credentials)
```

### As MFA Provider

```go
// Setup MFA
setupData, err := provider.Setup(ctx, userID)

// Verify MFA
verified, err := provider.Verify(ctx, userID, code)
```

## Data Storage

The provider uses the StateStore interface to persist:

- **Challenges**: Temporary challenges with expiration
- **Credentials**: User's WebAuthn credentials (public keys, counters, etc.)

Data is stored in these namespaces:
- `webauthn_challenges`: Active challenges
- `webauthn_credentials`: User credentials

## Security Considerations

1. **Origin Validation**: Always configure correct origins in `RPOrigins`
2. **RPID**: Must match the domain where authentication occurs
3. **User Verification**: Configure based on security requirements
4. **Attestation**: Set attestation preference based on trust requirements
5. **Challenge Timeout**: Balance security with user experience

## Client Integration

This provider requires client-side JavaScript to interact with the WebAuthn API:

```javascript
// Registration
const credential = await navigator.credentials.create({
    publicKey: registrationOptions
});

// Authentication
const assertion = await navigator.credentials.get({
    publicKey: authenticationOptions
});
```

## Testing

The package includes comprehensive unit tests. To run:

```bash
go test ./pkg/auth/providers/webauthn/...
```

## Dependencies

- `github.com/go-webauthn/webauthn`: WebAuthn protocol implementation
- `github.com/Fishwaldo/auth2/pkg/plugin/metadata`: StateStore interface

## License

Part of the Auth2 library.