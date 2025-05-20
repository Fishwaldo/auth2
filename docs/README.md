# Auth2 Documentation

Welcome to the Auth2 documentation. This guide will help you understand how to use and extend the Auth2 authentication library.

## Table of Contents

1. [Getting Started](./getting-started.md)
   - Installation
   - Basic Setup
   - Configuration Options

2. [Core Concepts](./core-concepts.md)
   - Architecture Overview
   - Authentication Flow
   - Session Management

3. [Authentication Methods](./auth-methods/README.md)
   - [Username/Password](./auth-methods/basic.md)
   - [OAuth2](./auth-methods/oauth2.md)
   - [SAML](./auth-methods/saml.md)

4. [Multi-Factor Authentication](./mfa/README.md)
   - [TOTP](./mfa/totp.md)
   - [WebAuthn/FIDO2](./mfa/webauthn.md)
   - [Email OTP](./mfa/email-otp.md)
   - [Backup Codes](./mfa/backup-codes.md)

5. [Storage Adapters](./storage/README.md)
   - [Memory](./storage/memory.md)
   - [SQL](./storage/sql.md)
   - [GORM](./storage/gorm.md)
   - [Ent ORM](./storage/ent.md)

6. [HTTP Framework Integration](./http/README.md)
   - [Standard Library](./http/std.md)
   - [Chi](./http/chi.md)
   - [Echo](./http/echo.md)
   - [Fiber](./http/fiber.md)
   - [Gin](./http/gin.md)
   - [More Frameworks](./http/other.md)

7. [Role-Based Access Control](./rbac/README.md)
   - [Roles and Permissions](./rbac/roles.md)
   - [User-Role Assignment](./rbac/assignment.md)
   - [Permission Checking](./rbac/checking.md)

8. [Security Features](./security/README.md)
   - [Brute Force Protection](./security/brute-force.md)
   - [Rate Limiting](./security/rate-limiting.md)
   - [CSRF Protection](./security/csrf.md)
   - [Account Recovery](./security/account-recovery.md)

9. [Examples](./examples/README.md)
   - [Basic Authentication](./examples/basic-auth.md)
   - [OAuth Integration](./examples/oauth.md)
   - [Multi-Factor Authentication](./examples/mfa.md)
   - [Custom Authentication Provider](./examples/custom-provider.md)

10. [API Reference](./api/README.md)
    - [Public API](./api/public.md)
    - [Interfaces](./api/interfaces.md)
    - [Error Types](./api/errors.md)

11. [Advanced Usage](./advanced/README.md)
    - [Custom Authentication Providers](./advanced/custom-auth.md)
    - [Custom Storage Adapters](./advanced/custom-storage.md)
    - [Extending the Core](./advanced/extending.md)

12. [Contributing](./contributing.md)
    - Development Guidelines
    - Testing
    - Pull Request Process