# Authentication Library Implementation Guide

This document provides specifications for implementing a comprehensive, modular authentication library in Go. The implementation must be complete and production-ready.

## Core Requirements

Your implementation MUST include ALL of the following:

1. **Pluggable Architecture**
   - Create a modular system with clear interfaces for all components
   - Support pluggable primary authentication methods
   - Support pluggable MFA (multi-factor authentication) methods
   - Allow for custom implementation of any component

2. **Authentication Methods**
   - **Primary Authentication**:
     - Username/Password with secure password hashing
     - OAuth2 support (Google, GitHub, Microsoft, Facebook at minimum)
     - SAML authentication
   - **MFA Methods**:
     - TOTP (Time-based One-Time Password)
     - FIDO2/WebAuthn (passkeys)
     - Email OTP (One-Time Password)
     - Backup codes

3. **Session Management**
   - Implement Cookie-based sessions
   - JWT token authentication
   - Bearer token authentication
   - Secure session revocation and refresh mechanisms

4. **Storage Adapters**
   - Standard library SQL interface
   - GORM integration
   - Ent ORM integration
   - In-memory implementation for testing

5. **HTTP Framework Integration**
   - Create adapters for ALL of these frameworks:
     - Standard library (net/http)
     - Chi router
     - Echo framework
     - Fiber
     - Gin
     - Gorilla mux
     - httprouter
     - Huma
     - FastHTTP

6. **Security Features**
   - Brute force protection with configurable limits
   - Rate limiting
   - CSRF protection
   - Secure cookie handling
   - User account locking/unlocking
   - Password reset functionality
   - Account recovery options

7. **RBAC (Role-Based Access Control)**
   - Permission management
   - Role assignment
   - Group-based permissions
   - Resource access control

8. **Developer API**
   - Clean, intuitive API
   - Consistent error handling
   - Comprehensive documentation
   - Minimal boilerplate for common use cases

9. **Testing**
   - Black box unit tests for ALL components
   - Mock implementations for testing
   - Test utilities to simplify testing
   - Test coverage > 80%
   - Deterministic tests (no reliance on time, randomness)
   - Table-driven tests for comprehensive scenarios

## Architecture Guidelines

1. **Clean Architecture**
   - Separate domain logic from infrastructure
   - Use interfaces (ports) for all dependencies
   - Implement adapters for specific technologies

2. **Hexagonal Design**
   - Core domain should be independent of external systems
   - Use dependency injection throughout
   - Clear boundaries between application layers

3. **Error Handling**
   - Custom error types for specific scenarios
   - Proper error wrapping with context
   - Exported errors for application testing

4. **Concurrency**
   - Use goroutines and channels appropriately
   - Context propagation for cancellation
   - Thread-safe implementations

5. **Logging**
   - Structured logging with log/slog
   - Appropriate log levels
   - Contextual information in logs
   - Proper redaction of sensitive data

## Implementation Details

1. **User Management**
   - Registration flow
   - Account verification
   - Profile management
   - Account status tracking

2. **Authentication Flow**
   - Registration
   - Login
   - Logout
   - MFA enrollment and verification
   - Account recovery
   - Password reset

3. **Session Handling**
   - Session creation
   - Session validation
   - Session expiration and renewal
   - Session revocation

4. **OAuth Integration**
   - OAuth2 provider configuration
   - OAuth2 callback handling
   - User profile mapping
   - Token management

5. **RBAC Implementation**
   - Permission definition and assignment
   - Role creation and management
   - User-role relationships
   - Permission checking middleware

6. **Security Measures**
   - Rate limiting implementation
   - Brute force detection and prevention
   - Security event logging
   - Audit trail

## Package Structure

1. Consult @docs/DESIGN.md

## CRITICAL IMPLEMENTATION REQUIREMENTS

1. The implementation MUST be complete and production-ready
2. Every feature MUST be fully implemented, not stubbed
3. All security features MUST be properly implemented (not placeholder)
4. Every component MUST have thorough unit tests
5. All interfaces MUST be well-defined with proper documentation
6. Error handling MUST be comprehensive
7. The library MUST be usable in a production environment
8. EVERY HTTP framework integration MUST be fully implemented
9. ALL storage adapters MUST be properly implemented
10. Documentation MUST be complete with examples

Create this authentication library with the same comprehensive features and flexibility as the original codebase, ensuring it meets all the requirements outlined above.

## Additional Documents
1. Detailed Project Design @docs/DESIGN.md
2. Project Plan @docs/PROJECT_PLAN.md
