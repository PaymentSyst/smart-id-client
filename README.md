# Smart-ID Go Client

<div align="center">
  <img src="https://joosep.org/projects/smart-id-node-client/smart-id-node-client-banner.png" width="800" alt="Smart-ID Go Client Banner">
</div>

This library provides a modern, developer-friendly Go integration with the official **Smart-ID REST API v3** from **SK ID Solutions**, supporting strong, secure electronic identity authentication and digital signing for users in **Estonia**, **Latvia**, and **Lithuania**.

It is built entirely in **Go**, leverages well-established cryptographic libraries, and offers a clean, modular design following Go best practices, giving developers full control over request construction, security validation, and interaction flows.

The library abstracts much of the low-level complexity of working with Smart-ID, while strictly following the official specifications and providing the tools necessary to build both **cross-device** (e.g., browser to mobile) and **same-device** (e.g., mobile app) authentication flows.

This is a **complete Go port** of the TypeScript/Node.js Smart-ID client library, maintaining feature parity and API compatibility where possible.

## Table of Contents

- [Overview](#overview)
  - [Features](#features)
  - [Supported Authentication Flows](#main-authentication-flows)
- [Installation](#installation)
  - [Before You Start](#before-you-start)
- [Quick Start](#quick-start)
- [Authentication Request Builder](#authentication-request-builder)
- [Smart-ID Authentication Client](#smart-id-authentication-client)
- [Authentication Response Validator](#authentication-response-validator)
- [Callback URL Validator](#callback-url-validator)
- [Authentication Identity](#authentication-identity)
- [Examples](#examples)
- [Security Considerations](#security)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Overview

### Features

- ✅ **Complete Smart-ID v3 API Support** (June 2025)
- ✅ **Strongly Typed Request Builders** (Device Link & Notification Authentication)
- ✅ **Full Authentication Response Validation** with certificate trust checks
- ✅ **Smart-ID Scheme Identification** (End-Entity Certificate) enforcement
- ✅ **Signature Reconstruction and Verification** logic
- ✅ **Notification Flow Support** with VC Type: numeric4
- ✅ **Session Secret Digest and User Challenge Verifier** validation
- ✅ **Clean, Extensible, Minimal Dependencies** (standard library + crypto/x509)
- ✅ **Comprehensive Test Coverage**
- ✅ **Concurrent-Safe Design**
- ✅ **Production Ready**

### Main Authentication Flows

This library implements the main Smart-ID RP API flows, based on version 3 of the protocol:

#### Cross-device Use Cases
The RP session is on a separate device from the mobile phone where the Smart-ID app is installed.
- PC browser to access an RP website
- Tablet to access an RP application

#### Same-device Use Cases  
The RP frontend resides on the same mobile device as the Smart-ID app.
- Mobile app authentication
- Mobile browser detection for same-device flows

**Recommended**: Use `GetAuthenticateAnonymousDeviceLink` for same-device use cases unless the user's document-number has already been established. These endpoints provide superior user experience with device-links and callbacks offering the best security protections.

## Installation

```bash
go get github.com/PaymentSyst/smart-id-client
```

### Before You Start

This library is intended for developers who are already familiar with the Smart-ID system and its technical workflows.

If you are new to Smart-ID, please start by reading the official Smart-ID Demo Documentation:

👉 [https://sk-eid.github.io/smart-id-documentation/demo.html](https://sk-eid.github.io/smart-id-documentation/demo.html)

The official documentation explains the Smart-ID concept, registration process, and how to obtain demo credentials required for development and testing.

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    smartid "github.com/PaymentSyst/smart-id-client"
)

func main() {
    // Create client configuration
    config := &smartid.SmartIdClientConfig{
        RelyingPartyUUID: "00000000-0000-4000-8000-000000000000", // Demo UUID
        RelyingPartyName: "DEMO",
        HostURL:          "https://sid.demo.sk.ee/smart-id-rp",
        Debug:            true,
    }

    // Create Smart-ID client
    client := smartid.NewSmartIdAuthClient(config)
    client.SetSchemeName("smart-id-demo")

    // Build authentication request
    builder := smartid.NewAuthenticationRequestBuilder(
        config.RelyingPartyUUID,
        config.RelyingPartyName,
    )

    request := builder.
        WithInitialCallbackURL("https://example.com/callback").
        WithCertificateLevel(smartid.CertificateLevelQualified).
        WithInteractions(&smartid.DisplayTextAndPINInteraction{
            Type:          "displayTextAndPIN",
            DisplayText60: "Authenticate with Smart-ID",
        }).
        Build()

    // Start authentication session
    response, sessionStartTime, err := client.GetAuthenticateAnonymousDeviceLink(request)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Session started: %s\n", response.SessionID)

    // Create device link URL
    linkOptions := &smartid.DeviceLinkOptions{
        DeviceLinkType: smartid.DeviceLinkTypeWeb2App,
        Lang:           "eng",
    }

    deviceLinkURL := client.CreateDeviceLinkURL(response, request, sessionStartTime, linkOptions)
    fmt.Printf("Device Link: %s\n", deviceLinkURL)

    // Poll for result
    authResponse, err := client.PollForSessionResult(response.SessionID, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Authentication completed: %s\n", authResponse.Result.EndResult)
}
```

## Authentication Request Builder

The `AuthenticationRequestBuilder` provides a fluent interface for constructing Smart-ID authentication requests:

```go
builder := smartid.NewAuthenticationRequestBuilder("your-uuid", "Your RP Name")

// Device Link Authentication
request := builder.
    WithInitialCallbackURL("https://yourapp.com/callback").
    WithCertificateLevel(smartid.CertificateLevelQualified).
    WithHashAlgorithm(smartid.HashAlgorithmSHA512).
    WithInteractions(&smartid.DisplayTextAndPINInteraction{
        Type:          "displayTextAndPIN",
        DisplayText60: "Please authenticate",
    }).
    WithRequestProperties(&smartid.RequestProperties{
        ShareMdClientIPAddress: true,
    }).
    Build()

// Notification Authentication
notificationRequest := builder.
    WithVCType("numeric4").
    Build()
```

### Available Methods

| Method | Description |
|--------|-------------|
| `WithInitialCallbackURL(url)` | Sets callback URL for Web2App/App2App flows |
| `WithCertificateLevel(level)` | Sets certificate level (ADVANCED/QUALIFIED) |
| `WithHashAlgorithm(algorithm)` | Sets hash algorithm for signatures |
| `WithRequestProperties(props)` | Adds request properties like IP sharing |
| `WithCapabilities(caps)` | Adds custom capabilities |
| `WithInteractions(interaction)` | Sets user interaction type |
| `WithVCType(vcType)` | Switches to notification authentication |

## Smart-ID Authentication Client

The `SmartIdAuthClient` handles all communication with the Smart-ID API:

### Device Link Authentication

```go
// Anonymous device link (recommended for same-device)
response, startTime, err := client.GetAuthenticateAnonymousDeviceLink(request)

// By ETSI identifier
response, startTime, err := client.GetAuthenticateDeviceLinkByEtsi("PNOEE-30303039914", request)

// By document number
response, startTime, err := client.GetAuthenticateDeviceLinkByDocument("PNOEE-30303039914-123", request)
```

### Notification Authentication

```go
// By ETSI identifier
response, err := client.StartAuthenticateNotificationByEtsi("PNOEE-30303039914", notificationRequest)

// By document number  
response, err := client.StartAuthenticateNotificationByDocument("PNOEE-30303039914-123", notificationRequest)
```

### Session Management

```go
// Get session status
status, err := client.GetSessionStatus(sessionID)

// Poll for completion
options := &smartid.PollOptions{
    MaxWaitMs:      60000, // 60 seconds
    PollIntervalMs: 2000,  // 2 seconds
    MaxAttempts:    30,
}
result, err := client.PollForSessionResult(sessionID, options)
```

### Device Link URL Generation

```go
// Generate QR code URL
qrOptions := &smartid.DeviceLinkOptions{
    DeviceLinkType: smartid.DeviceLinkTypeQR,
    Lang:           "eng",
    ElapsedSeconds: 10,
}
qrURL := client.CreateDeviceLinkURL(response, request, startTime, qrOptions)

// Generate Web2App URL
web2appOptions := &smartid.DeviceLinkOptions{
    DeviceLinkType: smartid.DeviceLinkTypeWeb2App,
    Lang:           "eng",
}
web2appURL := client.CreateDeviceLinkURL(response, request, startTime, web2appOptions)
```

## Authentication Response Validator

Comprehensive validation of Smart-ID responses:

```go
// Create validator with CA certificate path
validator, err := smartid.NewAuthenticationResponseValidator("/path/to/ca/certs", true)
if err != nil {
    log.Fatal(err)
}

// Validate response
result := validator.
    WithSchemeName("smart-id-demo").
    WithInteractionTypeUsed("displayTextAndPIN").
    WithFlowType("Web2App").
    Validate(authResponse, request).
    GetResult()

if result.HasError() {
    fmt.Printf("Validation errors: %v\n", result.GetErrors())
} else {
    identity := result.GetIdentity()
    fmt.Printf("User: %s %s\n", identity.GetGivenName(), identity.GetSurName())
    
    // Verify signature
    signatureValid := validator.VerifySignature(authResponse, request)
    fmt.Printf("Signature valid: %t\n", signatureValid)
}
```

### Certificate Policy Validation

```go
// Check for specific certificate policies
allowedOIDs := []string{
    "1.3.6.1.4.1.4146.1.1",  // Test OID
    "1.3.6.1.4.1.4146.1.2",  // Production OID
}

pemCert := identity.GetPemCertificate()
hasValidPolicy := validator.CheckIfHasAllowedCertificatePolicies(pemCert, allowedOIDs)
```

## Callback URL Validator

For Web2App and App2App flows:

```go
callbackEntity := &smartid.CallbackValidationEntity{
    SessionSecretDigest:   "digest_from_frontend",
    UserChallengeVerifier: "verifier_from_request",
    SessionSecret:         "base64_session_secret",
    SchemeName:            "smart-id-demo",
    AuthenticationResponse: authResponse,
}

validator := smartid.NewCallbackURLValidator(callbackEntity)
result := validator.Validate().GetResult()

if result.HasError() {
    fmt.Printf("Callback validation failed: %v\n", result.GetErrors())
}
```

## Authentication Identity

Extract user information from certificates:

```go
identity := result.GetIdentity()

// Basic information
fmt.Printf("Given Name: %s\n", identity.GetGivenName())
fmt.Printf("Surname: %s\n", identity.GetSurName())
fmt.Printf("Identity Code: %s\n", identity.GetIdentityCode())
fmt.Printf("Country: %s\n", identity.GetCountry())
fmt.Printf("Document Number: %s\n", identity.GetDocumentNumber())

// Certificate information
fmt.Printf("Valid From: %s\n", identity.GetValidFrom().Format("2006-01-02"))
fmt.Printf("Valid To: %s\n", identity.GetValidTo().Format("2006-01-02"))
fmt.Printf("Date of Birth: %s\n", identity.GetDateOfBirth())

// Certificate access
pemCert := identity.GetPemCertificate()
rawCert := identity.GetRawCertificate()
parsedInfo := identity.GetParsedCertificate()
```

## Examples

### Complete Authentication Flow

```go
func authenticateUser() error {
    // Setup
    config := &smartid.SmartIdClientConfig{
        RelyingPartyUUID: "your-uuid",
        RelyingPartyName: "Your App",
        HostURL:          "https://sid.demo.sk.ee/smart-id-rp",
        Debug:            true,
    }
    
    client := smartid.NewSmartIdAuthClient(config)
    
    // Build request
    request := smartid.NewAuthenticationRequestBuilder(
        config.RelyingPartyUUID,
        config.RelyingPartyName,
    ).WithInteractions(&smartid.DisplayTextAndPINInteraction{
        Type:          "displayTextAndPIN",
        DisplayText60: "Login to MyApp",
    }).Build()
    
    // Start session
    response, startTime, err := client.GetAuthenticateAnonymousDeviceLink(request)
    if err != nil {
        return err
    }
    
    // Generate QR code URL
    qrURL := client.CreateDeviceLinkURL(response, request, startTime, &smartid.DeviceLinkOptions{
        DeviceLinkType: smartid.DeviceLinkTypeQR,
    })
    
    // Display QR code to user (implement QR generation)
    fmt.Printf("Scan QR code: %s\n", qrURL)
    
    // Poll for result
    authResponse, err := client.PollForSessionResult(response.SessionID, nil)
    if err != nil {
        return err
    }
    
    // Validate response
    validator, err := smartid.NewAuthenticationResponseValidator("./ca-certs", false)
    if err != nil {
        return err
    }
    
    result := validator.Validate(authResponse, request).GetResult()
    if result.HasError() {
        return fmt.Errorf("validation failed: %v", result.GetErrors())
    }
    
    // Success!
    identity := result.GetIdentity()
    fmt.Printf("Authenticated: %s %s\n", identity.GetGivenName(), identity.GetSurName())
    
    return nil
}
```

### Notification Authentication

```go
func notificationAuth(idCode string) error {
    config := &smartid.SmartIdClientConfig{
        RelyingPartyUUID: "your-uuid",
        RelyingPartyName: "Your App",
        HostURL:          "https://sid.demo.sk.ee/smart-id-rp",
    }
    
    client := smartid.NewSmartIdAuthClient(config)
    
    notificationRequest := smartid.NewAuthenticationRequestBuilder(
        config.RelyingPartyUUID,
        config.RelyingPartyName,
    ).WithInteractions(&smartid.DisplayTextAndPINInteraction{
        Type:          "displayTextAndPIN", 
        DisplayText60: "Confirm login",
    }).WithVCType("numeric4").Build()
    
    response, err := client.StartAuthenticateNotificationByEtsi(idCode, notificationRequest)
    if err != nil {
        return err
    }
    
    fmt.Printf("Verification code: %s\n", response.VerificationCode)
    
    authResponse, err := client.PollForSessionResult(response.SessionID, nil)
    if err != nil {
        return err
    }
    
    fmt.Printf("Authentication result: %s\n", authResponse.Result.EndResult)
    return nil
}
```

## Security

This library implements comprehensive security validations:

### ✅ Built-in Security Features

- **Session Completion Verification** - Ensures proper session state
- **Certificate Chain Validation** - Verifies against trusted CA store  
- **Certificate Expiry Checks** - Validates certificate validity periods
- **Smart-ID Scheme Identification** - Enforces proper KeyUsage and EKU
- **Signature Verification** - Full ACSP_V2 signature validation
- **Callback Parameter Validation** - Prevents tampering in Web2App/App2App
- **TLS Certificate Pinning** - Optional public key pinning support

### ⚠️ Security Responsibilities

- **CA Certificate Management** - You must provide valid, up-to-date CA certificates
- **Replay Attack Protection** - Implement session token management
- **Secure Backend** - Protect session secrets and sensitive data
- **Follow Security Guidelines** - Read the [Smart-ID Security Guide](https://sk-eid.github.io/smart-id-documentation/rp-api/secure_implementation.html)

## API Reference

### Core Types

```go
// Client configuration
type SmartIdClientConfig struct {
    RelyingPartyUUID string
    RelyingPartyName string
    HostURL          string
    APIVersion       string
    BrokeredRpName   string
    PinnedCerts      []*x509.Certificate
    PublicSSLKeys    string
    Debug            bool
}

// Certificate levels
const (
    CertificateLevelAdvanced  CertificateLevel = "ADVANCED"
    CertificateLevelQualified CertificateLevel = "QUALIFIED"
)

// Hash algorithms  
const (
    HashAlgorithmSHA256   HashAlgorithm = "SHA-256"
    HashAlgorithmSHA384   HashAlgorithm = "SHA-384"
    HashAlgorithmSHA512   HashAlgorithm = "SHA-512"
    HashAlgorithmSHA3_256 HashAlgorithm = "SHA3-256"
    HashAlgorithmSHA3_384 HashAlgorithm = "SHA3-384"
    HashAlgorithmSHA3_512 HashAlgorithm = "SHA3-512"
)

// Device link types
const (
    DeviceLinkTypeQR      DeviceLinkType = "QR"
    DeviceLinkTypeWeb2App DeviceLinkType = "Web2App"
    DeviceLinkTypeApp2App DeviceLinkType = "App2App"
)
```

### Error Types

```go
// Base Smart-ID error
type SmartIdError struct {
    Message string
}

// User refused operation
type SmartIdUserRefusedError struct {
    SmartIdError
}

// Session timeout
type SmartIdTimeoutError struct {
    SmartIdError
}

// Session failed with specific reason
type SmartIdSessionFailedError struct {
    SmartIdError
    EndResult string
}
```

## Testing

Run the test suite:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run benchmarks
go test -bench=. ./...

# Run specific test
go test -run TestAuthenticationRequestBuilder ./...
```

### Test Coverage

The library includes comprehensive tests covering:

- ✅ Request builder functionality
- ✅ Client configuration and setup
- ✅ Authentication flows
- ✅ Response validation
- ✅ Error handling
- ✅ Security features
- ✅ Edge cases and error conditions

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Ensure all tests pass
5. Submit a pull request

### Development Setup

```bash
git clone https://github.com/PaymentSyst/smart-id-client.git
cd smart-id-client
go mod tidy
go test ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This is an **independent, third-party, open-source library** developed for convenience in integrating with the official Smart-ID API.

It is **not developed, reviewed, endorsed, or certified by SK ID Solutions AS** or any official Smart-ID authority.

⚠️ **Use at your own risk.** Ensure your Smart-ID integration complies with all applicable laws, regulations, and the official [Smart-ID Implementation Guidelines](https://sk-eid.github.io/smart-id-documentation/rp-api/).

For production use, thorough independent review and appropriate security measures are strongly recommended.

## References

- [SK-eID Smart-ID Documentation](https://sk-eid.github.io/smart-id-documentation/)
- [Smart-ID API v3 Reference](https://sk-eid.github.io/smart-id-documentation/rp-api/)
- [Secure Implementation Guide](https://github.com/SK-EID/smart-id-documentation/wiki/Secure-Implementation-Guide)

## Credits

This Go library is a complete port of the original TypeScript/Node.js Smart-ID client library developed by [Joosep Wong](https://medium.com/@joosepwong).

Go implementation maintains feature parity while leveraging Go's strengths in performance, type safety, and concurrent programming.