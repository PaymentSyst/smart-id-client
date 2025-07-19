package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	smartid "github.com/smartid-client/go-client"
)

func main() {
	// Example: Anonymous Device Link Authentication
	fmt.Println("=== Smart-ID Go Client Example ===")

	// Create client configuration
	config := &smartid.SmartIdClientConfig{
		RelyingPartyUUID: "00000000-0000-4000-8000-000000000000", // Demo UUID
		RelyingPartyName: "DEMO",
		HostURL:          "https://sid.demo.sk.ee/smart-id-rp",
		APIVersion:       "v3",
		Debug:            true,
	}

	// Create Smart-ID client
	client := smartid.NewSmartIdAuthClient(config)
	client.SetSchemeName("smart-id-demo")

	// Generate callback parameter for security
	callbackParam := generateCallbackParam()
	callbackURL := fmt.Sprintf("https://example.com/callback?chksum=%s", callbackParam)

	// Build authentication request
	builder := smartid.NewAuthenticationRequestBuilder(
		config.RelyingPartyUUID,
		config.RelyingPartyName,
	)

	request := builder.
		WithInitialCallbackURL(callbackURL).
		WithCertificateLevel(smartid.CertificateLevelQualified).
		WithInteractions(&smartid.DisplayTextAndPINInteraction{
			Type:          "displayTextAndPIN",
			DisplayText60: "Authenticate with Smart-ID",
		}).
		Build()

	fmt.Printf("Created authentication request for RP: %s\n", request.RelyingPartyName)

	// Start anonymous device link authentication
	response, sessionStartTime, err := client.GetAuthenticateAnonymousDeviceLink(request)
	if err != nil {
		log.Fatalf("Failed to start authentication: %v", err)
	}

	fmt.Printf("Authentication session started: %s\n", response.SessionID)

	// Create device link URL for Web2App flow
	linkOptions := &smartid.DeviceLinkOptions{
		DeviceLinkType: smartid.DeviceLinkTypeWeb2App,
		Lang:           "eng",
	}

	deviceLinkURL := client.CreateDeviceLinkURL(response, request, sessionStartTime, linkOptions)
	fmt.Printf("Device Link URL: %s\n", deviceLinkURL)

	// Poll for session result
	fmt.Println("Polling for authentication result...")
	pollOptions := &smartid.PollOptions{
		MaxWaitMs:      60000, // 60 seconds
		PollIntervalMs: 2000,  // 2 seconds
		MaxAttempts:    30,
	}

	authResponse, err := client.PollForSessionResult(response.SessionID, pollOptions)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	fmt.Printf("Authentication completed with result: %s\n", authResponse.Result.EndResult)

	// Validate the authentication response
	// Note: In production, provide actual path to CA certificates
	validator, err := smartid.NewAuthenticationResponseValidator("./ca-certificates", true)
	if err != nil {
		log.Printf("Warning: Could not create validator: %v", err)
		// Continue without validation for demo purposes
		fmt.Println("Skipping validation due to missing CA certificates")
		return
	}

	// Perform comprehensive validation
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
		if identity != nil {
			fmt.Println("\n=== Authentication Identity ===")
			fmt.Printf("Given Name: %s\n", identity.GetGivenName())
			fmt.Printf("Surname: %s\n", identity.GetSurName())
			fmt.Printf("Identity Code: %s\n", identity.GetIdentityCode())
			fmt.Printf("Identity Number: %s\n", identity.GetIdentityNumber())
			fmt.Printf("Country: %s\n", identity.GetCountry())
			fmt.Printf("Document Number: %s\n", identity.GetDocumentNumber())
			fmt.Printf("Valid From: %s\n", identity.GetValidFrom().Format("2006-01-02"))
			fmt.Printf("Valid To: %s\n", identity.GetValidTo().Format("2006-01-02"))
			fmt.Printf("Date of Birth: %s\n", identity.GetDateOfBirth())
		}

		// Verify signature (optional)
		signatureValid := validator.VerifySignature(authResponse, request)
		fmt.Printf("Signature valid: %t\n", signatureValid)
	}

	fmt.Println("\n=== Authentication Complete ===")
}

// Example: Notification Authentication
func exampleNotificationAuth() {
	config := &smartid.SmartIdClientConfig{
		RelyingPartyUUID: "00000000-0000-4000-8000-000000000000",
		RelyingPartyName: "DEMO",
		HostURL:          "https://sid.demo.sk.ee/smart-id-rp",
		Debug:            true,
	}

	client := smartid.NewSmartIdAuthClient(config)

	// Build notification request
	builder := smartid.NewAuthenticationRequestBuilder(
		config.RelyingPartyUUID,
		config.RelyingPartyName,
	)

	// Switch to notification request
	notificationBuilder := builder.
		WithCertificateLevel(smartid.CertificateLevelQualified).
		WithInteractions(&smartid.DisplayTextAndPINInteraction{
			Type:          "displayTextAndPIN",
			DisplayText60: "Authenticate with Smart-ID",
		}).
		WithVCType("numeric4")

	notificationRequest := notificationBuilder.Build()

	// Start notification authentication by ETSI identifier
	etsiId := "PNOEE-30303039914" // Example ETSI identifier
	notificationResponse, err := client.StartAuthenticateNotificationByEtsi(etsiId, notificationRequest)
	if err != nil {
		log.Fatalf("Failed to start notification authentication: %v", err)
	}

	fmt.Printf("Notification authentication started: %s\n", notificationResponse.SessionID)
	fmt.Printf("Verification code: %s\n", notificationResponse.VerificationCode)

	// Poll for result (same as device link)
	authResponse, err := client.PollForSessionResult(notificationResponse.SessionID, nil)
	if err != nil {
		log.Fatalf("Notification authentication failed: %v", err)
	}

	fmt.Printf("Notification authentication completed: %s\n", authResponse.Result.EndResult)
}

// Example: Callback URL validation for Web2App/App2App flows
func exampleCallbackValidation() {
	// This would typically be called when your callback URL receives parameters
	callbackEntity := &smartid.CallbackValidationEntity{
		SessionSecretDigest:   "computed_digest_from_frontend",
		UserChallengeVerifier: "random_verifier_used_in_request",
		SessionSecret:         "base64_session_secret_used_in_request",
		SchemeName:            "smart-id-demo",
		AuthenticationResponse: smartid.AuthenticationResponse{
			State: "COMPLETE",
			Result: &smartid.AuthenticationResult{
				EndResult:      "OK",
				DocumentNumber: "PNOEE-1234567890",
			},
			SignatureProtocol: "ACSP_V2",
			Signature: &smartid.SignatureInfo{
				Value:         "base64_signature_value",
				UserChallenge: "expected_computed_hash",
			},
			Cert: &smartid.CertificateInfo{
				Value:            "base64_certificate",
				CertificateLevel: smartid.CertificateLevelQualified,
			},
		},
	}

	// Validate callback parameters
	validator := smartid.NewCallbackURLValidator(callbackEntity)
	result := validator.Validate().GetResult()

	if result.HasError() {
		fmt.Printf("Callback validation failed: %v\n", result.GetErrors())
	} else {
		fmt.Println("Callback successfully validated!")
	}
}

// generateCallbackParam generates a random callback parameter for security
func generateCallbackParam() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
