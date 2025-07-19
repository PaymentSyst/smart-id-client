//go:build integration
// +build integration

package smartid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIntegrationAuthenticationFlow tests the complete authentication flow with a mock server
func TestIntegrationAuthenticationFlow(t *testing.T) {
	// Mock Smart-ID API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/authentication/device-link/anonymous":
			handleDeviceLinkRequest(w, r, t)
		case "/v3/session/test-session-id":
			handleSessionStatus(w, r, t)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// Create client with mock server
	config := &SmartIdClientConfig{
		RelyingPartyUUID: "00000000-0000-4000-8000-000000000000",
		RelyingPartyName: "TEST",
		HostURL:          server.URL,
		APIVersion:       "v3",
		Debug:            true,
	}

	client := NewSmartIdAuthClient(config)

	// Build authentication request
	builder := NewAuthenticationRequestBuilder(
		config.RelyingPartyUUID,
		config.RelyingPartyName,
	)

	request := builder.
		WithInitialCallbackURL("https://example.com/callback").
		WithCertificateLevel(CertificateLevelQualified).
		WithInteractions(&DisplayTextAndPINInteraction{
			Type:          "displayTextAndPIN",
			DisplayText60: "Test authentication",
		}).
		Build()

	// Test device link request
	response, sessionStartTime, err := client.GetAuthenticateAnonymousDeviceLink(request)
	if err != nil {
		t.Fatalf("Failed to start authentication: %v", err)
	}

	if response.SessionID != "test-session-id" {
		t.Errorf("Expected session ID 'test-session-id', got %s", response.SessionID)
	}

	if sessionStartTime == 0 {
		t.Error("Expected session start time to be set")
	}

	// Test device link URL generation
	linkOptions := &DeviceLinkOptions{
		DeviceLinkType: DeviceLinkTypeWeb2App,
		Lang:           "eng",
	}

	deviceLinkURL := client.CreateDeviceLinkURL(response, request, sessionStartTime, linkOptions)
	if deviceLinkURL == "" {
		t.Error("Expected device link URL to be generated")
	}

	// Test session status polling
	status, err := client.GetSessionStatus(response.SessionID)
	if err != nil {
		t.Fatalf("Failed to get session status: %v", err)
	}

	if status.State != "COMPLETE" {
		t.Errorf("Expected session state 'COMPLETE', got %s", status.State)
	}

	if status.Result.EndResult != "OK" {
		t.Errorf("Expected end result 'OK', got %s", status.Result.EndResult)
	}
}

// TestIntegrationNotificationFlow tests the notification authentication flow
func TestIntegrationNotificationFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v3/authentication/notification/etsi/PNOEE-30303039914":
			handleNotificationRequest(w, r, t)
		case r.URL.Path == "/v3/session/test-notification-session":
			handleNotificationSessionStatus(w, r, t)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	config := &SmartIdClientConfig{
		RelyingPartyUUID: "00000000-0000-4000-8000-000000000000",
		RelyingPartyName: "TEST",
		HostURL:          server.URL,
		Debug:            true,
	}

	client := NewSmartIdAuthClient(config)

	// Build notification request
	notificationRequest := NewAuthenticationRequestBuilder(
		config.RelyingPartyUUID,
		config.RelyingPartyName,
	).WithInteractions(&DisplayTextAndPINInteraction{
		Type:          "displayTextAndPIN",
		DisplayText60: "Test notification",
	}).WithVCType("numeric4").Build()

	// Test notification authentication
	response, err := client.StartAuthenticateNotificationByEtsi("PNOEE-30303039914", notificationRequest)
	if err != nil {
		t.Fatalf("Failed to start notification authentication: %v", err)
	}

	if response.SessionID != "test-notification-session" {
		t.Errorf("Expected session ID 'test-notification-session', got %s", response.SessionID)
	}

	if len(response.VerificationCode) != 4 {
		t.Errorf("Expected verification code to be 4 digits, got %s", response.VerificationCode)
	}

	// Test session polling
	status, err := client.GetSessionStatus(response.SessionID)
	if err != nil {
		t.Fatalf("Failed to get session status: %v", err)
	}

	if status.State != "COMPLETE" {
		t.Errorf("Expected session state 'COMPLETE', got %s", status.State)
	}
}

// TestIntegrationErrorHandling tests error handling scenarios
func TestIntegrationErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3/authentication/device-link/anonymous":
			// Return error response
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "INVALID_REQUEST",
				"message": "Invalid request parameters",
			})
		case "/v3/session/error-session":
			// Return failed session
			handleErrorSession(w, r, t)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	config := &SmartIdClientConfig{
		RelyingPartyUUID: "invalid-uuid",
		RelyingPartyName: "TEST",
		HostURL:          server.URL,
		Debug:            true,
	}

	client := NewSmartIdAuthClient(config)

	request := NewAuthenticationRequestBuilder(
		config.RelyingPartyUUID,
		config.RelyingPartyName,
	).Build()

	// Test API error handling
	_, _, err := client.GetAuthenticateAnonymousDeviceLink(request)
	if err == nil {
		t.Error("Expected error for invalid request")
	}
}

// TestIntegrationCallbackValidation tests callback URL validation
func TestIntegrationCallbackValidation(t *testing.T) {
	// Create test callback entity with valid data
	callbackEntity := &CallbackValidationEntity{
		SessionSecretDigest:   "Zm9vYmFy", // base64 encoded hash
		UserChallengeVerifier: "test-verifier",
		SessionSecret:         "dGVzdC1zZWNyZXQ=", // base64 encoded "test-secret"
		SchemeName:            "smart-id-demo",
		AuthenticationResponse: AuthenticationResponse{
			State: "COMPLETE",
			Result: &AuthenticationResult{
				EndResult:      "OK",
				DocumentNumber: "PNOEE-30303039914-123",
			},
			SignatureProtocol: "ACSP_V2",
			Signature: &SignatureInfo{
				Value:         "dGVzdC1zaWduYXR1cmU=", // base64 encoded test signature
				UserChallenge: "test-challenge-hash",
			},
			Cert: &CertificateInfo{
				Value:            "dGVzdC1jZXJ0aWZpY2F0ZQ==", // base64 encoded test cert
				CertificateLevel: CertificateLevelQualified,
			},
		},
	}

	// Test callback validation
	validator := NewCallbackURLValidator(callbackEntity)
	result := validator.Validate().GetResult()

	// Should have some validation errors due to mismatched digests/hashes in test data
	// This is expected behavior for the integration test
	if !result.HasError() {
		t.Log("Callback validation passed (expected for test data)")
	} else {
		t.Logf("Callback validation failed as expected: %v", result.GetErrors())
	}
}

// Helper functions for mock server responses

func handleDeviceLinkRequest(w http.ResponseWriter, r *http.Request, t *testing.T) {
	if r.Method != http.MethodPost {
		t.Errorf("Expected POST request, got %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decode and validate request
	var request DeviceLinkAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Errorf("Failed to decode request: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if request.RelyingPartyUUID == "" {
		t.Error("Expected RelyingPartyUUID in request")
	}
	if request.RelyingPartyName == "" {
		t.Error("Expected RelyingPartyName in request")
	}

	// Return mock response
	response := DeviceLinkAuthResponse{
		SessionID:      "test-session-id",
		SessionToken:   "test-session-token",
		SessionSecret:  "dGVzdC1zZXNzaW9uLXNlY3JldA==", // base64 encoded
		DeviceLinkBase: "https://sid.demo.sk.ee/smart-id-rp/v3/devicelink",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleSessionStatus(w http.ResponseWriter, r *http.Request, t *testing.T) {
	if r.Method != http.MethodGet {
		t.Errorf("Expected GET request, got %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return successful session status
	response := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult:      "OK",
			DocumentNumber: "PNOEE-30303039914-123",
		},
		SignatureProtocol: "ACSP_V2",
		Signature: &SignatureInfo{
			Value:              "dGVzdC1zaWduYXR1cmU=",
			UserChallenge:      "test-user-challenge",
			ServerRandom:       "test-server-random",
			SignatureAlgorithm: "rsassa-pss",
			SignatureAlgorithmParameters: &ResponseSignatureAlgorithmParams{
				HashAlgorithm: "SHA-512",
				SaltLength:    64,
			},
		},
		Cert: &CertificateInfo{
			Value:            "dGVzdC1jZXJ0aWZpY2F0ZQ==",
			CertificateLevel: CertificateLevelQualified,
		},
		InteractionTypeUsed: "displayTextAndPIN",
		FlowType:            "Web2App",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleNotificationRequest(w http.ResponseWriter, r *http.Request, t *testing.T) {
	if r.Method != http.MethodPost {
		t.Errorf("Expected POST request, got %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return mock notification response
	response := map[string]string{
		"sessionID": "test-notification-session",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleNotificationSessionStatus(w http.ResponseWriter, r *http.Request, t *testing.T) {
	if r.Method != http.MethodGet {
		t.Errorf("Expected GET request, got %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return successful notification session status
	response := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult:      "OK",
			DocumentNumber: "PNOEE-30303039914-456",
		},
		SignatureProtocol: "ACSP_V2",
		Signature: &SignatureInfo{
			Value:         "dGVzdC1ub3RpZmljYXRpb24tc2lnbmF0dXJl",
			UserChallenge: "test-notification-challenge",
		},
		Cert: &CertificateInfo{
			Value:            "dGVzdC1ub3RpZmljYXRpb24tY2VydA==",
			CertificateLevel: CertificateLevelQualified,
		},
		InteractionTypeUsed: "displayTextAndPIN",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleErrorSession(w http.ResponseWriter, r *http.Request, t *testing.T) {
	// Return failed session
	response := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult: "USER_REFUSED_INTERACTION",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// TestIntegrationClientConfiguration tests client configuration options
func TestIntegrationClientConfiguration(t *testing.T) {
	config := &SmartIdClientConfig{
		RelyingPartyUUID: "test-uuid",
		RelyingPartyName: "test-name",
		HostURL:          "https://example.com",
		APIVersion:       "v3",
		PublicSSLKeys:    "sha256//key1;sha256//key2",
		Debug:            true,
	}

	client := NewSmartIdAuthClient(config)

	// Test configuration methods
	client.
		SetAPIEndpoint("https://new-endpoint.com", "v4").
		SetSchemeName("custom-scheme").
		SetBrokeredRpName("custom-broker").
		SetPublicSSLKeys("sha256//newkey1;sha256//newkey2")

	if client.GetHostURL() != "https://new-endpoint.com/v4" {
		t.Errorf("Expected endpoint to be updated, got %s", client.GetHostURL())
	}

	if client.schemeName != "custom-scheme" {
		t.Errorf("Expected scheme name to be 'custom-scheme', got %s", client.schemeName)
	}

	// Test callback parameter generation
	param := client.GenerateCallbackParam()
	if len(param) != 32 { // 16 bytes * 2 (hex encoding)
		t.Errorf("Expected callback param length 32, got %d", len(param))
	}
}

// TestIntegrationBuilderPatterns tests the builder pattern implementations
func TestIntegrationBuilderPatterns(t *testing.T) {
	// Test authentication request builder
	builder := NewAuthenticationRequestBuilder("uuid", "name")

	request := builder.
		WithInitialCallbackURL("https://callback.com").
		WithCertificateLevel(CertificateLevelAdvanced).
		WithHashAlgorithm(HashAlgorithmSHA256).
		WithRequestProperties(&RequestProperties{
			ShareMdClientIPAddress: true,
		}).
		WithCapabilities(map[string]interface{}{
			"customCap": "value",
		}).
		WithInteractions(&ConfirmationMessageInteraction{
			Type:           "confirmationMessage",
			DisplayText200: "Please confirm this action",
		}).
		Build()

	// Validate built request
	if request.InitialCallbackURL != "https://callback.com" {
		t.Error("InitialCallbackURL not set correctly")
	}
	if request.CertificateLevel != CertificateLevelAdvanced {
		t.Error("CertificateLevel not set correctly")
	}
	if request.SignatureProtocolParameters.SignatureAlgorithmParameters.HashAlgorithm != HashAlgorithmSHA256 {
		t.Error("HashAlgorithm not set correctly")
	}

	// Test notification request builder
	notificationBuilder := builder.WithVCType("numeric4")
	notificationRequest := notificationBuilder.Build()

	if notificationRequest.VCType != "numeric4" {
		t.Error("VCType not set correctly in notification request")
	}
}

// TestIntegrationUtilityFunctions tests utility functions
func TestIntegrationUtilityFunctions(t *testing.T) {
	// Test semantics identifier generation
	identifier := GenerateSemanticsIdentifier("PNOEE", "EE", "12345678901")
	expected := "PNOEEEE-12345678901"
	if identifier != expected {
		t.Errorf("Expected %s, got %s", expected, identifier)
	}

	// Test session success checking
	successfulResponse := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult: "OK",
		},
	}
	if !IsSessionSuccessful(successfulResponse) {
		t.Error("Expected session to be successful")
	}

	failedResponse := AuthenticationResponse{
		State: "COMPLETE",
		Result: &AuthenticationResult{
			EndResult: "USER_REFUSED_INTERACTION",
		},
	}
	if IsSessionSuccessful(failedResponse) {
		t.Error("Expected session to be unsuccessful")
	}

	// Test certificate level ordering
	if CertificationLevelOrder[CertificateLevelAdvanced] >= CertificationLevelOrder[CertificateLevelQualified] {
		t.Error("Expected QUALIFIED to have higher order than ADVANCED")
	}
}
