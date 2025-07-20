package smartid

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SmartIdAuthClient serves as the primary communication layer between your application and the Smart-ID REST API
type SmartIdAuthClient struct {
	config         *SmartIdClientConfig
	httpClient     *http.Client
	publicSSLKeys  []string
	schemeName     string
	brokeredRpName string
	debug          bool
	baseURL        string
}

// NewSmartIdAuthClient creates a new SmartIdAuthClient instance
func NewSmartIdAuthClient(config *SmartIdClientConfig) *SmartIdAuthClient {
	if config.HostURL == "" {
		config.HostURL = "https://rp-api.smart-id.com"
	}
	if config.APIVersion == "" {
		config.APIVersion = "v3"
	}

	baseURL := strings.TrimRight(config.HostURL, "/") + "/" + config.APIVersion

	// Create HTTP client with custom TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Add pinned certificates if provided
	if len(config.PinnedCerts) > 0 {
		certPool := x509.NewCertPool()
		for _, cert := range config.PinnedCerts {
			certPool.AddCert(cert)
		}
		tlsConfig.RootCAs = certPool
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	client := &SmartIdAuthClient{
		config:         config,
		httpClient:     httpClient,
		publicSSLKeys:  make([]string, 0),
		schemeName:     "smart-id",
		brokeredRpName: config.BrokeredRpName,
		debug:          config.Debug,
		baseURL:        baseURL,
	}

	if config.PublicSSLKeys != "" {
		client.SetPublicSSLKeys(config.PublicSSLKeys)
	}

	return client
}

// SetPublicSSLKeys configures SHA-256 public key pinning for additional security
func (c *SmartIdAuthClient) SetPublicSSLKeys(fingerprints string) *SmartIdAuthClient {
	c.publicSSLKeys = strings.Split(fingerprints, ";")
	for i, key := range c.publicSSLKeys {
		c.publicSSLKeys[i] = strings.TrimSpace(key)
	}
	return c
}

// SetAPIEndpoint overrides Smart-ID API endpoint and version
func (c *SmartIdAuthClient) SetAPIEndpoint(hostURL string, version string) *SmartIdAuthClient {
	if version == "" {
		version = "v3"
	}
	c.baseURL = strings.TrimRight(hostURL, "/") + "/" + version
	return c
}

// SetAPIVersion updates Smart-ID API version
func (c *SmartIdAuthClient) SetAPIVersion(version string) *SmartIdAuthClient {
	hostURL := strings.TrimRight(c.config.HostURL, "/")
	c.baseURL = hostURL + "/" + version
	return c
}

// SetSchemeName sets the scheme name used for signature payloads
func (c *SmartIdAuthClient) SetSchemeName(name string) *SmartIdAuthClient {
	c.schemeName = name
	return c
}

// SetBrokeredRpName sets the brokered RP name used in DeviceLink URL generation
func (c *SmartIdAuthClient) SetBrokeredRpName(name string) *SmartIdAuthClient {
	c.brokeredRpName = name
	return c
}

// GetAuthenticateAnonymousDeviceLink starts anonymous DeviceLink authentication
func (c *SmartIdAuthClient) GetAuthenticateAnonymousDeviceLink(requestPayload *DeviceLinkAuthRequest) (*DeviceLinkAuthResponse, int64, error) {
	return c.sendDeviceLinkRequest("/authentication/device-link/anonymous", requestPayload)
}

// GetAuthenticateDeviceLinkByEtsi starts DeviceLink authentication by ETSI
func (c *SmartIdAuthClient) GetAuthenticateDeviceLinkByEtsi(idCode string, requestPayload *DeviceLinkAuthRequest) (*DeviceLinkAuthResponse, int64, error) {
	path := fmt.Sprintf("/authentication/device-link/etsi/%s", url.PathEscape(idCode))
	return c.sendDeviceLinkRequest(path, requestPayload)
}

// GetAuthenticateDeviceLinkByDocument starts DeviceLink authentication by document number
func (c *SmartIdAuthClient) GetAuthenticateDeviceLinkByDocument(documentNumber string, requestPayload *DeviceLinkAuthRequest) (*DeviceLinkAuthResponse, int64, error) {
	path := fmt.Sprintf("/authentication/device-link/document/%s", url.PathEscape(documentNumber))
	return c.sendDeviceLinkRequest(path, requestPayload)
}

// StartAuthenticateNotificationByEtsi starts Notification Authentication by ETSI
func (c *SmartIdAuthClient) StartAuthenticateNotificationByEtsi(idCode string, requestPayload *NotificationAuthRequest) (*NotificationAuthResponse, error) {
	path := fmt.Sprintf("/authentication/notification/etsi/%s", url.PathEscape(idCode))
	return c.sendNotificationRequest(path, requestPayload)
}

// StartAuthenticateNotificationByDocument starts Notification Authentication by document number
func (c *SmartIdAuthClient) StartAuthenticateNotificationByDocument(documentNumber string, requestPayload *NotificationAuthRequest) (*NotificationAuthResponse, error) {
	path := fmt.Sprintf("/authentication/notification/document/%s", url.PathEscape(documentNumber))
	return c.sendNotificationRequest(path, requestPayload)
}

// GetSessionStatus retrieves the current status of an authentication session
func (c *SmartIdAuthClient) GetSessionStatus(sessionID string, timeoutMs ...int) (*AuthenticationResponse, error) {
	path := fmt.Sprintf("/session/%s", url.PathEscape(sessionID))
	requestURL := c.baseURL + path

	if len(timeoutMs) > 0 && timeoutMs[0] > 0 {
		query := url.Values{}
		query.Add("timeoutMs", strconv.Itoa(timeoutMs[0]))
		requestURL += "?" + query.Encode()
	}

	resp, err := c.httpClient.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get session status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
	}

	var authResponse AuthenticationResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if authResponse.State == "" {
		return nil, fmt.Errorf("invalid response from Smart-ID session API")
	}

	return &authResponse, nil
}

// PollForSessionResult polls session status until success, failure, or timeout occurs
func (c *SmartIdAuthClient) PollForSessionResult(sessionID string, options *PollOptions) (*AuthenticationResponse, error) {
	if options == nil {
		options = &PollOptions{
			MaxWaitMs:      60000,
			PollIntervalMs: 2000,
			MaxAttempts:    30,
		}
	}

	if options.MaxWaitMs == 0 {
		options.MaxWaitMs = 60000
	}
	if options.PollIntervalMs == 0 {
		options.PollIntervalMs = 2000
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = options.MaxWaitMs / options.PollIntervalMs
	}

	startTime := time.Now()
	maxDuration := time.Duration(options.MaxWaitMs) * time.Millisecond

	for attempt := 0; attempt < options.MaxAttempts && time.Since(startTime) < maxDuration; attempt++ {
		status, err := c.GetSessionStatus(sessionID, options.PollIntervalMs)
		if err != nil {
			return nil, err
		}

		c.log(fmt.Sprintf("Attempt %d - Session state: %s", attempt+1, status.State))

		if status.State == "COMPLETE" {
			if status.Result == nil {
				return nil, NewSmartIdSessionFailedError("Missing result in completed session")
			}

			endResult := SmartIdEndResult(status.Result.EndResult)
			switch endResult {
			case SmartIdEndResultOK:
				return status, nil
			case SmartIdEndResultUserRefusedInteraction,
				SmartIdEndResultUserRefusedDisplayTextAndPIN,
				SmartIdEndResultUserRefusedConfirmationMessage,
				SmartIdEndResultUserRefusedConfirmationMessageWithVCChoice,
				SmartIdEndResultUserRefusedCertChoice:
				return nil, NewSmartIdUserRefusedError()
			case SmartIdEndResultDocumentUnusable:
				return nil, NewSmartIdSessionFailedError("Document unusable")
			case SmartIdEndResultWrongVC:
				return nil, NewSmartIdSessionFailedError("Wrong verification code")
			case SmartIdEndResultProtocolFailure:
				return nil, NewSmartIdSessionFailedError("Protocol failure")
			case SmartIdEndResultServerError:
				return nil, NewSmartIdSessionFailedError("Server error")
			case SmartIdEndResultTimeout:
				return nil, NewSmartIdSessionFailedError("Session timeout reported by Smart-ID")
			case SmartIdEndResultRequiredInteractionNotSupportedByApp:
				return nil, NewSmartIdSessionFailedError("Required interaction not supported by the app")
			default:
				return nil, NewSmartIdSessionFailedError(string(endResult))
			}
		}
	}

	return nil, NewSmartIdTimeoutError()
}

// CreateDeviceLinkURL generates a signed DeviceLink URL for QR, Web2App, or App2App flows
func (c *SmartIdAuthClient) CreateDeviceLinkURL(session *DeviceLinkAuthResponse, payload *DeviceLinkAuthRequest, sessionStartTime int64, opts *DeviceLinkOptions) string {
	base := session.DeviceLinkBase
	lang := opts.Lang
	if lang == "" {
		lang = "eng"
	}

	query := url.Values{}
	query.Set("deviceLinkType", string(opts.DeviceLinkType))

	if opts.DeviceLinkType == DeviceLinkTypeQR {
		elapsedSeconds := opts.ElapsedSeconds
		if elapsedSeconds == 0 {
			elapsedSeconds = int((time.Now().UnixMilli() - sessionStartTime) / 1000)
		}
		query.Set("elapsedSeconds", strconv.Itoa(elapsedSeconds))
	}

	query.Set("sessionToken", session.SessionToken)
	query.Set("sessionType", "auth")
	query.Set("version", "1.0")
	query.Set("lang", lang)

	unprotectedLink := base + "?" + query.Encode()

	rpChallenge := payload.SignatureProtocolParameters.RPChallenge
	relyingPartyNameBase64 := base64.StdEncoding.EncodeToString([]byte(payload.RelyingPartyName))
	brokeredRpNameBase64 := base64.StdEncoding.EncodeToString([]byte(c.brokeredRpName))
	interactions := payload.Interactions

	actualInitialCallbackURL := ""
	if opts.DeviceLinkType != DeviceLinkTypeQR {
		actualInitialCallbackURL = payload.InitialCallbackURL
	}

	authCodePayload := strings.Join([]string{
		c.schemeName,
		string(payload.SignatureProtocol),
		rpChallenge,
		relyingPartyNameBase64,
		brokeredRpNameBase64,
		interactions,
		actualInitialCallbackURL,
		unprotectedLink,
	}, "|")

	sessionSecret, err := base64.StdEncoding.DecodeString(session.SessionSecret)
	if err != nil {
		return unprotectedLink
	}

	h := hmac.New(sha256.New, sessionSecret)
	h.Write([]byte(authCodePayload))
	authCode := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return unprotectedLink + "&authCode=" + authCode
}

// GenerateCallbackParam generates a random callback parameter
func (c *SmartIdAuthClient) GenerateCallbackParam() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetHostURL returns the current API base URL
func (c *SmartIdAuthClient) GetHostURL() string {
	return c.baseURL
}

// sendDeviceLinkRequest sends a device link authentication request
func (c *SmartIdAuthClient) sendDeviceLinkRequest(path string, payload *DeviceLinkAuthRequest) (*DeviceLinkAuthResponse, int64, error) {
	sessionStartTime := time.Now().UnixMilli()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, sessionStartTime, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+path, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, sessionStartTime, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, sessionStartTime, fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
	}

	var response DeviceLinkAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, sessionStartTime, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, sessionStartTime, nil
}

// sendNotificationRequest sends a notification authentication request
func (c *SmartIdAuthClient) sendNotificationRequest(path string, payload *NotificationAuthRequest) (*NotificationAuthResponse, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(c.baseURL+path, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
	}

	var response struct {
		SessionID string `json:"sessionID"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	verificationCode := c.computeVerificationCode(payload.SignatureProtocolParameters.RPChallenge)

	return &NotificationAuthResponse{
		SessionID:        response.SessionID,
		VerificationCode: verificationCode,
	}, nil
}

// computeVerificationCode computes the verification code from the RP challenge
func (c *SmartIdAuthClient) computeVerificationCode(base64Challenge string) string {
	challengeBytes, err := base64.StdEncoding.DecodeString(base64Challenge)
	if err != nil {
		return "0000"
	}

	hash := sha256.Sum256(challengeBytes)
	code := ((int(hash[30]) << 8) + int(hash[31])) % 10000
	return fmt.Sprintf("%04d", code)
}

// log outputs debug messages if debug mode is enabled
func (c *SmartIdAuthClient) log(message string) {
	if c.debug {
		fmt.Printf("[Smart-ID] %s\n", message)
	}
}
