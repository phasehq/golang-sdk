package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
)

func ConstructHTTPHeaders(tokenType string, appToken string) http.Header {
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Bearer %s %s", tokenType, appToken))
	headers.Set("User-Agent", GetUserAgent())
	return headers
}

var customUserAgent string

func SetUserAgent(ua string) {
	customUserAgent = ua
}

func GetUserAgent() string {
	if customUserAgent != "" {
		return customUserAgent
	}

	details := []string{}

	cliVersion := "phase-golang-sdk/" + misc.Version
	details = append(details, cliVersion)

	osType := runtime.GOOS
	architecture := runtime.GOARCH
	details = append(details, fmt.Sprintf("%s %s", osType, architecture))

	currentUser, err := user.Current()
	if err == nil {
		hostname, err := os.Hostname()
		if err == nil {
			userHostString := fmt.Sprintf("%s@%s", currentUser.Username, hostname)
			details = append(details, userHostString)
		}
	}

	// Return only the concatenated string without "User-Agent:" prefix
	return strings.Join(details, " ")
}

var httpClient *http.Client

func getHTTPClient() *http.Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
		if !misc.VerifySSL {
			httpClient.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
	}
	return httpClient
}

// wrapTransportError converts raw Go net/http errors into typed SDK errors.
func wrapTransportError(err error) error {
	if err == nil {
		return nil
	}

	// Check for DNS errors
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return &NetworkError{Kind: "dns", Host: dnsErr.Name, Detail: err.Error()}
	}

	// Check for connection refused
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "dial" {
			return &NetworkError{Kind: "connection", Detail: err.Error()}
		}
	}

	// Check for TLS/SSL errors
	errStr := err.Error()
	if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
		return &SSLError{Detail: errStr}
	}

	// Check for timeout
	if os.IsTimeout(err) || strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "context deadline exceeded") {
		return &NetworkError{Kind: "timeout", Detail: err.Error()}
	}

	// Fallback
	return &NetworkError{Kind: "unknown", Detail: err.Error()}
}

func makeRequest(req *http.Request) ([]byte, error) {
	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, formatHTTPError(resp.StatusCode, body)
	}

	return body, nil
}

// formatHTTPError creates a typed SDK error from an HTTP error response.
func formatHTTPError(statusCode int, body []byte) error {
	switch statusCode {
	case http.StatusForbidden:
		return &AuthorizationError{Detail: extractErrorDetail(body)}
	case http.StatusTooManyRequests:
		return &RateLimitError{}
	default:
		return &APIError{StatusCode: statusCode, Detail: extractErrorDetail(body)}
	}
}

// extractErrorDetail tries to extract an error message from a JSON response body.
func extractErrorDetail(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var errResp map[string]interface{}
	if err := json.Unmarshal(body, &errResp); err == nil {
		if detail, ok := errResp["error"].(string); ok {
			return detail
		}
		if detail, ok := errResp["detail"].(string); ok {
			return detail
		}
	}
	// If not JSON or no known error field, return the raw body (truncated)
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// handleHTTPResponse checks the HTTP response status and handles errors appropriately.
func handleHTTPResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return formatHTTPError(resp.StatusCode, body)
}

func FetchPhaseUser(tokenType, appToken, host string) (*http.Response, error) {
	client := getHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	err = handleHTTPResponse(resp)
	if err != nil {
		resp.Body.Close() // Ensure response body is closed on error
		return nil, err
	}

	return resp, nil
}

// FetchPhaseUserRaw returns the raw JSON bytes from the user/tokens endpoint.
func FetchPhaseUserRaw(tokenType, appToken, host string) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	return makeRequest(req)
}

// FetchPhaseSecretsRaw returns the raw JSON bytes from the secrets endpoint.
func FetchPhaseSecretsRaw(tokenType, appToken, environmentID, host, path, keyDigest string) ([]byte, error) {
	url := fmt.Sprintf("%s/service/secrets/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Environment", environmentID)
	if path != "" {
		req.Header.Set("Path", path)
	}
	if keyDigest != "" {
		req.Header.Set("KeyDigest", keyDigest)
	}
	return makeRequest(req)
}

// FetchPhaseSecretsWithDynamicRaw returns the raw JSON bytes from the secrets endpoint with dynamic secret support.
func FetchPhaseSecretsWithDynamicRaw(tokenType, appToken, envID, host, path, keyDigest string, dynamic, lease bool, leaseTTL *int) ([]byte, error) {
	reqURL := fmt.Sprintf("%s/service/secrets/", host)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Environment", envID)
	if path != "" {
		req.Header.Set("Path", path)
	}
	if keyDigest != "" {
		req.Header.Set("KeyDigest", keyDigest)
	}
	if dynamic {
		req.Header.Set("dynamic", "true")
	}
	if lease {
		req.Header.Set("lease", "true")
	}
	if leaseTTL != nil {
		req.Header.Set("lease-ttl", fmt.Sprintf("%d", *leaseTTL))
	}
	return makeRequest(req)
}

func FetchAppKey(tokenType, appToken, host string) (string, error) {
	client := getHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", wrapTransportError(err)
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return "", err
	}

	var jsonResp misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON: %v", err)
	}

	return jsonResp.WrappedKeyShare, nil
}

func FetchPhaseSecrets(tokenType, appToken, environmentID, host, path, keyDigest string) ([]map[string]interface{}, error) {
	body, err := FetchPhaseSecretsRaw(tokenType, appToken, environmentID, host, path, keyDigest)
	if err != nil {
		return nil, err
	}
	var secrets []map[string]interface{}
	if err := json.Unmarshal(body, &secrets); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}
	return secrets, nil
}

func FetchPhaseSecret(tokenType, appToken, environmentID, host, keyDigest, path string) (map[string]interface{}, error) {
	client := getHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/", host)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Environment", environmentID)
	req.Header.Set("KeyDigest", keyDigest)
	if path != "" {
		req.Header.Set("Path", path)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, wrapTransportError(err)
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return nil, err
	}

	var secrets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	if len(secrets) > 0 {
		return secrets[0], nil
	}

	return nil, fmt.Errorf("no secrets found in the response")
}

func CreatePhaseSecrets(tokenType, appToken, environmentID string, secrets []map[string]interface{}, host string) error {
	client := getHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/", host)
	data, err := json.Marshal(map[string][]map[string]interface{}{"secrets": secrets})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Environment", environmentID)

	resp, err := client.Do(req)
	if err != nil {
		return wrapTransportError(err)
	}
	defer resp.Body.Close()

	return handleHTTPResponse(resp)
}

func UpdatePhaseSecrets(tokenType, appToken, environmentID string, secrets []map[string]interface{}, host string) error {
	client := getHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/", host)
	data, err := json.Marshal(map[string][]map[string]interface{}{"secrets": secrets})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Environment", environmentID)

	resp, err := client.Do(req)
	if err != nil {
		return wrapTransportError(err)
	}
	defer resp.Body.Close()

	return handleHTTPResponse(resp)
}

func DeletePhaseSecrets(tokenType, appToken, environmentID string, secretIDs []string, host string) error {
	client := getHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/", host)
	data, err := json.Marshal(map[string][]string{"secrets": secretIDs})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Environment", environmentID)

	resp, err := client.Do(req)
	if err != nil {
		return wrapTransportError(err)
	}
	defer resp.Body.Close()

	return handleHTTPResponse(resp)
}

func FetchPhaseSecretsWithDynamic(tokenType, appToken, envID, host, path, keyDigest string, dynamic, lease bool, leaseTTL *int) ([]map[string]interface{}, error) {
	body, err := FetchPhaseSecretsWithDynamicRaw(tokenType, appToken, envID, host, path, keyDigest, dynamic, lease, leaseTTL)
	if err != nil {
		return nil, err
	}
	var secrets []map[string]interface{}
	if err := json.Unmarshal(body, &secrets); err != nil {
		return nil, fmt.Errorf("failed to decode secrets response: %w", err)
	}
	return secrets, nil
}

func ListDynamicSecrets(tokenType, appToken, host, appID, env, path string) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	if path != "" {
		params.Set("path", path)
	}
	reqURL += "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)

	body, err := makeRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func CreateDynamicSecretLease(tokenType, appToken, host, appID, env, secretID string, ttl *int) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	params.Set("id", secretID)
	params.Set("lease", "true")
	if ttl != nil {
		params.Set("ttl", fmt.Sprintf("%d", *ttl))
	}
	reqURL += "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)

	body, err := makeRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func ListDynamicSecretLeases(tokenType, appToken, host, appID, env, secretID string) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/leases/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	if secretID != "" {
		params.Set("secret_id", secretID)
	}
	reqURL += "?" + params.Encode()

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)

	body, err := makeRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func RenewDynamicSecretLease(tokenType, appToken, host, appID, env, leaseID string, ttl int) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/leases/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	reqURL += "?" + params.Encode()

	payload, _ := json.Marshal(map[string]interface{}{
		"lease_id": leaseID,
		"ttl":      ttl,
	})

	req, err := http.NewRequest("PUT", reqURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")

	body, err := makeRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func RevokeDynamicSecretLease(tokenType, appToken, host, appID, env, leaseID string) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/service/public/v1/secrets/dynamic/leases/", host)

	params := url.Values{}
	params.Set("app_id", appID)
	params.Set("env", env)
	reqURL += "?" + params.Encode()

	payload, _ := json.Marshal(map[string]interface{}{
		"lease_id": leaseID,
	})

	req, err := http.NewRequest("DELETE", reqURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Content-Type", "application/json")

	body, err := makeRequest(req)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

// ExternalIdentityAuthAzure acquires an Azure AD JWT using DefaultAzureCredential
// and exchanges it for a Phase ServiceAccount token.
//
// DefaultAzureCredential tries (in order):
//  1. Environment vars (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
//  2. Workload Identity (Kubernetes)
//  3. Managed Identity (IMDS — Azure VMs, Functions, AKS)
//  4. Azure CLI (az login)
//  5. Azure Developer CLI (azd login)
//
// The resource parameter must match the "Resource / Audience" configured on the
// Phase identity (default: "https://management.azure.com/").
func ExternalIdentityAuthAzure(host, serviceAccountID string, ttl *int, resource string) (map[string]interface{}, error) {
	if resource == "" {
		resource = "https://management.azure.com/"
	}

	ctx := context.Background()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// .default scope suffix required for v2.0 token endpoint
	// Ensure resource ends with "/" before appending ".default"
	scope := strings.TrimRight(resource, "/") + "/.default"
	azToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{scope},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure AD token: %w", err)
	}

	encodedJWT := base64.StdEncoding.EncodeToString([]byte(azToken.Token))

	reqURL := fmt.Sprintf("%s/service/public/identities/external/v1/azure/entra/auth/", host)

	payload := map[string]interface{}{
		"account": map[string]interface{}{
			"type": "service",
			"id":   serviceAccountID,
		},
		"azureEntra": map[string]interface{}{
			"jwt": encodedJWT,
		},
	}
	if ttl != nil {
		payload["tokenRequest"] = map[string]interface{}{
			"ttl": *ttl,
		}
	}

	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := makeRequest(req)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}
	return result, nil
}

func ExternalIdentityAuthAWS(host, serviceAccountID string, ttl *int, encodedURL, encodedHeaders, encodedBody, method string) (map[string]interface{}, error) {
	reqURL := fmt.Sprintf("%s/service/public/identities/external/v1/aws/iam/auth/", host)

	payload := map[string]interface{}{
		"account": map[string]interface{}{
			"type": "service",
			"id":   serviceAccountID,
		},
		"awsIam": map[string]interface{}{
			"httpRequestMethod":  method,
			"httpRequestUrl":     encodedURL,
			"httpRequestHeaders": encodedHeaders,
			"httpRequestBody":    encodedBody,
		},
	}
	if ttl != nil {
		payload["tokenRequest"] = map[string]interface{}{
			"ttl": *ttl,
		}
	}

	payloadBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", reqURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	respBody, err := makeRequest(req)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to decode auth response: %w", err)
	}
	return result, nil
}
