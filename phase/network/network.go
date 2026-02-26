package network

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/phasehq/golang-sdk/phase/misc"
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

func createHTTPClient() *http.Client {
	client := &http.Client{}
	if !misc.VerifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client
}

func makeRequest(req *http.Request) ([]byte, error) {
	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// handleHTTPResponse checks the HTTP response status and handles errors appropriately.
func handleHTTPResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK:
		// If OK, nothing more to do.
		return nil
	case http.StatusForbidden:
		// Handle forbidden access.
		log.Println("🚫 Not authorized. Token expired or revoked.")
		return nil
	case http.StatusTooManyRequests:
		// Handle rate limiting.
		retryAfter := resp.Header.Get("Retry-After")
		log.Printf("⏳ Rate limit exceeded. Retry after %s seconds.", retryAfter)
		return fmt.Errorf("rate limit exceeded, retry after %s seconds", retryAfter)
	default:
		// Handle other unexpected statuses.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		errorMessage := fmt.Sprintf("🗿 Request failed with status code %d: %s", resp.StatusCode, string(body))
		return fmt.Errorf(errorMessage)
	}
}

func FetchPhaseUser(tokenType, appToken, host string) (*http.Response, error) {
	client := createHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	err = handleHTTPResponse(resp)
	if err != nil {
		resp.Body.Close() // Ensure response body is closed on error
		return nil, err
	}

	return resp, nil
}

type AppKeyResponse struct {
	WrappedKeyShare string `json:"wrapped_key_share"`
	Apps            []struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Encryption      string `json:"encryption"`
		EnvironmentKeys []struct {
			ID          string `json:"id"`
			Environment struct {
				ID      string `json:"id"`
				Name    string `json:"name"`
				EnvType string `json:"env_type"`
			} `json:"environment"`
			IdentityKey string  `json:"identity_key"`
			WrappedSeed string  `json:"wrapped_seed"`
			WrappedSalt string  `json:"wrapped_salt"`
			CreatedAt   string  `json:"created_at"`
			UpdatedAt   string  `json:"updated_at"`
			DeletedAt   *string `json:"deleted_at"` // Use pointer to accommodate null
			User        *string `json:"user"`       // Use pointer to accommodate null
		} `json:"environment_keys"`
	} `json:"apps"`
}

func FetchAppKey(tokenType, appToken, host string) (string, error) {
	client := createHTTPClient()
	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header = ConstructHTTPHeaders(tokenType, appToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return "", err
	}

	var jsonResp AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON: %v", err)
	}

	return jsonResp.WrappedKeyShare, nil
}

func FetchPhaseSecrets(tokenType, appToken, environmentID, host, path string) ([]map[string]interface{}, error) {
	client := createHTTPClient()
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

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := handleHTTPResponse(resp); err != nil {
		return nil, err
	}

	var secrets []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("failed to decode JSON response: %v", err)
	}

	return secrets, nil
}

func FetchPhaseSecret(tokenType, appToken, environmentID, host, keyDigest, path string) (map[string]interface{}, error) {
	client := createHTTPClient()
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
		return nil, err
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
	client := createHTTPClient()
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
	req.Header.Set("Environment", environmentID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return handleHTTPResponse(resp)
}

func UpdatePhaseSecrets(tokenType, appToken, environmentID string, secrets []map[string]interface{}, host string) error {
	client := createHTTPClient()
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
	req.Header.Set("Environment", environmentID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return handleHTTPResponse(resp)
}

func DeletePhaseSecrets(tokenType, appToken, environmentID string, secretIDs []string, host string) error {
	client := createHTTPClient()
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
	req.Header.Set("Environment", environmentID)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return handleHTTPResponse(resp)
}

func FetchPhaseSecretsWithDynamic(tokenType, appToken, envID, host, path string, dynamic, lease bool, leaseTTL *int) ([]map[string]interface{}, error) {
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
	if dynamic {
		req.Header.Set("dynamic", "true")
	}
	if lease {
		req.Header.Set("lease", "true")
	}
	if leaseTTL != nil {
		req.Header.Set("lease-ttl", fmt.Sprintf("%d", *leaseTTL))
	}

	body, err := makeRequest(req)
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
