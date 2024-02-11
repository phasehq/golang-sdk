package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"strings"
)

var (
	verifySSL = os.Getenv("PHASE_VERIFY_SSL") != "false"
	phaseDebug = os.Getenv("PHASE_DEBUG") == "true"
)

// ConstructHTTPHeaders constructs common headers for HTTP requests.
func ConstructHTTPHeaders(tokenType, appToken string) http.Header {
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Bearer %s %s", tokenType, appToken))
	headers.Set("User-Agent", GetUserAgent())
	return headers
}

// GetUserAgent constructs a user agent string with details about the CLI version,
// operating system, architecture, and the current user with hostname.
func GetUserAgent() string {
	details := []string{}

	// Example CLI version, replace "v1.0.0" with your actual version retrieval method
	cliVersion := "phase-golang-sdk/v1.0.0"
	details = append(details, cliVersion)

	osType := runtime.GOOS
	osVersion := "" // Go does not directly provide OS version; consider using a third-party package if necessary
	architecture := runtime.GOARCH
	details = append(details, fmt.Sprintf("%s %s %s", osType, osVersion, architecture))

	// Get username and hostname
	currentUser, err := user.Current()
	if err == nil {
		hostname, err := os.Hostname()
		if err == nil {
			userHostString := fmt.Sprintf("%s@%s", currentUser.Username, hostname)
			details = append(details, userHostString)
		}
	}

	userAgentStr := fmt.Sprintf("User-Agent: %s", details)
	return userAgentStr
}

func createHTTPClient() *http.Client {
	verifySSL := os.Getenv("PHASE_VERIFY_SSL") != "false"
	client := &http.Client{}

	if !verifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return client
}


func handleHTTPResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusForbidden {
		log.Println("🚫 Not authorized. Token expired or revoked.")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		// Use io.ReadAll instead of ioutil.ReadAll
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			body = []byte("failed to read response body")
		}
		errorMessage := fmt.Sprintf("🗿 Request failed with status code %d", resp.StatusCode)
		if phaseDebug {
			errorMessage += fmt.Sprintf(": %s", string(body))
		}
		return fmt.Errorf(errorMessage)
	}
	
	return nil
}
// FetchPhaseUser fetches users from the Phase API.
func FetchPhaseUser(tokenType, appToken, host string) (*http.Response, error) {
	client := &http.Client{}
	if !verifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("🗿 Network error: Please check your internet connection. Detail: %v", err)
	}

	err = handleHTTPResponse(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}


// FetchAppKey fetches the application key share from Phase KMS.
func FetchAppKey(tokenType, appToken, host string) (string, error) {
	client := &http.Client{}

	// Configure client for SSL verification based on environment variables
	verifySSL := os.Getenv("PHASE_VERIFY_SSL") != "false"
	if !verifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("network error: please check your internet connection. Detail: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("request failed with status code %d: failed to read response body", resp.StatusCode)
		}
		// Specifically handle the 404 status code as per the Python code
		if resp.StatusCode == http.StatusNotFound {
			return "", fmt.Errorf("the app token is invalid (HTTP status code 404): %s", string(body))
		}
		return "", fmt.Errorf("request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	var jsonResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON from response: %v", err)
	}

	wrappedKeyShare, ok := jsonResp["wrapped_key_share"]
	if !ok {
		return "", fmt.Errorf("wrapped key share not found in the response")
	}

	return wrappedKeyShare, nil
}


// FetchWrappedKeyShare fetches the wrapped application key share from Phase KMS.
func FetchWrappedKeyShare(tokenType, appToken, host string) (string, error) {
	client := &http.Client{}

	// Check if SSL verification should be skipped
	verifySSL := os.Getenv("PHASE_VERIFY_SSL") != "false"
	if !verifySSL {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	url := fmt.Sprintf("%s/service/secrets/tokens/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header = ConstructHTTPHeaders(tokenType, appToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("network error: please check your internet connection. Detail: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("request failed with status code %d: failed to read response body", resp.StatusCode)
		}
		return "", fmt.Errorf("request failed with status code %d: %s", resp.StatusCode, string(body))
	}

	var jsonResp map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
		return "", fmt.Errorf("failed to decode JSON from response: %v", err)
	}

	wrappedKeyShare, ok := jsonResp["wrapped_key_share"]
	if !ok {
		return "", fmt.Errorf("wrapped key share not found in the response")
	}

	return wrappedKeyShare, nil
}

func FetchPhaseSecrets(tokenType, appToken, id, host string) (*http.Response, error) {
	url := fmt.Sprintf("%s/service/secrets/", host)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	headers := ConstructHTTPHeaders(tokenType, appToken)
	headers.Set("Environment", id)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return handleHTTPResponse(resp)
}

func CreatePhaseSecrets(tokenType, appToken, environmentID string, secrets []map[string]interface{}, host string) (*http.Response, error) {
	url := fmt.Sprintf("%s/service/secrets/", host)
	data, err := json.Marshal(map[string][]map[string]interface{}{"secrets": secrets})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	headers := ConstructHTTPHeaders(tokenType, appToken)
	req.Header.Set("Environment", strings.Join(environmentID, ",")) // If multiple values are meant to be a comma-separated list
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return handleHTTPResponse(resp)
}

func DeletePhaseSecrets(tokenType, appToken, environmentID string, secretIDs []string, host string) (*http.Response, error) {
	url := fmt.Sprintf("%s/service/secrets/", host)
	data, err := json.Marshal(map[string][]string{"secrets": secretIDs})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("DELETE", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	headers := ConstructHTTPHeaders(tokenType, appToken)
	headers.Set("Environment", environmentID)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return handleHTTPResponse(resp)
}

