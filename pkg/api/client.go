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
)

var (
    verifySSL = os.Getenv("PHASE_VERIFY_SSL") != "false"
    phaseDebug = os.Getenv("PHASE_DEBUG") == "true"
)

func ConstructHTTPHeaders(tokenType, appToken string) http.Header {
    headers := http.Header{}
    headers.Set("Authorization", fmt.Sprintf("Bearer %s %s", tokenType, appToken))
    headers.Set("User-Agent", GetUserAgent())
    return headers
}

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
        body, err := io.ReadAll(resp.Body)
        if err != nil {
            return fmt.Errorf("failed to read response body: %v", err)
        }
        errorMessage := fmt.Sprintf("🗿 Request failed with status code %d: %s", resp.StatusCode, string(body))
        return fmt.Errorf(errorMessage)
    }

    return nil
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

    var jsonResp map[string]string
    if err := json.NewDecoder(resp.Body).Decode(&jsonResp); err != nil {
        return "", fmt.Errorf("failed to decode JSON: %v", err)
    }

    wrappedKeyShare, ok := jsonResp["wrapped_key_share"]
    if !ok {
        return "", fmt.Errorf("wrapped key share not found in response")
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

func FetchPhaseSecrets(tokenType, appToken, environmentID, host string) ([]map[string]interface{}, error) {
    client := createHTTPClient()
    url := fmt.Sprintf("%s/service/secrets/", host)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }

    req.Header = ConstructHTTPHeaders(tokenType, appToken)
    req.Header.Set("Environment", environmentID)

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

