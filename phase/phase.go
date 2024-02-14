package phase

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/phasehq/golang-sdk/phase/crypto"
	"github.com/phasehq/golang-sdk/phase/network"
)

// Phase struct to hold parsed service token information and host.
type Phase struct {
	Prefix           string
	PesVersion       string
	AppToken         string
	PssUserPublicKey string
	Keyshare0        string
	Keyshare1UnwrapKey string
	Host             string
}

// Init initializes a new instance of Phase with the provided service token and host.
func Init(serviceToken, host string) *Phase {
	// Split the service token by ':' to extract its components.
	parts := strings.Split(serviceToken, ":")
	if len(parts) != 6 {
		log.Fatalf("Service token format is invalid: expected 6 parts, got %d", len(parts))
	}

	// Create a new Phase instance with parsed service token components.
	return &Phase{
		Prefix:           parts[0],
		PesVersion:       parts[1],
		AppToken:         parts[2],
		PssUserPublicKey: parts[3],
		Keyshare0:        parts[4],
		Keyshare1UnwrapKey: parts[5],
		Host:             host,
	}
}

type Environment struct {
    ID      string `json:"id"`
    Name    string `json:"name"`
    EnvType string `json:"env_type"`
}

type EnvironmentKey struct {
    ID           string      `json:"id"`
    Environment  Environment `json:"environment"`
    IdentityKey  string      `json:"identity_key"`
    WrappedSeed  string      `json:"wrapped_seed"`
    WrappedSalt  string      `json:"wrapped_salt"`
    CreatedAt    string      `json:"created_at"`
    UpdatedAt    string      `json:"updated_at"`
    DeletedAt    *string     `json:"deleted_at"`
    User         *string     `json:"user"`
}

type App struct {
    ID              string          `json:"id"`
    Name            string          `json:"name"`
    Encryption      string          `json:"encryption"`
    EnvironmentKeys []EnvironmentKey `json:"environment_keys"`
}

type AppKeyResponse struct {
    WrappedKeyShare string `json:"wrapped_key_share"`
    Apps            []App  `json:"apps"`
}

// UpdateSecretOptions holds all the options for updating a secret.
type UpdateSecretOptions struct {
    EnvName    string
    AppName    string
    Key        string
    Value      string
    Path       string
}

func (p *Phase) PhaseGet(envName, appName, keyToFind, tag, path string) (*map[string]interface{}, error) {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        log.Printf("Failed to fetch user data: %v", err)
        return nil, err
    }
    defer resp.Body.Close()

    var userData AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        log.Printf("Failed to decode user data: %v", err)
        return nil, err
    }

    envKey, err := findEnvironmentKey(&userData, envName, appName)
    if err != nil {
        log.Printf("Failed to find environment key: %v", err)
        return nil, err
    }

    decryptedSeed, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSeed, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        log.Printf("Failed to decrypt wrapped seed: %v", err)
        return nil, err
    }
    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        log.Printf("Failed to decrypt wrapped salt: %v", err)
        return nil, err
    }

    publicKeyHex, privateKeyHex, err := crypto.GenerateEnvKeyPair(decryptedSeed)
    if err != nil {
        log.Printf("Failed to generate environment key pair: %v", err)
        return nil, err
    }

    keyDigest, err := crypto.Blake2bDigest(keyToFind, decryptedSalt)
    if err != nil {
        log.Printf("Failed to generate key digest: %v", err)
        return nil, err
    }

    // Fetch a single secret based on keyDigest and optional path
    secret, err := network.FetchPhaseSecret(p.AppToken, envKey.Environment.ID, p.Host, keyDigest, path)
    if err != nil {
        log.Printf("Failed to fetch secret: %v", err)
        return nil, err
    }

    decryptedKey, decryptedValue, decryptedComment, err := decryptSecret(secret, privateKeyHex, publicKeyHex)
    if err != nil {
        log.Printf("Failed to decrypt secret: %v", err)
        return nil, err
    }

    // Verify tag match if a tag is provided
    var stringTags []string
    if tag != "" {
        if secretTags, ok := secret["tags"].([]interface{}); ok {
            for _, tagInterface := range secretTags {
                if tagStr, ok := tagInterface.(string); ok {
                    stringTags = append(stringTags, tagStr)
                }
            }
            if !tagMatches(stringTags, tag) {
                return nil, fmt.Errorf("secret with key '%s' found, but doesn't match the provided tag '%s'", keyToFind, tag)
            }
        }
    }

    // Extract the path directly from the secret map
    secretPath, _ := secret["path"].(string)

    result := &map[string]interface{}{
        "key":     decryptedKey,
        "value":   decryptedValue,
        "comment": decryptedComment,
        "tags":    stringTags,
        "path":    secretPath,
    }

    return result, nil
}

func (p *Phase) GetAllSecrets(envName, appName, tag, path string) ([]map[string]interface{}, error) {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        log.Fatalf("Failed to fetch user data: %v", err)
        return nil, err
    }
    defer resp.Body.Close()

    var userData AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        log.Fatalf("Failed to decode user data: %v", err)
        return nil, err
    }

    // Identify the correct environment and application
    envKey, err := findEnvironmentKey(&userData, envName, appName)
    if err != nil {
        log.Fatalf("Failed to find environment key: %v", err)
        return nil, err
    }

    // Decrypt the wrapped seed
    decryptedSeed, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSeed, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        log.Fatalf("Failed to decrypt wrapped seed: %v", err)
        return nil, err
    }

    // Generate environment key pair
    publicKeyHex, privateKeyHex, err := crypto.GenerateEnvKeyPair(decryptedSeed)
    if err != nil {
        log.Fatalf("Failed to generate environment key pair: %v", err)
        return nil, err
    }

    // Fetch secrets with optional path filtering
    secrets, err := network.FetchPhaseSecrets(p.AppToken, envKey.Environment.ID, p.Host, path)
    if err != nil {
        log.Fatalf("Failed to fetch secrets: %v", err)
        return nil, err
    }

    decryptedSecrets := make([]map[string]interface{}, 0)
    for _, secret := range secrets {
        // Decrypt key, value, and optional comment
        decryptedKey, decryptedValue, decryptedComment, err := decryptSecret(secret, privateKeyHex, publicKeyHex)
        if err != nil {
            log.Printf("Failed to decrypt secret: %v\n", err)
            continue
        }

        // Prepare tags for inclusion in result
        var stringTags []string
        if secretTags, ok := secret["tags"].([]interface{}); ok {
            for _, tagInterface := range secretTags {
                if tagStr, ok := tagInterface.(string); ok {
                    stringTags = append(stringTags, tagStr)
                }
            }
        }

        // Check for tag match if a tag is provided
        if tag != "" && !tagMatches(stringTags, tag) {
            continue
        }

        // Extract path directly from the secret map
        path, _ := secret["path"].(string)

        // Append decrypted secret with path to result list
        result := map[string]interface{}{
            "key":     decryptedKey,
            "value":   decryptedValue,
            "comment": decryptedComment,
            "tags":    stringTags,
            "path":    path,
        }

        decryptedSecrets = append(decryptedSecrets, result)
    }

    return decryptedSecrets, nil
}

// CreateSecrets creates new secrets in the Phase KMS for the specified environment and application.
func (p *Phase) CreateSecrets(keyValuePairs []map[string]string, envName, appName string, keyPaths map[string]string) error {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        log.Fatalf("Failed to fetch user data: %v", err)
        return err
    }
    defer resp.Body.Close()

    var userData AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        log.Fatalf("Failed to decode user data: %v", err)
        return err
    }

    _, envID, publicKey, err := phaseGetContext(&userData, appName, envName)
    if err != nil {
        log.Fatalf("Failed to get context: %v", err)
        return err
    }

    // Identify the correct environment and application
    envKey, err := findEnvironmentKey(&userData, envName, appName)
    if err != nil {
        log.Printf("Failed to find environment key: %v", err)
        return err
    }

    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        log.Fatalf("Failed to decrypt wrapped salt: %v", err)
        return err
    }

    secrets := make([]map[string]interface{}, 0)
    for _, pair := range keyValuePairs {
        for key, value := range pair {
            encryptedKey, err := crypto.EncryptAsymmetric(key, publicKey)
            if err != nil {
                log.Printf("Failed to encrypt key: %v\n", err)
                continue
            }

            encryptedValue, err := crypto.EncryptAsymmetric(value, publicKey)
            if err != nil {
                log.Printf("Failed to encrypt value: %v\n", err)
                continue
            }

            keyDigest, err := crypto.Blake2bDigest(key, decryptedSalt)
            if err != nil {
                log.Printf("Failed to generate key digest: %v\n", err)
                continue
            }

            // Determine the path for the secret, default to "/" if not specified
            path, ok := keyPaths[key]
            if !ok {
                path = "/" // Default path if not provided
            }

            secret := map[string]interface{}{
                "key":       encryptedKey,
                "keyDigest": keyDigest,
                "value":     encryptedValue,
                "path":      path,
                "tags":      []string{},
                "comment":   "",
            }
            secrets = append(secrets, secret)
        }
    }

    return network.CreatePhaseSecrets(p.AppToken, envID, secrets, p.Host)
}

func (p *Phase) UpdateSecret(opts UpdateSecretOptions) error {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        log.Fatalf("Failed to fetch user data: %v", err)
        return err
    }
    defer resp.Body.Close()

    var userData AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        log.Fatalf("Failed to decode user data: %v", err)
        return err
    }

    envKey, err := findEnvironmentKey(&userData, opts.EnvName, opts.AppName)
    if err != nil {
        log.Fatalf("Failed to find environment key: %v", err)
        return err
    }

    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        log.Fatalf("Failed to decrypt wrapped salt: %v", err)
        return err
    }

    // Generate key digest
    keyDigest, err := crypto.Blake2bDigest(opts.Key, decryptedSalt)
    if err != nil {
        log.Fatalf("Failed to generate key digest: %v", err)
        return err
    }

    // Fetch a single secret based on keyDigest
    secret, err := network.FetchPhaseSecret(p.AppToken, envKey.Environment.ID, p.Host, keyDigest, opts.Path)
    if err != nil {
        log.Printf("Failed to fetch secret: %v", err)
        return err
    }

    publicKeyHex := envKey.IdentityKey

    // Encrypt the key and value with the environment's public key
    encryptedKey, err := crypto.EncryptAsymmetric(opts.Key, publicKeyHex)
    if err != nil {
        log.Fatalf("Failed to encrypt key: %v", err)
        return err
    }

    encryptedValue, err := crypto.EncryptAsymmetric(opts.Value, publicKeyHex)
    if err != nil {
        log.Fatalf("Failed to encrypt value: %v", err)
        return err
    }

    secretID, ok := secret["id"].(string)
    if !ok {
        log.Fatalf("Secret ID is not a string")
        return fmt.Errorf("secret ID is not a string")
    }

    // Default path to "/" if not provided
    if opts.Path == "" {
        opts.Path = "/"
    }

    secretUpdatePayload := map[string]interface{}{
        "id":        secretID,
        "key":       encryptedKey,
        "keyDigest": keyDigest,
        "value":     encryptedValue,
        "path":      opts.Path,
        "tags":      []string{},
        "comment":   "",
    }

    // Perform the update
    err = network.UpdatePhaseSecrets(p.AppToken, envKey.Environment.ID, []map[string]interface{}{secretUpdatePayload}, p.Host)
    if err != nil {
        log.Fatalf("Failed to update secret: %v", err)
        return err
    }

    log.Println("Secret updated successfully")
    return nil
}


// DeleteSecret deletes a secret in Phase KMS based on a key and environment.
func (p *Phase) DeleteSecret(envName, appName, keyToDelete, path string) error {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        log.Fatalf("Failed to fetch user data: %v", err)
        return err
    }
    defer resp.Body.Close()

    var userData AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        log.Fatalf("Failed to decode user data: %v", err)
        return err
    }

    envKey, err := findEnvironmentKey(&userData, envName, appName)
    if err != nil {
        log.Printf("Failed to find environment key: %v", err)
        return err
    }

    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        log.Fatalf("Failed to decrypt wrapped salt: %v", err)
        return err
    }

    // Generate key digest
    keyDigest, err := crypto.Blake2bDigest(keyToDelete, decryptedSalt)
    if err != nil {
        log.Fatalf("Failed to generate key digest: %v", err)
        return err
    }

    // Fetch the specific secret by its key digest and path
    secret, err := network.FetchPhaseSecret(p.AppToken, envKey.Environment.ID, p.Host, keyDigest, path)
    if err != nil {
        log.Printf("Failed to fetch secret: %v", err)
        return err
    }

    secretID, ok := secret["id"].(string)
    if !ok {
        log.Printf("Secret ID is not a string for key: %v", keyToDelete)
        return fmt.Errorf("secret ID is not a string for key: %v", keyToDelete)
    }

    // Perform the delete operation for the found secret ID
    err = network.DeletePhaseSecrets(p.AppToken, envKey.Environment.ID, []string{secretID}, p.Host)
    if err != nil {
        log.Fatalf("Failed to delete secret: %v", err)
        return err
    }

    log.Println("Secret deleted successfully")
    return nil
}

// decryptSecret decrypts a secret's key, value, and optional comment using asymmetric decryption.
func decryptSecret(secret map[string]interface{}, privateKeyHex, publicKeyHex string) (decryptedKey string, decryptedValue string, decryptedComment string, err error) {
    // Decrypt the key
    key, ok := secret["key"].(string)
    if !ok {
        err = fmt.Errorf("key is not a string")
        return
    }
    decryptedKey, err = crypto.DecryptAsymmetric(key, privateKeyHex, publicKeyHex)
    if err != nil {
        log.Printf("Failed to decrypt key: %v\n", err)
        return
    }

    // Decrypt the value
    value, ok := secret["value"].(string)
    if !ok {
        err = fmt.Errorf("value is not a string")
        return
    }
    decryptedValue, err = crypto.DecryptAsymmetric(value, privateKeyHex, publicKeyHex)
    if err != nil {
        log.Printf("Failed to decrypt value: %v\n", err)
        return
    }

    // Decrypt the comment if it exists
    comment, ok := secret["comment"].(string)
    if ok && comment != "" {
        decryptedComment, err = crypto.DecryptAsymmetric(comment, privateKeyHex, publicKeyHex)
        if err != nil {
            log.Printf("Failed to decrypt comment: %v\n", err)
            // We decide not to return an error here because comments are optional and failure to decrypt them
            // should not prevent the rest of the secret data from being used.
            err = nil
        }
    }

    return decryptedKey, decryptedValue, decryptedComment, nil
}


// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
    for _, v := range slice {
        if v == str {
            return true
        }
    }
    return false
}

// phaseGetContext finds the matching application and environment, returning their IDs and the public key.
func phaseGetContext(userData *AppKeyResponse, appName, envName string) (string, string, string, error) {
	for _, app := range userData.Apps {
		if app.Name == appName {
			for _, envKey := range app.EnvironmentKeys {
				if envKey.Environment.Name == envName {
					return app.ID, envKey.Environment.ID, envKey.IdentityKey, nil
				}
			}
		}
	}
	return "", "", "", fmt.Errorf("matching context not found")
}


func findEnvironmentKey(userData *AppKeyResponse, envName, appName string) (*EnvironmentKey, error) {
    for _, app := range userData.Apps {
        if appName == "" || app.Name == appName {
            for _, envKey := range app.EnvironmentKeys {
                if envKey.Environment.Name == envName {
                    return &envKey, nil // This should now match the expected return type
                }
            }
        }
    }
    return nil, fmt.Errorf("environment key not found")
}


// normalizeTag replaces underscores with spaces and converts the string to lower case.
func normalizeTag(tag string) string {
    return strings.ToLower(strings.Replace(tag, "_", " ", -1))
}

// tagMatches checks if the user-provided tag partially matches any of the secret tags.
func tagMatches(secretTags []string, userTag string) bool {
    normalizedUserTag := normalizeTag(userTag)
    for _, tag := range secretTags {
        normalizedSecretTag := normalizeTag(tag)
        if strings.Contains(normalizedSecretTag, normalizedUserTag) {
            return true
        }
    }
    return false
}
