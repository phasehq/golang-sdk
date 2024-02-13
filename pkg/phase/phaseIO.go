package phase

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/jamesruan/sodium"
	"github.com/phasehq/golang-sdk/pkg/api"
	"github.com/phasehq/golang-sdk/pkg/crypto"
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


// PhaseGet fetches and decrypts secrets based on the provided parameters.
func (p *Phase) PhaseGet(envName string, keys []string, appName string, tag string) ([]map[string]string, error) {
	// Fetch user data
	resp, err := api.FetchPhaseUser(p.AppToken, p.Host)
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
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed)
	if err != nil {
		log.Fatalf("Failed to decrypt wrapped seed: %v", err)
		return nil, err
	}

	// Generate environment key pair
	publicKeyHex, privateKeyHex, err := generateEnvKeyPair(decryptedSeed)
	if err != nil {
		log.Fatalf("Failed to generate environment key pair: %v", err)
		return nil, err
	}

	// Fetch secrets
	secrets, err := api.FetchPhaseSecrets(p.AppToken, envKey.Environment.ID, p.Host)
	if err != nil {
		log.Fatalf("Failed to fetch secrets: %v", err)
		return nil, err
	}

	decryptedSecrets := make([]map[string]string, 0)
	for _, secret := range secrets {

		// Decrypt key and value with optional comment
		decryptedKey, decryptedValue, decryptedComment, err := decryptSecret(secret, privateKeyHex, publicKeyHex)
		if err != nil {
			log.Printf("Failed to decrypt secret: %v\n", err)
			continue
		}

		// Check if key matches the provided keys list
		if len(keys) > 0 && !contains(keys, decryptedKey) {
			continue
		}

		// Check for tag match if a tag is provided
		if tag != "" && !tagMatches(secret["tags"].([]string), tag) {
			continue
		}

		result := map[string]string{
			"key":     decryptedKey,
			"value":   decryptedValue,
			"comment": decryptedComment,
		}

		decryptedSecrets = append(decryptedSecrets, result)
	}

	return decryptedSecrets, nil
}

func (p *Phase) GetAllSecrets(envName, appName, tag string) ([]map[string]interface{}, error) {
    // Fetch user data
    resp, err := api.FetchPhaseUser(p.AppToken, p.Host)
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
    decryptedSeed, err := p.Decrypt(envKey.WrappedSeed)
    if err != nil {
        log.Fatalf("Failed to decrypt wrapped seed: %v", err)
        return nil, err
    }

    // Generate environment key pair
    publicKeyHex, privateKeyHex, err := generateEnvKeyPair(decryptedSeed)
    if err != nil {
        log.Fatalf("Failed to generate environment key pair: %v", err)
        return nil, err
    }

    // Fetch secrets
    secrets, err := api.FetchPhaseSecrets(p.AppToken, envKey.Environment.ID, p.Host)
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

            // Check for tag match if a tag is provided
            if tag != "" && !tagMatches(stringTags, tag) {
                continue
            }
        } else if tag != "" {
            // If there are no tags but a tag filter is specified, skip this secret.
            continue
        }

        // Append decrypted secret to result list
        result := map[string]interface{}{
            "key":     decryptedKey,
            "value":   decryptedValue,
            "comment": decryptedComment,
            "tags":    stringTags,
        }

        decryptedSecrets = append(decryptedSecrets, result)
    }

    return decryptedSecrets, nil
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


// Decrypt decrypts the provided ciphertext using the Phase encryption mechanism.
func (p *Phase) Decrypt(ciphertext string) (string, error) {
	// Fetch the wrapped key share using the app token and host
	wrappedKeyShare, err := api.FetchAppKey(p.AppToken, p.Host)
	if err != nil {
		log.Fatalf("Failed to fetch wrapped key share: %v", err)
		return "", err
	}

	// Decode the wrapped key share from hex, not base64
	wrappedKeyShareBytes, err := hex.DecodeString(wrappedKeyShare)
	if err != nil {
		log.Fatalf("Failed to decode wrapped key share from hex: %v", err)
		return "", err
	}

	// Decode Keyshare1UnwrapKey from hex, ensuring it's correctly sized
	keyshare1UnwrapKeyBytes, err := hex.DecodeString(p.Keyshare1UnwrapKey)
	if err != nil {
		log.Fatalf("Failed to decode Keyshare1UnwrapKey from hex: %v", err)
		return "", err
	}
	if len(keyshare1UnwrapKeyBytes) != 32 { // Sodium expects a 32-byte key
		log.Fatalf("Incorrect Keyshare1UnwrapKey size: expected 32 bytes, got %d", len(keyshare1UnwrapKeyBytes))
		return "", err
	}

	keyshare1, err := crypto.DecryptRaw(wrappedKeyShareBytes, sodium.KXSessionKey{Bytes: keyshare1UnwrapKeyBytes})
	if err != nil {
		log.Fatalf("Failed to decrypt wrapped key share: %v", err)
		return "", err
	}

	// Reconstruct the application's private key
	appPrivateKey, err := crypto.ReconstructSecret(p.Keyshare0, string(keyshare1))
	if err != nil {
		log.Fatalf("Failed to reconstruct application's private key: %v", err)
		return "", err
	}

	// Decrypt the ciphertext using the application's private key
	plaintext, err := crypto.DecryptAsymmetric(ciphertext, appPrivateKey, p.PssUserPublicKey)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext: %v", err)
		return "", err
	}

	return plaintext, nil
}

func generateEnvKeyPair(seed string) (publicKeyHex, privateKeyHex string, err error) {
	seedBytes, err := hex.DecodeString(seed)
	if err != nil {
		return "", "", err
	}
	if len(seedBytes) != 32 {
		return "", "", fmt.Errorf("incorrect seed length: expected 32 bytes, got %d", len(seedBytes))
	}

    // Prepare the seed as KXSeed
    var seedKX sodium.KXSeed
    copy(seedKX.Bytes[:], seedBytes)

	// Allocate slice if KXSeed.Bytes is a slice
	seedKX.Bytes = make([]byte, len(seedBytes))
	copy(seedKX.Bytes, seedBytes)

    // Generate key pair from seed
    keyPair := sodium.SeedKXKP(seedKX)

    publicKeyHex = hex.EncodeToString(keyPair.PublicKey.Bytes[:])
    privateKeyHex = hex.EncodeToString(keyPair.SecretKey.Bytes[:])

    return publicKeyHex, privateKeyHex, nil
}
