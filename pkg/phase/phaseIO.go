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


func (p *Phase) PhaseGet(envName, appName, keyToFind, tag string) ([]map[string]interface{}, error) {
    // Fetch user data
    resp, err := api.FetchPhaseUser(p.AppToken, p.Host)
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

    // Identify the correct environment and application
    envKey, err := findEnvironmentKey(&userData, envName, appName)
    if err != nil {
        log.Printf("Failed to find environment key: %v", err)
        return nil, err
    }

    // Decrypt the wrapped seed
    decryptedSeed, err := p.Decrypt(envKey.WrappedSeed)
    if err != nil {
        log.Printf("Failed to decrypt wrapped seed: %v", err)
        return nil, err
    }

    // Generate environment key pair
    publicKeyHex, privateKeyHex, err := generateEnvKeyPair(decryptedSeed)
    if err != nil {
        log.Printf("Failed to generate environment key pair: %v", err)
        return nil, err
    }

    // Fetch secrets
    secrets, err := api.FetchPhaseSecrets(p.AppToken, envKey.Environment.ID, p.Host)
    if err != nil {
        log.Printf("Failed to fetch secrets: %v", err)
        return nil, err
    }

    var foundSecrets []map[string]interface{}
    keyFound := false

    for _, secret := range secrets {
        decryptedKey, decryptedValue, decryptedComment, err := decryptSecret(secret, privateKeyHex, publicKeyHex)
        if err != nil {
            log.Printf("Failed to decrypt secret: %v\n", err)
            continue
        }

        if decryptedKey == keyToFind {
            keyFound = true

            // Prepare tags for inclusion in result
            var stringTags []string
            if secretTags, ok := secret["tags"].([]interface{}); ok {
                for _, tagInterface := range secretTags {
                    if tagStr, ok := tagInterface.(string); ok {
                        stringTags = append(stringTags, tagStr)
                    }
                }

                // If a tag is provided, ensure it matches.
                if tag != "" && !tagMatches(stringTags, tag) {
                    continue
                }
            }

            result := map[string]interface{}{
                "key":     decryptedKey,
                "value":   decryptedValue,
                "comment": decryptedComment,
                "tags":    stringTags,
            }

            foundSecrets = append(foundSecrets, result)
            break
        }
    }

    if !keyFound {
        log.Printf("Secret with key '%s' not found or could not be decrypted.", keyToFind)
    }

    return foundSecrets, nil
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

// CreateSecrets creates new secrets in the Phase KMS for the specified environment and application.
func (p *Phase) CreateSecrets(keyValuePairs []map[string]string, envName, appName string) error {
	// Fetch user data
	resp, err := api.FetchPhaseUser(p.AppToken, p.Host)
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

	decryptedSalt, err := p.Decrypt(envKey.WrappedSalt)
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

			secret := map[string]interface{}{
				"key":       encryptedKey,
				"keyDigest": keyDigest,
				"value":     encryptedValue,
				"folderId":  nil,
				"tags":      []string{},
				"comment":   "",
			}
			secrets = append(secrets, secret)
		}
	}

	return api.CreatePhaseSecrets(p.AppToken, envID, secrets, p.Host)
}

// UpdateSecret updates a secret in Phase KMS based on key and environment.
func (p *Phase) UpdateSecret(envName, key, value, appName string) error {
	// Fetch user data
	resp, err := api.FetchPhaseUser(p.AppToken, p.Host)
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

	// Fetch existing secrets to find the one matching the key
	secrets, err := api.FetchPhaseSecrets(p.AppToken, envID, p.Host)
	if err != nil {
		log.Fatalf("Failed to fetch secrets: %v", err)
		return err
	}

	// Decrypt the wrapped seed
	envKey, err := findEnvironmentKey(&userData, envName, appName)
	if err != nil {
		log.Fatalf("No environment found with id: %v", envID)
		return err
	}
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed)
	if err != nil {
		log.Fatalf("Failed to decrypt wrapped seed: %v", err)
		return err
	}

	// Generate environment key pair
	_, privateKeyHex, err := generateEnvKeyPair(decryptedSeed)
	if err != nil {
		log.Fatalf("Failed to generate environment key pair: %v", err)
		return err
	}

	var secretUpdatePayload map[string]interface{}
	for _, secret := range secrets {
		decryptedKey, _, _, err := decryptSecret(secret, privateKeyHex, publicKey)
		if err != nil {
			log.Printf("Failed to decrypt secret key: %v\n", err)
			continue
		}

		if decryptedKey == key {
			encryptedKey, err := crypto.EncryptAsymmetric(key, publicKey)
			if err != nil {
				log.Fatalf("Failed to encrypt key: %v", err)
				return err
			}

			encryptedValue, err := crypto.EncryptAsymmetric(value, publicKey)
			if err != nil {
				log.Fatalf("Failed to encrypt value: %v", err)
				return err
			}

			decryptedSalt, err := p.Decrypt(envKey.WrappedSalt)
			if err != nil {
				log.Fatalf("Failed to decrypt wrapped salt: %v", err)
				return err
			}

			keyDigest, err := crypto.Blake2bDigest(key, decryptedSalt)
			if err != nil {
				log.Fatalf("Failed to generate key digest: %v", err)
				return err
			}

			secretID, ok := secret["id"].(string)
			if !ok {
				log.Fatalf("Secret ID is not a string")
				return fmt.Errorf("secret ID is not a string")
			}

			secretUpdatePayload = map[string]interface{}{
				"id":        secretID,
				"key":       encryptedKey,
				"keyDigest": keyDigest,
				"value":     encryptedValue,
				"folderId":  nil,
				"tags":      []string{},
				"comment":   "",
			}
			break
		}
	}

	if secretUpdatePayload == nil {
		log.Printf("Key '%s' doesn't exist.", key)
		return fmt.Errorf("key '%s' doesn't exist", key)
	}

	// Perform the update
	err = api.UpdatePhaseSecrets(p.AppToken, envID, []map[string]interface{}{secretUpdatePayload}, p.Host)
	if err != nil {
		log.Fatalf("Failed to update secret: %v", err)
		return err
	}

	log.Println("Success")
	return nil
}

// DeleteSecrets deletes secrets in Phase KMS based on keys and environment.
func (p *Phase) DeleteSecrets(envName string, keysToDelete []string, appName string) ([]string, error) {
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

	_, envID, publicKey, err := phaseGetContext(&userData, appName, envName)
	if err != nil {
		log.Fatalf("Failed to get context: %v", err)
		return nil, err
	}

	secrets, err := api.FetchPhaseSecrets(p.AppToken, envID, p.Host)
	if err != nil {
		log.Fatalf("Failed to fetch secrets: %v", err)
		return nil, err
	}

    // Identify the correct environment and application
    envKey, err := findEnvironmentKey(&userData, envName, appName)
    if err != nil {
        log.Printf("Failed to find environment key: %v", err)
        return nil, err
    }
	
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed)
	if err != nil {
		log.Fatalf("Failed to decrypt wrapped seed: %v", err)
		return nil, err
	}

	_, privateKeyHex, err := generateEnvKeyPair(decryptedSeed)
	if err != nil {
		log.Fatalf("Failed to generate environment key pair: %v", err)
		return nil, err
	}

	var secretIDsToDelete []string
	keysNotFound := make([]string, 0)

	for _, key := range keysToDelete {
		found := false
		for _, secret := range secrets {
			decryptedKey, _, _, err := decryptSecret(secret, privateKeyHex, publicKey)
			if err != nil {
				log.Printf("Failed to decrypt secret key: %v\n", err)
				continue
			}

			if decryptedKey == key {
				secretID, ok := secret["id"].(string)
				if !ok {
					log.Printf("Secret ID is not a string for key: %v", key)
					continue
				}
				secretIDsToDelete = append(secretIDsToDelete, secretID)
				found = true
				break
			}
		}

		if !found {
			keysNotFound = append(keysNotFound, key)
		}
	}

	if len(secretIDsToDelete) > 0 {
		err = api.DeletePhaseSecrets(p.AppToken, envID, secretIDsToDelete, p.Host)
		if err != nil {
			log.Fatalf("Failed to delete secrets: %v", err)
			return keysNotFound, err
		}
	}

	return keysNotFound, nil
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