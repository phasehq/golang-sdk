package phase

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/phasehq/golang-sdk/phase/crypto"
	"github.com/phasehq/golang-sdk/phase/misc"
	"github.com/phasehq/golang-sdk/phase/network"
)

// Phase struct to hold parsed service token information and host.
type Phase struct {
    Prefix            string
    PesVersion        string
    AppToken          string
    PssUserPublicKey  string
    Keyshare0         string
    Keyshare1UnwrapKey string
    Host              string
    Debug             bool
}

type GetSecretOptions struct {
    EnvName   string
    AppName   string
    KeyToFind string
    Tag       string
    SecretPath string
}

type GetAllSecretsOptions struct {
    EnvName string
    AppName string
    Tag     string
    SecretPath string
}

type CreateSecretsOptions struct {
    KeyValuePairs []map[string]string
    EnvName       string
    AppName       string
    SecretPath    map[string]string
}

type SecretUpdateOptions struct {
    EnvName    string
    AppName    string
    Key        string
    Value      string
    SecretPath string
}

type DeleteSecretOptions struct {
    EnvName     string
    AppName     string
    KeyToDelete string
    SecretPath  string
}

// Init initializes a new instance of Phase with the provided service token, host, and debug flag.
func Init(serviceToken, host string, debug bool) *Phase {
    // Validate the service token against the pattern.
    matches := misc.PssServicePattern.FindStringSubmatch(serviceToken)
    if matches == nil || len(matches) != 6 {
        log.Fatalf("Error: Invalid Phase Service Token.")
    }

    // Use default host if none is specified.
    if host == "" {
        host = misc.PhaseCloudAPIHost
    }

    // Create a new Phase instance with parsed service token components and debug flag.
    return &Phase{
        Prefix:            "pss_service",
        PesVersion:        matches[1],
        AppToken:          matches[2],
        PssUserPublicKey:  matches[3],
        Keyshare0:         matches[4],
        Keyshare1UnwrapKey: matches[5],
        Host:              host,
        Debug:             debug,
    }
}

func (p *Phase) Get(opts GetSecretOptions) (*map[string]interface{}, error) {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch user data: %v", err)
        }
        return nil, err
    }
    defer resp.Body.Close()

    var userData misc.AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        if p.Debug {
            log.Printf("Failed to decode user data: %v", err)
        }
        return nil, err
    }

    envKey, err := misc.FindEnvironmentKey(userData, opts.EnvName, opts.AppName)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to find environment key: %v", err)
        }
        return nil, err
    }

    decryptedSeed, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSeed, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt wrapped seed: %v", err)
        }
        return nil, err
    }
    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt wrapped salt: %v", err)
        }
        return nil, err
    }

    publicKeyHex, privateKeyHex, err := crypto.GenerateEnvKeyPair(decryptedSeed)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to generate environment key pair: %v", err)
        }
        return nil, err
    }

    keyDigest, err := crypto.Blake2bDigest(opts.KeyToFind, decryptedSalt)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to generate key digest: %v", err)
        }
        return nil, err
    }

    // Fetch a single secret based on keyDigest and optional path
    secret, err := network.FetchPhaseSecret(p.AppToken, envKey.Environment.ID, p.Host, keyDigest, opts.SecretPath)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch secret: %v", err)
        }
        return nil, err
    }

    decryptedKey, decryptedValue, decryptedComment, err := crypto.DecryptSecret(secret, privateKeyHex, publicKeyHex)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt secret: %v", err)
        }
        return nil, err
    }

    // Verify tag match if a tag is provided
    var stringTags []string
    if opts.Tag != "" {
        if secretTags, ok := secret["tags"].([]interface{}); ok {
            for _, tagInterface := range secretTags {
                if tagStr, ok := tagInterface.(string); ok {
                    stringTags = append(stringTags, tagStr)
                }
            }
            if !misc.TagMatches(stringTags, opts.Tag) {
                return nil, fmt.Errorf("secret with key '%s' found, but doesn't match the provided tag '%s'", opts.KeyToFind, opts.Tag)
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

    if p.Debug {
        log.Println("Secret fetched successfully")
    }

    return result, nil
}

func (p *Phase) GetAll(opts GetAllSecretsOptions) ([]map[string]interface{}, error) {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch user data: %v", err)
        }
        return nil, err
    }
    defer resp.Body.Close()

    var userData misc.AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        if p.Debug {
            log.Printf("Failed to decode user data: %v", err)
        }
        return nil, err
    }

    // Identify the correct environment and application
    envKey, err := misc.FindEnvironmentKey(userData, opts.EnvName, opts.AppName)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to find environment key: %v", err)
        }
        return nil, err
    }

    // Decrypt the wrapped seed
    decryptedSeed, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSeed, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt wrapped seed: %v", err)
        }
        return nil, err
    }

    // Generate environment key pair
    publicKeyHex, privateKeyHex, err := crypto.GenerateEnvKeyPair(decryptedSeed)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to generate environment key pair: %v", err)
        }
        return nil, err
    }

    // Fetch secrets with optional path filtering
    secrets, err := network.FetchPhaseSecrets(p.AppToken, envKey.Environment.ID, p.Host, opts.SecretPath)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch secrets: %v", err)
        }
        return nil, err
    }

    decryptedSecrets := make([]map[string]interface{}, 0)
    for _, secret := range secrets {
        // Decrypt key, value, and optional comment
        decryptedKey, decryptedValue, decryptedComment, err := crypto.DecryptSecret(secret, privateKeyHex, publicKeyHex)
        if err != nil {
            if p.Debug {
                log.Printf("Failed to decrypt secret: %v\n", err)
            }
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
        if opts.Tag != "" && !misc.TagMatches(stringTags, opts.Tag) {
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

    if p.Debug {
        log.Println("Secrets fetched successfully")
    }

    return decryptedSecrets, nil
}

// CreateSecrets creates new secrets in the Phase KMS for the specified environment and application.
func (p *Phase) Create(opts CreateSecretsOptions) error {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch user data: %v", err)
        }
        return err
    }
    defer resp.Body.Close()

    var userData misc.AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        if p.Debug {
            log.Printf("Failed to decode user data: %v", err)
        }
        return err
    }

    _, envID, publicKey, err := misc.PhaseGetContext(userData, opts.AppName, opts.EnvName)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to get context: %v", err)
        }
        return err
    }

    // Identify the correct environment and application
    envKey, err := misc.FindEnvironmentKey(userData, opts.EnvName, opts.AppName)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to find environment key: %v", err)
        }
        return err
    }

    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt wrapped salt: %v", err)
        }
        return err
    }

    secrets := make([]map[string]interface{}, 0)
    for _, pair := range opts.KeyValuePairs {
        for key, value := range pair {
            encryptedKey, err := crypto.EncryptAsymmetric(key, publicKey)
            if err != nil {
                if p.Debug {
                    log.Printf("Failed to encrypt key: %v\n", err)
                }
                continue
            }

            encryptedValue, err := crypto.EncryptAsymmetric(value, publicKey)
            if err != nil {
                if p.Debug {
                    log.Printf("Failed to encrypt value: %v\n", err)
                }
                continue
            }

            keyDigest, err := crypto.Blake2bDigest(key, decryptedSalt)
            if err != nil {
                if p.Debug {
                    log.Printf("Failed to generate key digest: %v\n", err)
                }
                continue
            }

            // Determine the path for the secret, default to "/" if not specified
            path, ok := opts.SecretPath[key]
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

    // Create the secret
    err = network.CreatePhaseSecrets(p.AppToken, envID, secrets, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to create secret: %v", err)
        }
        return err
    }
    if p.Debug {
        log.Println("Secret created successfully")
    }
    return nil
}

func (p *Phase) Update(opts SecretUpdateOptions) error {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch user data: %v", err)
        }
        return err
    }
    defer resp.Body.Close()

    var userData misc.AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        if p.Debug {
            log.Printf("Failed to decode user data: %v", err)
        }
        return err
    }

    envKey, err := misc.FindEnvironmentKey(userData, opts.EnvName, opts.AppName)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to find environment key: %v", err)
        }
        return err
    }

    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt wrapped salt: %v", err)
        }
        return err
    }

    // Generate key digest
    keyDigest, err := crypto.Blake2bDigest(opts.Key, decryptedSalt)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to generate key digest: %v", err)
        }
        return err
    }

    // Fetch a single secret based on keyDigest
    secret, err := network.FetchPhaseSecret(p.AppToken, envKey.Environment.ID, p.Host, keyDigest, opts.SecretPath)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch secret: %v", err)
        }
        return err
    }

    publicKeyHex := envKey.IdentityKey

    // Encrypt the key and value with the environment's public key
    encryptedKey, err := crypto.EncryptAsymmetric(opts.Key, publicKeyHex)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to encrypt key: %v", err)
        }
        return err
    }

    encryptedValue, err := crypto.EncryptAsymmetric(opts.Value, publicKeyHex)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to encrypt value: %v", err)
        }
        return err
    }

    secretID, ok := secret["id"].(string)
    if !ok {
        return fmt.Errorf("secret ID is not a string")
    }

    // Default path to "/" if not provided
    if opts.SecretPath == "" {
        opts.SecretPath = "/"
    }

    secretUpdatePayload := map[string]interface{}{
        "id":        secretID,
        "key":       encryptedKey,
        "keyDigest": keyDigest,
        "value":     encryptedValue,
        "path":      opts.SecretPath,
        "tags":      []string{},
        "comment":   "",
    }

    // Perform the update
    err = network.UpdatePhaseSecrets(p.AppToken, envKey.Environment.ID, []map[string]interface{}{secretUpdatePayload}, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to update secret: %v", err)
        }
        return err
    }
    if p.Debug {
        log.Println("Secret updated successfully")
    }
    return nil
}

// DeleteSecret deletes a secret in Phase KMS based on a key and environment.
func (p *Phase) Delete(opts DeleteSecretOptions) error {
    // Fetch user data
    resp, err := network.FetchPhaseUser(p.AppToken, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch user data: %v", err)
        }
        return err
    }
    defer resp.Body.Close()

    var userData misc.AppKeyResponse
    if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
        if p.Debug {
            log.Printf("Failed to decode user data: %v", err)
        }
        return err
    }

    envKey, err := misc.FindEnvironmentKey(userData, opts.EnvName, opts.AppName)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to find environment key: %v", err)
        }
        return err
    }

    decryptedSalt, err := crypto.DecryptWrappedKeyShare(envKey.WrappedSalt, p.Keyshare0, p.AppToken, p.Keyshare1UnwrapKey, p.PssUserPublicKey, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to decrypt wrapped salt: %v", err)
        }
        return err
    }

    // Generate key digest
    keyDigest, err := crypto.Blake2bDigest(opts.KeyToDelete, decryptedSalt)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to generate key digest: %v", err)
        }
        return err
    }

    // Fetch the specific secret by its key digest and path
    secret, err := network.FetchPhaseSecret(p.AppToken, envKey.Environment.ID, p.Host, keyDigest, opts.SecretPath)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to fetch secret: %v", err)
        }
        return err
    }

    secretID, ok := secret["id"].(string)
    if !ok {
        return fmt.Errorf("secret ID is not a string for key: %v", opts.KeyToDelete)
    }

    // Perform the delete operation for the found secret ID
    err = network.DeletePhaseSecrets(p.AppToken, envKey.Environment.ID, []string{secretID}, p.Host)
    if err != nil {
        if p.Debug {
            log.Printf("Failed to delete secret: %v", err)
        }
        return err
    }

    if p.Debug {
        log.Println("Secret deleted successfully")
    }
    return nil
}
