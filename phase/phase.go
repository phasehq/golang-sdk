package phase

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/phasehq/golang-sdk/v2/phase/crypto"
	"github.com/phasehq/golang-sdk/v2/phase/misc"
	"github.com/phasehq/golang-sdk/v2/phase/network"
)

// Phase config
type Phase struct {
	prefix             string
	pesVersion         string
	AppToken           string
	pssUserPublicKey   string
	keyshare0          string
	keyshare1UnwrapKey string
	Host               string
	Debug              bool
	TokenType          string
	IsServiceToken     bool
	IsUserToken        bool
	offlineConfig      *OfflineConfig
}

// Return when a secret key does not exist at the specified path.
type ErrSecretNotFound struct {
	Key  string
	Path string
}

func (e *ErrSecretNotFound) Error() string {
	return fmt.Sprintf("secret '%s' not found in path '%s'", e.Key, e.Path)
}

// debugf logs a message only when Debug mode is enabled.
// Callers can redirect output via log.SetOutput().
func (p *Phase) debugf(format string, args ...interface{}) {
	if p.Debug {
		log.Printf("[phase] "+format, args...)
	}
}

// SecretType constants
const (
	SecretTypeSecret = "secret" // Default: standard encrypted secret
	SecretTypeSealed = "sealed" // Write-only: value cannot be read back in the Console after creation
	SecretTypeConfig = "config" // Non-sensitive configuration value
)

// ValidSecretTypes is the set of allowed secret type values.
var ValidSecretTypes = map[string]bool{
	SecretTypeSecret: true,
	SecretTypeSealed: true,
	SecretTypeConfig: true,
}

// ValidateSecretType returns an error if secretType is non-empty and not a recognized secret type.
func ValidateSecretType(secretType string) error {
	if secretType != "" && !ValidSecretTypes[secretType] {
		return fmt.Errorf("unsupported secret type: %s. Supported types: %s, %s, %s", secretType, SecretTypeSecret, SecretTypeSealed, SecretTypeConfig)
	}
	return nil
}

// Decrypted secrets from API response
type SecretResult struct {
	Key          string   `json:"key"`
	Value        string   `json:"value"`
	Comment      string   `json:"comment"`
	Path         string   `json:"path"`
	Type         string   `json:"type"`
	Application  string   `json:"application"`
	Environment  string   `json:"environment"`
	Tags         []string `json:"tags"`
	Overridden   bool     `json:"overridden"`
	IsDynamic    bool     `json:"is_dynamic,omitempty"`
	DynamicGroup string   `json:"dynamic_group,omitempty"`
}

// KeyValuePair represents a key-value pair for secret creation
type KeyValuePair struct {
	Key   string
	Value string
	Type  string
}

// GET SECRETS
type GetOptions struct {
	EnvName  string
	AppName  string
	AppID    string
	Keys     []string
	Tag      string
	Path     string
	Dynamic  bool
	Lease    bool
	LeaseTTL *int
	Raw      bool // When true, return raw secret values without resolving references
}

// CREATE SECRETS
type CreateOptions struct {
	KeyValuePairs []KeyValuePair
	EnvName       string
	AppName       string
	AppID         string
	Path          string
	OverrideValue string
	Type          string
}

// UPDATE SECRETS
type UpdateOptions struct {
	EnvName         string
	AppName         string
	AppID           string
	Key             string
	Value           string
	SourcePath      string
	DestinationPath string
	Override        bool
	ToggleOverride  bool
	Type            string
}

// DELETE SECRETS
type DeleteOptions struct {
	EnvName      string
	AppName      string
	AppID        string
	KeysToDelete []string
	Path         string
}

// Create a new Phase instance from a token (service or user), host, and debug flag
func New(token, host string, debug bool) (*Phase, error) {
	if host == "" {
		host = misc.PhaseCloudAPIHost
	}

	p := &Phase{
		Host:  host,
		Debug: debug,
	}

	serviceMatches := misc.PssServicePattern.FindStringSubmatch(token)
	userMatches := misc.PssUserPattern.FindStringSubmatch(token)

	if len(serviceMatches) == 6 {
		p.IsServiceToken = true
		version := serviceMatches[1]
		p.prefix = "pss_service"
		p.pesVersion = "v" + version
		p.AppToken = serviceMatches[2]
		p.pssUserPublicKey = serviceMatches[3]
		p.keyshare0 = serviceMatches[4]
		p.keyshare1UnwrapKey = serviceMatches[5]
		if version == "2" {
			p.TokenType = "ServiceAccount"
		} else {
			p.TokenType = "Service"
		}
	} else if len(userMatches) == 6 {
		p.IsUserToken = true
		version := userMatches[1]
		p.prefix = "pss_user"
		p.pesVersion = "v" + version
		p.AppToken = userMatches[2]
		p.pssUserPublicKey = userMatches[3]
		p.keyshare0 = userMatches[4]
		p.keyshare1UnwrapKey = userMatches[5]
		p.TokenType = "User"
	} else {
		tokenType := "service token"
		if strings.Contains(token, "pss_user") {
			tokenType = "user token"
		}
		return nil, fmt.Errorf("invalid Phase %s", tokenType)
	}

	return p, nil
}

// Decrypt decrypts a wrapped ciphertext using the Phase encryption mechanism.
func (p *Phase) Decrypt(phaseCiphertext string, wrappedKeyShare string) (string, error) {
	segments := strings.Split(phaseCiphertext, ":")
	if len(segments) != 4 || segments[0] != "ph" {
		return "", fmt.Errorf("ciphertext is invalid")
	}

	if wrappedKeyShare == "" {
		return "", fmt.Errorf("wrapped key share is empty")
	}

	wrappedKeyShareBytes, err := hex.DecodeString(wrappedKeyShare)
	if err != nil {
		return "", fmt.Errorf("failed to decode wrapped key share: %w", err)
	}

	unwrapKeyBytes, err := hex.DecodeString(p.keyshare1UnwrapKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode keyshare1 unwrap key: %w", err)
	}
	defer crypto.ZeroBytes(unwrapKeyBytes)

	var unwrapKey [32]byte
	copy(unwrapKey[:], unwrapKeyBytes)
	defer crypto.ZeroBytes(unwrapKey[:])

	keyshare1Bytes, err := crypto.DecryptRaw(wrappedKeyShareBytes, unwrapKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt wrapped key share: %w", err)
	}
	defer crypto.ZeroBytes(keyshare1Bytes)

	appPrivKey, err := crypto.ReconstructSecret(p.keyshare0, string(keyshare1Bytes))
	if err != nil {
		return "", fmt.Errorf("failed to reconstruct app private key: %w", err)
	}

	plaintext, err := crypto.DecryptAsymmetric(phaseCiphertext, appPrivKey, p.pssUserPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Find the environment key for the given environment ID - to be used to decrypt secrets inside of a given environment
func (p *Phase) findMatchingEnvironmentKey(userData *misc.AppKeyResponse, envID string) *misc.EnvironmentKey {
	for _, app := range userData.Apps {
		for _, envKey := range app.EnvironmentKeys {
			if envKey.Environment.ID == envID {
				return &envKey
			}
		}
	}
	return nil
}

// GET SECRETS
func (p *Phase) Get(opts GetOptions) ([]SecretResult, error) {
	results, err := p.fetchSecrets(opts)
	if err != nil {
		return nil, err
	}

	if !opts.Raw {
		// Resolve secret references
		ResetSecretsCache()
		for i, secret := range results {
			if secret.Value == "" {
				continue
			}
			resolvedValue, err := ResolveAllSecrets(secret.Value, results, p, secret.Application, secret.Environment)
			if err != nil {
				p.debugf("failed to resolve references in key %s: %v", secret.Key, err)
				continue // Keep original unresolved value
			}
			results[i].Value = resolvedValue
		}
	}

	return results, nil
}

// fetchSecrets fetches and decrypts secrets without resolving references.
// When OfflineConfig is set, encrypted API responses are cached to disk on success
// and served from cache when the network is unavailable.
func (p *Phase) fetchSecrets(opts GetOptions) ([]SecretResult, error) {
	cfg := p.offlineConfig
	offline := cfg != nil && cfg.Offline

	// --- Step 1: Get user data (from network or cache) ---
	var userData misc.AppKeyResponse

	if offline {
		cached, err := cacheRead(userDataCachePath(cfg.CacheDir))
		if err != nil {
			return nil, fmt.Errorf("offline mode: no cached user data available: %w", err)
		}
		if err := json.Unmarshal(cached, &userData); err != nil {
			return nil, fmt.Errorf("offline mode: failed to decode cached user data: %w", err)
		}
	} else {
		resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.Host)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
			return nil, fmt.Errorf("failed to decode user data: %w", err)
		}
		// Cache user data on success
		if cfg != nil {
			if data, err := json.Marshal(&userData); err == nil {
				_ = cacheWrite(userDataCachePath(cfg.CacheDir), data)
			}
		}
	}

	// --- Step 2: Resolve app/env context ---
	appName, _, envName, envID, publicKey, err := misc.PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return nil, err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return nil, fmt.Errorf("no environment found with id: %s", envID)
	}

	// Decrypt wrapped seed to get env keypair
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed, userData.WrappedKeyShare)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wrapped seed: %w", err)
	}

	_, envPrivKey, err := crypto.GenerateEnvKeyPair(decryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate env key pair: %w", err)
	}

	// Compute key digest for single-key lookups (only when online — cache stores full env)
	var keyDigest string
	if !offline && len(opts.Keys) == 1 {
		decryptedSalt, saltErr := p.Decrypt(envKey.WrappedSalt, userData.WrappedKeyShare)
		if saltErr == nil {
			keyDigest, _ = crypto.Blake2bDigest(opts.Keys[0], decryptedSalt)
		}
	}

	// --- Step 3: Get encrypted secrets (from network or cache) ---
	var secrets []map[string]interface{}

	if offline {
		cached, err := cacheRead(secretsCachePath(cfg.CacheDir, envName, appName, opts.AppID, opts.Path))
		if err != nil {
			return nil, fmt.Errorf("offline mode: no cached secrets for environment '%s': %w", envName, err)
		}
		if err := json.Unmarshal(cached, &secrets); err != nil {
			return nil, fmt.Errorf("offline mode: failed to decode cached secrets: %w", err)
		}
	} else {
		var fetchErr error
		if opts.Dynamic {
			secrets, fetchErr = network.FetchPhaseSecretsWithDynamic(p.TokenType, p.AppToken, envID, p.Host, opts.Path, keyDigest, true, opts.Lease, opts.LeaseTTL)
		} else {
			secrets, fetchErr = network.FetchPhaseSecrets(p.TokenType, p.AppToken, envID, p.Host, opts.Path, keyDigest)
		}
		if fetchErr != nil {
			return nil, fmt.Errorf("failed to fetch secrets: %w", fetchErr)
		}
		// Only cache full-env fetches — single-key fetches (keyDigest != "") return
		// a subset and would overwrite the complete cache file.
		if cfg != nil && keyDigest == "" {
			if data, err := json.Marshal(secrets); err == nil {
				_ = cacheWrite(secretsCachePath(cfg.CacheDir, envName, appName, opts.AppID, opts.Path), data)
			}
		}
	}

	// --- Step 4: Decrypt secrets (shared path for online and offline) ---
	var results []SecretResult
	for _, secret := range secrets {
		// Handle dynamic secrets
		secretType, _ := secret["type"].(string)
		if secretType == "dynamic" {
			if offline {
				name, _ := secret["name"].(string)
				if name == "" {
					name = "unknown"
				}
				fmt.Fprintf(os.Stderr, "⚠️ Offline mode: dynamic secret '%s' requires network access, skipping\n", name)
				continue
			}
			dynamicResults := processDynamicSecret(secret, envPrivKey, publicKey, appName, envName, opts)
			results = append(results, dynamicResults...)
			continue
		}

		// Check tag filter
		if opts.Tag != "" {
			secretTags := misc.ExtractStringSlice(secret, "tags")
			if !misc.TagMatches(secretTags, opts.Tag) {
				continue
			}
		}

		// Determine if override is active
		override, hasOverride := secret["override"].(map[string]interface{})
		useOverride := hasOverride && override != nil && misc.GetBool(override, "is_active")

		keyToDecrypt, _ := secret["key"].(string)
		var valueToDecrypt string
		if useOverride {
			valueToDecrypt, _ = override["value"].(string)
		} else {
			valueToDecrypt, _ = secret["value"].(string)
		}
		commentToDecrypt, _ := secret["comment"].(string)

		decryptedKey, err := crypto.DecryptAsymmetric(keyToDecrypt, envPrivKey, publicKey)
		if err != nil {
			p.debugf("failed to decrypt key: %v", err)
			continue
		}

		decryptedValue, err := crypto.DecryptAsymmetric(valueToDecrypt, envPrivKey, publicKey)
		if err != nil {
			p.debugf("failed to decrypt value for key %s: %v", decryptedKey, err)
			continue
		}

		var decryptedComment string
		if commentToDecrypt != "" {
			decryptedComment, _ = crypto.DecryptAsymmetric(commentToDecrypt, envPrivKey, publicKey)
		}

		secretPath, _ := secret["path"].(string)
		if secretPath == "" {
			secretPath = "/"
		}

		secretTags := misc.ExtractStringSlice(secret, "tags")
		if secretTags == nil {
			secretTags = []string{}
		}

		// Extract secret type (defaults to "secret" for backwards compatibility)
		sType, _ := secret["type"].(string)
		if sType == "" || sType == "static" {
			sType = "secret"
		}

		result := SecretResult{
			Key:         decryptedKey,
			Value:       decryptedValue,
			Overridden:  useOverride,
			Tags:        secretTags,
			Comment:     decryptedComment,
			Path:        secretPath,
			Type:        sType,
			Application: appName,
			Environment: envName,
		}

		// Filter by keys if specified
		if len(opts.Keys) > 0 {
			found := false
			for _, k := range opts.Keys {
				if k == decryptedKey {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// CREATE SECRETS
func (p *Phase) Create(opts CreateOptions) error {
	if p.offlineConfig != nil && p.offlineConfig.Offline {
		return fmt.Errorf("cannot create secrets in offline mode")
	}
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.Host)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return fmt.Errorf("failed to decode user data: %w", err)
	}

	_, _, _, envID, publicKey, err := misc.PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return fmt.Errorf("no environment found with id: %s", envID)
	}

	decryptedSalt, err := p.Decrypt(envKey.WrappedSalt, userData.WrappedKeyShare)
	if err != nil {
		return fmt.Errorf("failed to decrypt wrapped salt: %w", err)
	}

	path := opts.Path
	if path == "" {
		path = "/"
	}

	var secrets []map[string]interface{}
	for _, pair := range opts.KeyValuePairs {
		encryptedKey, err := crypto.EncryptAsymmetric(pair.Key, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt key: %w", err)
		}

		encryptedValue, err := crypto.EncryptAsymmetric(pair.Value, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}

		keyDigest, err := crypto.Blake2bDigest(pair.Key, decryptedSalt)
		if err != nil {
			return fmt.Errorf("failed to generate key digest: %w", err)
		}

		secret := map[string]interface{}{
			"key":       encryptedKey,
			"keyDigest": keyDigest,
			"value":     encryptedValue,
			"path":      path,
			"tags":      []string{},
			"comment":   "",
		}

		// Set secret type: per-pair type takes precedence, then option-level type
		secretType := pair.Type
		if secretType == "" {
			secretType = opts.Type
		}
		if secretType != "" {
			secret["type"] = secretType
		}

		if opts.OverrideValue != "" {
			encryptedOverride, err := crypto.EncryptAsymmetric(opts.OverrideValue, publicKey)
			if err != nil {
				return fmt.Errorf("failed to encrypt override value: %w", err)
			}
			secret["override"] = map[string]interface{}{
				"value":    encryptedOverride,
				"isActive": true,
			}
		}

		secrets = append(secrets, secret)
	}

	return network.CreatePhaseSecrets(p.TokenType, p.AppToken, envID, secrets, p.Host)
}

// UPDATE SECRETS
func (p *Phase) Update(opts UpdateOptions) error {
	if p.offlineConfig != nil && p.offlineConfig.Offline {
		return fmt.Errorf("cannot update secrets in offline mode")
	}
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.Host)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return fmt.Errorf("failed to decode user data: %w", err)
	}

	_, _, _, envID, publicKey, err := misc.PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return fmt.Errorf("no environment found with id: %s", envID)
	}

	// Fetch secrets from source path
	sourcePath := opts.SourcePath
	secrets, err := network.FetchPhaseSecrets(p.TokenType, p.AppToken, envID, p.Host, sourcePath, "")
	if err != nil {
		return fmt.Errorf("failed to fetch secrets: %w", err)
	}

	// Decrypt seed to get env keypair
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed, userData.WrappedKeyShare)
	if err != nil {
		return fmt.Errorf("failed to decrypt wrapped seed: %w", err)
	}

	_, envPrivKey, err := crypto.GenerateEnvKeyPair(decryptedSeed)
	if err != nil {
		return fmt.Errorf("failed to generate env key pair: %w", err)
	}

	// Find matching secret, filtering by source path when specified.
	var matchingSecret map[string]interface{}
	for _, secret := range secrets {
		if sourcePath != "" {
			secretPath, _ := secret["path"].(string)
			if secretPath != sourcePath {
				continue
			}
		}
		encKey, _ := secret["key"].(string)
		dk, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey)
		if err != nil {
			continue
		}
		if dk == opts.Key {
			matchingSecret = secret
			break
		}
	}

	if matchingSecret == nil {
		return &ErrSecretNotFound{Key: opts.Key, Path: sourcePath}
	}

	// Encrypt key
	encryptedKey, err := crypto.EncryptAsymmetric(opts.Key, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %w", err)
	}

	// Encrypt value — if no new value provided, reuse existing encrypted value
	var encryptedValue string
	if opts.Value != "" {
		encryptedValue, err = crypto.EncryptAsymmetric(opts.Value, publicKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt value: %w", err)
		}
	} else {
		encryptedValue, _ = matchingSecret["value"].(string)
	}

	// Get key digest
	decryptedSalt, err := p.Decrypt(envKey.WrappedSalt, userData.WrappedKeyShare)
	if err != nil {
		return fmt.Errorf("failed to decrypt wrapped salt: %w", err)
	}

	keyDigest, err := crypto.Blake2bDigest(opts.Key, decryptedSalt)
	if err != nil {
		return fmt.Errorf("failed to generate key digest: %w", err)
	}

	// Determine payload value
	payloadValue := encryptedValue
	if opts.Override || opts.ToggleOverride {
		payloadValue, _ = matchingSecret["value"].(string)
	}

	// Determine path
	path := matchingSecret["path"]
	if opts.DestinationPath != "" {
		path = opts.DestinationPath
	}

	secretID, _ := matchingSecret["id"].(string)
	payload := map[string]interface{}{
		"id":        secretID,
		"key":       encryptedKey,
		"keyDigest": keyDigest,
		"value":     payloadValue,
		"tags":      matchingSecret["tags"],
		"comment":   matchingSecret["comment"],
		"path":      path,
	}

	// Set secret type if specified
	if opts.Type != "" {
		payload["type"] = opts.Type
	}

	// Handle override logic
	if opts.ToggleOverride {
		override, hasOverride := matchingSecret["override"].(map[string]interface{})
		if !hasOverride || override == nil {
			return fmt.Errorf("no override found for key '%s'. Create one first with --override", opts.Key)
		}
		currentState := misc.GetBool(override, "is_active")
		payload["override"] = map[string]interface{}{
			"value":    override["value"],
			"isActive": !currentState,
		}
	} else if opts.Override {
		override, hasOverride := matchingSecret["override"].(map[string]interface{})
		if !hasOverride || override == nil {
			payload["override"] = map[string]interface{}{
				"value":    encryptedValue,
				"isActive": true,
			}
		} else {
			v := encryptedValue
			if opts.Value == "" {
				v, _ = override["value"].(string)
			}
			payload["override"] = map[string]interface{}{
				"value":    v,
				"isActive": misc.GetBool(override, "is_active"),
			}
		}
	}

	err = network.UpdatePhaseSecrets(p.TokenType, p.AppToken, envID, []map[string]interface{}{payload}, p.Host)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// DELETE SECRETS
func (p *Phase) Delete(opts DeleteOptions) ([]string, error) {
	if p.offlineConfig != nil && p.offlineConfig.Offline {
		return nil, fmt.Errorf("cannot delete secrets in offline mode")
	}
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.Host)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userData misc.AppKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %w", err)
	}

	_, _, _, envID, publicKey, err := misc.PhaseGetContext(&userData, opts.AppName, opts.EnvName, opts.AppID)
	if err != nil {
		return nil, err
	}

	envKey := p.findMatchingEnvironmentKey(&userData, envID)
	if envKey == nil {
		return nil, fmt.Errorf("no environment found with id: %s", envID)
	}

	// Decrypt seed to get env keypair
	decryptedSeed, err := p.Decrypt(envKey.WrappedSeed, userData.WrappedKeyShare)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt wrapped seed: %w", err)
	}

	_, envPrivKey, err := crypto.GenerateEnvKeyPair(decryptedSeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate env key pair: %w", err)
	}

	// Fetch secrets
	secrets, err := network.FetchPhaseSecrets(p.TokenType, p.AppToken, envID, p.Host, opts.Path, "")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}

	var idsToDelete []string
	var keysNotFound []string

	for _, key := range opts.KeysToDelete {
		found := false
		for _, secret := range secrets {
			if opts.Path != "" {
				secretPath, _ := secret["path"].(string)
				if secretPath != opts.Path {
					continue
				}
			}
			encKey, _ := secret["key"].(string)
			dk, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey)
			if err != nil {
				continue
			}
			if dk == key {
				secretID, _ := secret["id"].(string)
				idsToDelete = append(idsToDelete, secretID)
				found = true
				break
			}
		}
		if !found {
			keysNotFound = append(keysNotFound, key)
		}
	}

	if len(idsToDelete) > 0 {
		if err := network.DeletePhaseSecrets(p.TokenType, p.AppToken, envID, idsToDelete, p.Host); err != nil {
			return nil, fmt.Errorf("failed to delete secrets: %w", err)
		}
	}

	return keysNotFound, nil
}

// Handle dynamic secrets inside of a given environment
func processDynamicSecret(secret map[string]interface{}, envPrivKey, publicKey, appName, envName string, opts GetOptions) []SecretResult {
	var results []SecretResult

	name, _ := secret["name"].(string)
	if name == "" {
		// Fallback: try decrypting the key field
		encKey, _ := secret["key"].(string)
		if encKey != "" {
			if decName, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey); err == nil {
				name = decName
			}
		}
		if name == "" {
			name = "Dynamic secret"
		}
	}
	provider, _ := secret["provider"].(string)
	groupLabel := fmt.Sprintf("%s (%s)", name, provider)

	secretPath, _ := secret["path"].(string)
	if secretPath == "" {
		secretPath = "/"
	}

	credMap := map[string]string{}
	if leaseData, ok := secret["lease"].(map[string]interface{}); ok && leaseData != nil {
		if creds, ok := leaseData["credentials"].([]interface{}); ok {
			for _, c := range creds {
				credEntry, ok := c.(map[string]interface{})
				if !ok {
					continue
				}
				encKey, _ := credEntry["key"].(string)
				encVal, _ := credEntry["value"].(string)
				if encKey == "" {
					continue
				}
				decKey, err := crypto.DecryptAsymmetric(encKey, envPrivKey, publicKey)
				if err != nil {
					continue
				}
				decVal := ""
				if encVal != "" {
					decVal, _ = crypto.DecryptAsymmetric(encVal, envPrivKey, publicKey)
				}
				credMap[decKey] = decVal
			}
		}
	}

	keyMap, ok := secret["key_map"].([]interface{})
	if !ok {
		return results
	}

	for _, km := range keyMap {
		entry, ok := km.(map[string]interface{})
		if !ok {
			continue
		}
		encKeyName, _ := entry["key_name"].(string)
		if encKeyName == "" {
			continue
		}
		decKeyName, err := crypto.DecryptAsymmetric(encKeyName, envPrivKey, publicKey)
		if err != nil {
			continue
		}

		value := ""
		if v, exists := credMap[decKeyName]; exists {
			value = v
		}

		result := SecretResult{
			Key:          decKeyName,
			Value:        value,
			Path:         secretPath,
			Application:  appName,
			Environment:  envName,
			IsDynamic:    true,
			DynamicGroup: groupLabel,
		}

		if len(opts.Keys) > 0 {
			found := false
			for _, k := range opts.Keys {
				if k == decKeyName {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		results = append(results, result)
	}

	return results
}
