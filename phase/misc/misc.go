package misc

import (
	"fmt"
	"strings"
)

// PhaseGetContext finds the matching application and environment, returning their IDs and the public key.
func PhaseGetContext(userData AppKeyResponse, opts GetContextOptions) (string, string, string, error) {
	for _, app := range userData.Apps {
		if (opts.AppID != "" && app.ID == opts.AppID) || (opts.AppName != "" && app.Name == opts.AppName) {
			for _, envKey := range app.EnvironmentKeys {
				if envKey.Environment.Name == opts.EnvName {
					return app.ID, envKey.Environment.ID, envKey.IdentityKey, nil
				}
			}
		}
	}
	return "", "", "", fmt.Errorf("matching context not found")
}

// FindEnvironmentKey searches for an environment key with case-insensitive matching.
func FindEnvironmentKey(userData AppKeyResponse, opts FindEnvironmentKeyOptions) (*EnvironmentKey, error) {
	lcEnvName := strings.ToLower(strings.TrimSpace(opts.EnvName))

	// If no app specified, try all apps
	if opts.AppName == "" && opts.AppID == "" {
		for _, app := range userData.Apps {
			for _, envKey := range app.EnvironmentKeys {
				if strings.EqualFold(strings.TrimSpace(envKey.Environment.Name), lcEnvName) {
					return &envKey, nil
				}
			}
		}
	} else {
		// Check specific app
		for _, app := range userData.Apps {
			if (opts.AppID != "" && app.ID == opts.AppID) ||
				(opts.AppName != "" && strings.EqualFold(app.Name, opts.AppName)) {

				for _, envKey := range app.EnvironmentKeys {
					if strings.EqualFold(strings.TrimSpace(envKey.Environment.Name), lcEnvName) {
						return &envKey, nil
					}
				}
			}
		}
	}

	// If exact match not found, try partial matches
	for _, app := range userData.Apps {
		for _, envKey := range app.EnvironmentKeys {
			envName := strings.ToLower(strings.TrimSpace(envKey.Environment.Name))
			if strings.Contains(envName, lcEnvName) {
				return &envKey, nil
			}
		}
	}

	return nil, fmt.Errorf("environment key not found for app '%s' (ID: %s) and environment '%s'",
		opts.AppName, opts.AppID, opts.EnvName)
}

// normalizeTag replaces underscores with spaces and converts the string to lower case.
func normalizeTag(tag string) string {
	return strings.ToLower(strings.Replace(tag, "_", " ", -1))
}

// TagMatches checks if the user-provided tag partially matches any of the secret tags.
func TagMatches(secretTags []string, userTag string) bool {
	normalizedUserTag := normalizeTag(userTag)
	for _, tag := range secretTags {
		normalizedSecretTag := normalizeTag(tag)
		if strings.Contains(normalizedSecretTag, normalizedUserTag) {
			return true
		}
	}
	return false
}

// GenerateRandomSecret generates a random secret of the specified type and length.
func GenerateRandomSecret(randomType string, length int) (string, error) {
	if length <= 0 {
		length = 32
	}

	switch randomType {
	case "hex":
		b := make([]byte, length/2+1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b)[:length], nil
	case "alphanumeric":
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		result := make([]byte, length)
		for i := range result {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				return "", err
			}
			result[i] = chars[n.Int64()]
		}
		return string(result), nil
	case "key128":
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	case "key256":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	case "base64":
		b := make([]byte, length)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		encoded := base64.StdEncoding.EncodeToString(b)
		if len(encoded) < length {
			return encoded, nil
		}
		return encoded[:length], nil
	case "base64url":
		b := make([]byte, length)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		encoded := base64.URLEncoding.EncodeToString(b)
		if len(encoded) < length {
			return encoded, nil
		}
		return encoded[:length], nil
	default:
		return "", fmt.Errorf("unsupported random type: %s. Supported types: hex, alphanumeric, base64, base64url, key128, key256", randomType)
	}
}

