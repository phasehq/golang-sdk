package misc

import (
	"fmt"
	"strings"
)

// phaseGetContext finds the matching application and environment, returning their IDs and the public key.
func PhaseGetContext(userData AppKeyResponse, appName, envName string) (string, string, string, error) {
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

// FindEnvironmentKey searches for an environment key with case-insensitive and partial matching.
func FindEnvironmentKey(userData AppKeyResponse, envName, appName string) (*EnvironmentKey, error) {
    // Convert envName and appName to lowercase for case-insensitive comparison
    lcEnvName := strings.ToLower(envName)
    lcAppName := strings.ToLower(appName)

    for _, app := range userData.Apps {
        // Support partial and case-insensitive matching for appName
        if appName == "" || strings.Contains(strings.ToLower(app.Name), lcAppName) {
            for _, envKey := range app.EnvironmentKeys {
                // Support partial and case-insensitive matching for envName
                if strings.Contains(strings.ToLower(envKey.Environment.Name), lcEnvName) {
                    return &envKey, nil
                }
            }
        }
    }
    return nil, fmt.Errorf("environment key not found for app '%s' and environment '%s'", appName, envName)
}

// normalizeTag replaces underscores with spaces and converts the string to lower case.
func normalizeTag(tag string) string {
    return strings.ToLower(strings.Replace(tag, "_", " ", -1))
}

// tagMatches checks if the user-provided tag partially matches any of the secret tags.
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
