package phase

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var secretRefRegex = regexp.MustCompile(`\$\{([^}]+)\}`)

// secretsCache keyed by "app|env|path" -> key -> value
var (
	secretsCache   = map[string]map[string]string{}
	secretsCacheMu sync.RWMutex
)

// ResetSecretsCache clears the internal referencing cache.
func ResetSecretsCache() {
	secretsCacheMu.Lock()
	secretsCache = map[string]map[string]string{}
	secretsCacheMu.Unlock()
}

func cacheKey(app, env, path string) string {
	path = normalizePath(path)
	return fmt.Sprintf("%s|%s|%s", app, env, path)
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Strip trailing slash (except for root "/")
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func ensureCached(p *Phase, appName, envName, path string) {
	ck := cacheKey(appName, envName, path)

	secretsCacheMu.RLock()
	_, ok := secretsCache[ck]
	secretsCacheMu.RUnlock()
	if ok {
		return
	}

	if p == nil {
		return
	}
	fetched, err := p.fetchSecrets(GetOptions{
		EnvName: envName,
		AppName: appName,
		Path:    normalizePath(path),
	})
	if err != nil {
		return
	}
	bucket := map[string]string{}
	for _, s := range fetched {
		bucket[s.Key] = s.Value
	}

	secretsCacheMu.Lock()
	secretsCache[ck] = bucket
	secretsCacheMu.Unlock()
}

func getFromCache(appName, envName, path, keyName string) (string, bool) {
	ck := cacheKey(appName, envName, path)
	secretsCacheMu.RLock()
	defer secretsCacheMu.RUnlock()
	bucket, ok := secretsCache[ck]
	if !ok {
		return "", false
	}
	val, ok := bucket[keyName]
	return val, ok
}

func splitPathAndKey(ref string) (string, string) {
	lastSlash := strings.LastIndex(ref, "/")
	if lastSlash != -1 {
		path := ref[:lastSlash]
		key := ref[lastSlash+1:]
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return path, key
	}
	return "/", ref
}

func parseReferenceContext(ref, currentApp, currentEnv string) (appName, envName, path, keyName string, err error) {
	appName = currentApp
	envName = currentEnv
	refBody := ref

	isCrossApp := false
	if strings.Contains(refBody, "::") {
		isCrossApp = true
		parts := strings.SplitN(refBody, "::", 2)
		appName = parts[0]
		refBody = parts[1]
	}

	if strings.Contains(refBody, ".") {
		parts := strings.SplitN(refBody, ".", 2)
		envName = parts[0]
		refBody = parts[1]
		if isCrossApp && envName == "" {
			return "", "", "", "", fmt.Errorf("invalid reference '%s': cross-app references must specify an environment", ref)
		}
	} else if isCrossApp {
		return "", "", "", "", fmt.Errorf("invalid reference '%s': cross-app references must specify an environment", ref)
	}

	path, keyName = splitPathAndKey(refBody)
	return
}

// ResolveAllSecrets resolves all ${...} references in a value string.
func ResolveAllSecrets(value string, allSecrets []SecretResult, p *Phase, currentApp, currentEnv string) (string, error) {
	return resolveAllSecretsInternal(value, allSecrets, p, currentApp, currentEnv, nil)
}

func resolveAllSecretsInternal(value string, allSecrets []SecretResult, p *Phase, currentApp, currentEnv string, visited map[string]bool) (string, error) {
	if visited == nil {
		visited = map[string]bool{}
	}

	// Build in-memory lookup: env -> path -> key -> value
	// Normalize paths so they match what parseReferenceContext produces (no trailing slash).
	secretsDict := map[string]map[string]map[string]string{}
	for _, s := range allSecrets {
		p := normalizePath(s.Path)
		if _, ok := secretsDict[s.Environment]; !ok {
			secretsDict[s.Environment] = map[string]map[string]string{}
		}
		if _, ok := secretsDict[s.Environment][p]; !ok {
			secretsDict[s.Environment][p] = map[string]string{}
		}
		secretsDict[s.Environment][p][s.Key] = s.Value
	}

	refs := secretRefRegex.FindAllStringSubmatch(value, -1)
	if len(refs) == 0 {
		return value, nil
	}

	// Prefetch caches
	seen := map[string]bool{}
	for _, match := range refs {
		ref := match[1]
		app, env, path, _, err := parseReferenceContext(ref, currentApp, currentEnv)
		if err != nil {
			return "", fmt.Errorf("failed to resolve reference ${%s}: %w", ref, err)
		}
		combo := fmt.Sprintf("%s|%s|%s", app, env, path)
		if !seen[combo] {
			seen[combo] = true
			ensureCached(p, app, env, path)
		}
	}

	// Resolve each reference and collect results
	type resolvedRef struct {
		fullRef     string
		resolvedVal string
	}
	var resolutions []resolvedRef

	locs := secretRefRegex.FindAllStringIndex(value, -1)
	for i, match := range refs {
		ref := match[1]

		app, env, path, keyName, err := parseReferenceContext(ref, currentApp, currentEnv)
		if err != nil {
			return "", fmt.Errorf("failed to resolve reference ${%s}: %w", ref, err)
		}

		canonical := fmt.Sprintf("%s|%s|%s|%s", app, env, path, keyName)
		if visited[canonical] {
			return "", fmt.Errorf("circular reference detected: ${%s}", ref)
		}

		// Try in-memory dict first (same app only)
		resolvedVal := ""
		found := false
		if app == currentApp {
			resolvedVal, found = lookupInMemory(secretsDict, env, path, keyName)
		}

		// Try cache
		if !found {
			resolvedVal, found = getFromCache(app, env, path, keyName)
		}

		if !found {
			// Keep original reference text
			resolutions = append(resolutions, resolvedRef{fullRef: value[locs[i][0]:locs[i][1]], resolvedVal: value[locs[i][0]:locs[i][1]]})
			continue
		}

		// Recursively resolve if the resolved value itself contains references
		if secretRefRegex.MatchString(resolvedVal) {
			// Create a child visited set so sibling refs don't interfere
			childVisited := make(map[string]bool, len(visited)+1)
			for k, v := range visited {
				childVisited[k] = v
			}
			childVisited[canonical] = true
			resolvedVal, err = resolveAllSecretsInternal(resolvedVal, allSecrets, p, app, env, childVisited)
			if err != nil {
				return "", err
			}
		}

		resolutions = append(resolutions, resolvedRef{fullRef: value[locs[i][0]:locs[i][1]], resolvedVal: resolvedVal})
	}

	// Build result using positional replacement to avoid aliasing
	var result strings.Builder
	lastEnd := 0
	for i, loc := range locs {
		result.WriteString(value[lastEnd:loc[0]])
		result.WriteString(resolutions[i].resolvedVal)
		lastEnd = loc[1]
	}
	result.WriteString(value[lastEnd:])

	return result.String(), nil
}

func lookupInMemory(secretsDict map[string]map[string]map[string]string, envName, path, keyName string) (string, bool) {
	envKey := findEnvKeyCaseInsensitive(secretsDict, envName)
	if envKey == "" {
		return "", false
	}
	if pathBucket, ok := secretsDict[envKey][path]; ok {
		if val, ok := pathBucket[keyName]; ok {
			return val, true
		}
	}
	return "", false
}

func findEnvKeyCaseInsensitive(secretsDict map[string]map[string]map[string]string, envName string) string {
	// Exact match
	if _, ok := secretsDict[envName]; ok {
		return envName
	}
	// Case-insensitive exact match
	for k := range secretsDict {
		if strings.EqualFold(k, envName) {
			return k
		}
	}
	return ""
}
