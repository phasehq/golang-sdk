package phase

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

// OfflineConfig controls offline caching behavior.
// When set on a Phase instance, encrypted API responses are cached to CacheDir
// and served from cache when the network is unavailable.
type OfflineConfig struct {
	CacheDir string // Root cache directory (e.g. ~/.phase/secrets/offline/{account_id})
	Offline  bool   // When true, skip network entirely and serve from cache
}

// SetOfflineConfig enables offline caching on this Phase instance.
func (p *Phase) SetOfflineConfig(cfg *OfflineConfig) {
	p.offlineConfig = cfg
}

// pathHash returns a filesystem-safe SHA-256 hex digest for a cache key.
func pathHash(envName, appName, appID, path string) string {
	if path == "" {
		path = "/"
	}
	raw := fmt.Sprintf("%s|%s|%s|%s", envName, appName, appID, path)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// userDataCachePath returns the path for cached user data (AppKeyResponse).
func userDataCachePath(cacheDir string) string {
	return filepath.Join(cacheDir, "userdata.json")
}

// secretsCachePath returns the path for cached encrypted secrets.
func secretsCachePath(cacheDir, envName, appName, appID, path string) string {
	return filepath.Join(cacheDir, "secrets", pathHash(envName, appName, appID, path)+".json")
}

// cacheWrite atomically writes data to a file with 0600 permissions.
func cacheWrite(fp string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(fp), 0700); err != nil {
		return err
	}
	tmp := fp + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, fp); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// cacheRead reads a cached file.
func cacheRead(fp string) ([]byte, error) {
	return os.ReadFile(fp)
}

// isNetworkError returns true if the error indicates the server is unreachable
// (DNS, connection, timeout, SSL) — not auth or API errors.
func isNetworkError(err error) bool {
	var netErr *network.NetworkError
	var sslErr *network.SSLError
	return errors.As(err, &netErr) || errors.As(err, &sslErr)
}

// offlineLog prints an offline-related message to stderr.
func offlineLog(format string, args ...interface{}) {
	log.Printf("[phase] "+format, args...)
}
