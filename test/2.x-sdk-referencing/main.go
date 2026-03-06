// Test program for verifying secret reference resolution using the Phase Go SDK (v2.x).
//
// This program:
// 1. Creates base secrets across two apps, multiple envs and paths
// 2. Creates secrets whose values contain ${...} references
// 3. Fetches each referencing secret via Get() and checks if the reference was resolved
// 4. Cleans up all created secrets
//
// Usage:
//   go run main.go --token "pss_service:v1:..." --host "https://localhost"

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/phasehq/golang-sdk/phase"
	"github.com/phasehq/golang-sdk/phase/misc"
	"github.com/phasehq/golang-sdk/phase/network"
)

// testSecret describes a secret to create.
type testSecret struct {
	appName string
	envName string
	key     string
	value   string
	path    string // empty means root "/"
}

// refTest describes a reference resolution test case.
type refTest struct {
	name     string // human-readable test name
	key      string // secret key containing the reference
	rawValue string // the ${...} reference string stored as the value
	expected string // what Get() should resolve it to
}

func main() {
	token := flag.String("token", "", "Phase service/user token with access to both apps")
	host := flag.String("host", "https://localhost", "Phase console URL")
	skipCleanup := flag.Bool("skip-cleanup", false, "Skip deleting test secrets after run")
	cleanupOnly := flag.Bool("cleanup-only", false, "Only delete test secrets, don't create or test")
	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		flag.Usage()
		os.Exit(1)
	}

	// Disable SSL verification for local self-signed certs
	misc.VerifySSL = false

	fmt.Println("=== Phase 2.x SDK Reference Resolution Test ===")
	fmt.Println()

	p, err := phase.New(*token, *host, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAIL  could not init Phase client: %v\n", err)
		os.Exit(1)
	}

	// Print available apps/envs so we can verify the names match
	fmt.Println("[DEBUG] Fetching available apps and environments...")
	resp, err := network.FetchPhaseUser(p.TokenType, p.AppToken, p.Host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  FAIL  could not fetch user data: %v\n", err)
		os.Exit(1)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var userData misc.AppKeyResponse
	json.Unmarshal(body, &userData)
	for _, app := range userData.Apps {
		fmt.Printf("  App: %q (ID: %s)\n", app.Name, app.ID)
		for _, ek := range app.EnvironmentKeys {
			fmt.Printf("    Env: %q (ID: %s)\n", ek.Environment.Name, ek.Environment.ID)
		}
	}
	fmt.Println()

	// Define all secrets up front (needed for cleanup-only mode too)
	baseSecrets := []testSecret{
		{"test-chamber", "Development", "BASE_SECRET", "hello_from_base", ""},
		{"test-chamber", "Development", "DB_PASS", "pg_password_123", "/backend"},
		{"test-chamber", "Staging", "STAGING_VAL", "staging_value_42", ""},
		{"gravity-gun", "Development", "GRAVITY_KEY", "gravity_key_value", ""},
	}

	refSecrets := []testSecret{
		{"test-chamber", "Development", "REF_SAME_ENV", "${BASE_SECRET}", ""},
		{"test-chamber", "Development", "REF_DIFF_PATH", "${/backend/DB_PASS}", ""},
		{"test-chamber", "Development", "REF_CROSS_ENV", "${Staging.STAGING_VAL}", ""},
		{"test-chamber", "Development", "REF_CROSS_APP", "${gravity-gun::Development.GRAVITY_KEY}", ""},
	}

	// Handle cleanup-only mode
	if *cleanupOnly {
		cleanup(p, baseSecrets, refSecrets)
		fmt.Println("Cleanup complete.")
		return
	}

	tests := []refTest{
		{"same env, root path", "REF_SAME_ENV", "${BASE_SECRET}", "hello_from_base"},
		{"same env, different path", "REF_DIFF_PATH", "${/backend/DB_PASS}", "pg_password_123"},
		{"cross-env", "REF_CROSS_ENV", "${Staging.STAGING_VAL}", "staging_value_42"},
		{"cross-app", "REF_CROSS_APP", "${gravity-gun::Development.GRAVITY_KEY}", "gravity_key_value"},
	}

	// ----------------------------------------------------------------
	// SETUP: Create base secrets
	// ----------------------------------------------------------------
	fmt.Println("[SETUP] Creating base secrets...")
	for _, s := range baseSecrets {
		if err := createSecret(p, s); err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL  %s/%s%s: %s — %v\n", s.appName, s.envName, pathDisplay(s.path), s.key, err)
			os.Exit(1)
		}
		fmt.Printf("  OK    %s/%s%s: %s\n", s.appName, s.envName, pathDisplay(s.path), s.key)
	}
	fmt.Println()

	// ----------------------------------------------------------------
	// SETUP: Create referencing secrets
	// ----------------------------------------------------------------
	fmt.Println("[SETUP] Creating referencing secrets...")
	for _, s := range refSecrets {
		if err := createSecret(p, s); err != nil {
			fmt.Fprintf(os.Stderr, "  FAIL  %s = %s — %v\n", s.key, s.value, err)
			// Try cleanup before exit
			if !*skipCleanup {
				cleanup(p, baseSecrets, refSecrets)
			}
			os.Exit(1)
		}
		fmt.Printf("  OK    %s = %s\n", s.key, s.value)
	}
	fmt.Println()

	// ----------------------------------------------------------------
	// TEST: Fetch each referencing secret and check resolved value
	// ----------------------------------------------------------------
	fmt.Println("[TEST] Fetching and verifying references...")
	passed := 0
	failed := 0

	for _, tc := range tests {
		results, err := p.Get(phase.GetOptions{
			EnvName: "Development",
			AppName: "test-chamber",
			Keys:    []string{tc.key},
		})
		if err != nil {
			fmt.Printf("  FAIL  %s (%s): fetch error: %v\n", tc.key, tc.name, err)
			failed++
			continue
		}
		if len(results) == 0 {
			fmt.Printf("  FAIL  %s (%s): Get() returned no results\n", tc.key, tc.name)
			failed++
			continue
		}

		got := results[0].Value

		if got == tc.expected {
			fmt.Printf("  PASS  %s (%s)\n", tc.key, tc.name)
			fmt.Printf("        expected=%q got=%q\n", tc.expected, got)
			passed++
		} else {
			fmt.Printf("  FAIL  %s (%s)\n", tc.key, tc.name)
			fmt.Printf("        expected=%q got=%q\n", tc.expected, got)
			if got == tc.rawValue {
				fmt.Printf("        (value was NOT resolved — still contains raw reference)\n")
			}
			failed++
		}
	}
	fmt.Println()

	// ----------------------------------------------------------------
	// CLEANUP
	// ----------------------------------------------------------------
	if !*skipCleanup {
		cleanup(p, baseSecrets, refSecrets)
	} else {
		fmt.Println("[CLEANUP] Skipped (--skip-cleanup)")
		fmt.Println()
	}

	// ----------------------------------------------------------------
	// SUMMARY
	// ----------------------------------------------------------------
	total := passed + failed
	fmt.Printf("Results: %d/%d PASSED", passed, total)
	if failed > 0 {
		fmt.Printf(", %d FAILED", failed)
	}
	fmt.Println()

	if failed > 0 {
		os.Exit(1)
	}
}

func createSecret(p *phase.Phase, s testSecret) error {
	opts := phase.CreateOptions{
		KeyValuePairs: []phase.KeyValuePair{{Key: s.key, Value: s.value}},
		EnvName:       s.envName,
		AppName:       s.appName,
	}
	if s.path != "" {
		opts.Path = s.path
	}
	return p.Create(opts)
}

func cleanup(p *phase.Phase, baseSecrets, refSecrets []testSecret) {
	fmt.Println("[CLEANUP] Deleting test secrets...")

	// Delete referencing secrets first, then base secrets
	allSecrets := append(refSecrets, baseSecrets...)
	deleted := 0
	errors := 0

	for _, s := range allSecrets {
		_, err := p.Delete(phase.DeleteOptions{
			EnvName:      s.envName,
			AppName:      s.appName,
			KeysToDelete: []string{s.key},
			Path:         s.path,
		})
		if err != nil {
			// Don't fail hard on cleanup errors — the secret may not have been created
			if !strings.Contains(err.Error(), "not found") {
				fmt.Printf("  WARN  failed to delete %s/%s/%s: %v\n", s.appName, s.envName, s.key, err)
			}
			errors++
		} else {
			deleted++
		}
	}

	fmt.Printf("  OK    deleted %d secrets", deleted)
	if errors > 0 {
		fmt.Printf(" (%d skipped/failed)", errors)
	}
	fmt.Println()
	fmt.Println()
}

func pathDisplay(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	return path
}
