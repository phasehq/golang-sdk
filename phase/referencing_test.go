package phase

import (
	"strings"
	"testing"
)

func seedCache(app, env, path string, values map[string]string) {
	secretsCache[cacheKey(app, env, path)] = values
}

func TestNormalizePath(t *testing.T) {
	if got := normalizePath(""); got != "/" {
		t.Fatalf("normalizePath(\"\") = %q, want /", got)
	}
	if got := normalizePath("backend"); got != "/backend" {
		t.Fatalf("normalizePath(\"backend\") = %q, want /backend", got)
	}
	if got := normalizePath("/backend"); got != "/backend" {
		t.Fatalf("normalizePath(\"/backend\") = %q, want /backend", got)
	}
}

func TestSplitPathAndKey(t *testing.T) {
	path, key := splitPathAndKey("KEY")
	if path != "/" || key != "KEY" {
		t.Fatalf("unexpected split for KEY: path=%q key=%q", path, key)
	}

	path, key = splitPathAndKey("/backend/payments/STRIPE_KEY")
	if path != "/backend/payments" || key != "STRIPE_KEY" {
		t.Fatalf("unexpected split for path ref: path=%q key=%q", path, key)
	}
}

func TestParseReferenceContext(t *testing.T) {
	app, env, path, key, err := parseReferenceContext("production.SECRET_KEY", "my-app", "dev")
	if err != nil {
		t.Fatalf("parseReferenceContext returned error: %v", err)
	}
	if app != "my-app" || env != "production" || path != "/" || key != "SECRET_KEY" {
		t.Fatalf("unexpected parse result: %q %q %q %q", app, env, path, key)
	}

	app, env, path, key, err = parseReferenceContext("backend_api::production./frontend/SECRET_KEY", "my-app", "dev")
	if err != nil {
		t.Fatalf("parseReferenceContext returned error: %v", err)
	}
	if app != "backend_api" || env != "production" || path != "/frontend" || key != "SECRET_KEY" {
		t.Fatalf("unexpected cross-app parse result: %q %q %q %q", app, env, path, key)
	}
}

func TestParseReferenceContext_CrossAppRequiresEnv(t *testing.T) {
	_, _, _, _, err := parseReferenceContext("backend_api::SECRET_KEY", "my-app", "dev")
	if err == nil {
		t.Fatal("expected error for cross-app reference without env")
	}
	if !strings.Contains(err.Error(), "cross-app references must specify an environment") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestFindEnvKeyCaseInsensitiveAndPartial(t *testing.T) {
	secretsDict := map[string]map[string]map[string]string{
		"Development": {"/": {"DEBUG": "true"}},
		"dev":         {"/": {"DEBUG": "short"}},
	}

	if got := findEnvKeyCaseInsensitive(secretsDict, "development"); got != "Development" {
		t.Fatalf("expected case-insensitive match Development, got %q", got)
	}
	if got := findEnvKeyCaseInsensitive(secretsDict, "de"); got != "dev" {
		t.Fatalf("expected shortest partial match dev, got %q", got)
	}
}

func TestResolveAllSecrets_LocalCrossEnvAndPath(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	app := "test_app"
	currentEnv := "current"

	allSecrets := []SecretResult{
		{Application: app, Environment: "current", Path: "/", Key: "KEY", Value: "value1"},
		{Application: app, Environment: "staging", Path: "/", Key: "DEBUG", Value: "staging_debug_value"},
		{Application: app, Environment: "current", Path: "/backend/payments", Key: "STRIPE_KEY", Value: "stripe_value"},
	}

	seedCache(app, "current", "/", map[string]string{"KEY": "value1"})
	seedCache(app, "staging", "/", map[string]string{"DEBUG": "staging_debug_value"})
	seedCache(app, "current", "/backend/payments", map[string]string{"STRIPE_KEY": "stripe_value"})

	input := "A=${KEY};B=${staging.DEBUG};C=${/backend/payments/STRIPE_KEY}"
	got, err := ResolveAllSecrets(input, allSecrets, nil, app, currentEnv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "A=value1;B=staging_debug_value;C=stripe_value"
	if got != want {
		t.Fatalf("unexpected resolved value: got %q want %q", got, want)
	}
}

func TestResolveAllSecrets_CrossAppRecursive(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	seedCache("other_app", "dev", "/", map[string]string{
		"POSTGRESQL_URL":      "postgresql://${/creds/POSTGRESQL_USER}:${/creds/POSTGRESQL_PASSWORD}@${POSTGRESQL_HOST}/${POSTGRESQL_DB}",
		"POSTGRESQL_HOST":     "localhost",
		"POSTGRESQL_DB":       "db",
		"POSTGRESQL_PASSWORD": "pg_password_root",
	})
	seedCache("other_app", "dev", "/creds", map[string]string{
		"POSTGRESQL_USER":     "pg_user",
		"POSTGRESQL_PASSWORD": "pg_password",
	})

	input := "DB=${other_app::dev.POSTGRESQL_URL}"
	got, err := ResolveAllSecrets(input, nil, nil, "test_app", "current")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "DB=postgresql://pg_user:pg_password@localhost/db"
	if got != want {
		t.Fatalf("unexpected recursive cross-app resolution: got %q want %q", got, want)
	}
}

func TestResolveAllSecrets_CycleDoesNotInfiniteLoop(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	seedCache("other_app", "dev", "/", map[string]string{
		"A": "${B}",
		"B": "${C}",
		"C": "${A}",
	})

	got, err := ResolveAllSecrets("X=${other_app::dev.A}", nil, nil, "test_app", "current")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "${") {
		t.Fatalf("expected unresolved placeholder due to cycle, got %q", got)
	}
}

func TestResolveAllSecrets_PreservesRailwayStyleSyntax(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	input := "Railway: ${{RAILWAY_TOKEN}}"
	got, err := ResolveAllSecrets(input, nil, nil, "test_app", "current")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != input {
		t.Fatalf("expected railway syntax unchanged: got %q want %q", got, input)
	}
}

func TestResolveAllSecrets_MultipleOccurrences(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	app := "test_app"
	seedCache(app, "current", "/", map[string]string{"KEY": "v"})
	allSecrets := []SecretResult{
		{Application: app, Environment: "current", Path: "/", Key: "KEY", Value: "v"},
	}

	got, err := ResolveAllSecrets("A=${KEY};B=${KEY}", allSecrets, nil, app, "current")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "A=v;B=v" {
		t.Fatalf("unexpected repeated-reference result: %q", got)
	}
}

func TestResolveAllSecrets_CrossAppInvalidRefReturnsError(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	input := "${backend_api::SECRET_KEY}"
	_, err := ResolveAllSecrets(input, nil, nil, "test_app", "current")
	if err == nil {
		t.Fatal("expected error for invalid cross-app reference without env")
	}
	if !strings.Contains(err.Error(), "cross-app references must specify an environment") {
		t.Fatalf("unexpected error message: %v", err)
	}
}
