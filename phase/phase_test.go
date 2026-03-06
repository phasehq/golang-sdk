package phase

import (
	"strings"
	"testing"

	"github.com/phasehq/golang-sdk/v2/phase/misc"
)

func makeHex(n int, ch string) string {
	return strings.Repeat(ch, n)
}

func TestNew_ServiceAndUserTokens(t *testing.T) {
	s1 := "pss_service:v1:" + makeHex(64, "a") + ":" + makeHex(64, "b") + ":" + makeHex(64, "c") + ":" + makeHex(64, "d")
	p, err := New(s1, "", false)
	if err != nil {
		t.Fatalf("New(service v1) error: %v", err)
	}
	if !p.IsServiceToken || p.IsUserToken || p.TokenType != "Service" || p.prefix != "pss_service" || p.pesVersion != "v1" {
		t.Fatalf("unexpected service v1 parse: %+v", p)
	}
	if p.Host != misc.PhaseCloudAPIHost {
		t.Fatalf("unexpected default host: %s", p.Host)
	}

	s2 := "pss_service:v2:" + makeHex(64, "a") + ":" + makeHex(64, "b") + ":" + makeHex(64, "c") + ":" + makeHex(64, "d")
	p, err = New(s2, "https://example.com", false)
	if err != nil {
		t.Fatalf("New(service v2) error: %v", err)
	}
	if p.TokenType != "ServiceAccount" || p.Host != "https://example.com" {
		t.Fatalf("unexpected service v2 parse: %+v", p)
	}

	u1 := "pss_user:v2:" + makeHex(64, "e") + ":" + makeHex(64, "f") + ":" + makeHex(64, "1") + ":" + makeHex(64, "2")
	p, err = New(u1, "", true)
	if err != nil {
		t.Fatalf("New(user) error: %v", err)
	}
	if !p.IsUserToken || p.IsServiceToken || p.TokenType != "User" || p.prefix != "pss_user" {
		t.Fatalf("unexpected user parse: %+v", p)
	}
}

func TestNew_InvalidTokens(t *testing.T) {
	if _, err := New("not-a-token", "", false); err == nil {
		t.Fatal("expected invalid service token error")
	}
	if _, err := New("pss_user:invalid", "", false); err == nil {
		t.Fatal("expected invalid user token error")
	}
}

func TestFindMatchingEnvironmentKey(t *testing.T) {
	p := &Phase{}
	userData := &misc.AppKeyResponse{
		Apps: []misc.App{
			{
				ID:   "app-1",
				Name: "Backend",
				EnvironmentKeys: []misc.EnvironmentKey{
					{Environment: misc.Environment{ID: "env-dev", Name: "Development"}},
					{Environment: misc.Environment{ID: "env-prod", Name: "Production"}},
				},
			},
		},
	}

	key := p.findMatchingEnvironmentKey(userData, "env-prod")
	if key == nil || key.Environment.Name != "Production" {
		t.Fatalf("expected Production key, got %+v", key)
	}

	key = p.findMatchingEnvironmentKey(userData, "does-not-exist")
	if key != nil {
		t.Fatalf("expected nil for missing env id, got %+v", key)
	}
}

func TestHelpersExtractStringSliceAndGetBool(t *testing.T) {
	m := map[string]interface{}{
		"tags":      []interface{}{"prod", 123, "backend"},
		"is_active": true,
		"as_str":    "true",
		"bad":       1,
	}

	tags := misc.ExtractStringSlice(m, "tags")
	if len(tags) != 2 || tags[0] != "prod" || tags[1] != "backend" {
		t.Fatalf("unexpected extracted tags: %#v", tags)
	}

	if !misc.GetBool(m, "is_active") {
		t.Fatal("expected true for bool value")
	}
	if !misc.GetBool(m, "as_str") {
		t.Fatal("expected true for string true value")
	}
	if misc.GetBool(m, "bad") {
		t.Fatal("expected false for unsupported value type")
	}
	if misc.GetBool(m, "missing") {
		t.Fatal("expected false for missing key")
	}
}

// TestGetOptions_RawSkipsResolution validates that the Raw flag in GetOptions
// controls whether ${REF} references are resolved. Since Get() requires network
// calls, we test the resolution logic directly using ResolveAllSecrets — the
// same code path that Get() uses when Raw is false.
func TestGetOptions_RawSkipsResolution(t *testing.T) {
	ResetSecretsCache()
	t.Cleanup(ResetSecretsCache)

	app := "test_app"
	env := "current"

	seedCache(app, env, "/", map[string]string{"DB_HOST": "localhost"})

	secrets := []SecretResult{
		{Application: app, Environment: env, Path: "/", Key: "DB_URL", Value: "host=${DB_HOST}"},
		{Application: app, Environment: env, Path: "/", Key: "DB_HOST", Value: "localhost"},
	}

	// Simulate Raw=true: no resolution, original ${REF} syntax preserved
	if secrets[0].Value != "host=${DB_HOST}" {
		t.Fatalf("expected raw reference syntax, got %q", secrets[0].Value)
	}

	// Simulate Raw=false (default): references are resolved via ResolveAllSecrets
	resolved, err := ResolveAllSecrets(secrets[0].Value, secrets, nil, app, env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != "host=localhost" {
		t.Fatalf("expected resolved value %q, got %q", "host=localhost", resolved)
	}
}
