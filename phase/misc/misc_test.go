package misc

import (
	"regexp"
	"strings"
	"testing"
)

func makeUserData() *AppKeyResponse {
	return &AppKeyResponse{
		Apps: []App{
			{
				ID:   "app-1",
				Name: "Backend API",
				EnvironmentKeys: []EnvironmentKey{
					{Environment: Environment{ID: "env-dev", Name: "Development"}, IdentityKey: "pub-dev"},
					{Environment: Environment{ID: "env-prod", Name: "Production"}, IdentityKey: "pub-prod"},
				},
			},
			{
				ID:   "app-2",
				Name: "Backend",
				EnvironmentKeys: []EnvironmentKey{
					{Environment: Environment{ID: "env-stage", Name: "Staging"}, IdentityKey: "pub-stage"},
				},
			},
		},
	}
}

func TestPhaseGetContext_ByAppID(t *testing.T) {
	userData := makeUserData()
	appName, appID, envName, envID, identityKey, err := PhaseGetContext(userData, "", "Production", "app-1")
	if err != nil {
		t.Fatalf("PhaseGetContext returned error: %v", err)
	}
	if appName != "Backend API" || appID != "app-1" || envName != "Production" || envID != "env-prod" || identityKey != "pub-prod" {
		t.Fatalf("unexpected context: %q %q %q %q %q", appName, appID, envName, envID, identityKey)
	}
}

func TestPhaseGetContext_ByPartialAppNameShortestMatch(t *testing.T) {
	userData := makeUserData()
	appName, appID, envName, envID, _, err := PhaseGetContext(userData, "backend", "Staging", "")
	if err != nil {
		t.Fatalf("PhaseGetContext returned error: %v", err)
	}
	if appName != "Backend" || appID != "app-2" || envName != "Staging" || envID != "env-stage" {
		t.Fatalf("unexpected context from partial app match: %q %q %q %q", appName, appID, envName, envID)
	}
}

func TestPhaseGetContext_DefaultEnvWhenNotProvided(t *testing.T) {
	userData := makeUserData()
	_, _, envName, envID, _, err := PhaseGetContext(userData, "backend api", "", "")
	if err != nil {
		t.Fatalf("PhaseGetContext returned error: %v", err)
	}
	if envName != "Development" || envID != "env-dev" {
		t.Fatalf("unexpected default env context: %q %q", envName, envID)
	}
}

func TestPhaseGetContext_Errors(t *testing.T) {
	userData := makeUserData()

	if _, _, _, _, _, err := PhaseGetContext(userData, "", "Development", "bad-app-id"); err == nil {
		t.Fatal("expected error for missing app ID")
	}
	if _, _, _, _, _, err := PhaseGetContext(userData, "", "Development", ""); err == nil {
		t.Fatal("expected error for missing app context")
	}
	if _, _, _, _, _, err := PhaseGetContext(userData, "backend", "qa", ""); err == nil {
		t.Fatal("expected error for missing env in matched app")
	}
}

func TestFindEnvironmentKey(t *testing.T) {
	userData := *makeUserData()

	key, err := FindEnvironmentKey(userData, FindEnvironmentKeyOptions{EnvName: "development", AppName: "backend api"})
	if err != nil {
		t.Fatalf("FindEnvironmentKey returned error: %v", err)
	}
	if key.Environment.ID != "env-dev" {
		t.Fatalf("unexpected env id: %s", key.Environment.ID)
	}

	key, err = FindEnvironmentKey(userData, FindEnvironmentKeyOptions{EnvName: "prod"})
	if err != nil {
		t.Fatalf("FindEnvironmentKey partial returned error: %v", err)
	}
	if key.Environment.Name != "Production" {
		t.Fatalf("unexpected partial env match: %s", key.Environment.Name)
	}

	if _, err := FindEnvironmentKey(userData, FindEnvironmentKeyOptions{EnvName: "not-real", AppName: "backend api"}); err == nil {
		t.Fatal("expected not found error")
	}
}

func TestTagMatchesAndNormalize(t *testing.T) {
	if got := normalizeTag("PROD_ENV"); got != "prod env" {
		t.Fatalf("unexpected normalized tag: %q", got)
	}

	if !TagMatches([]string{"Production", "ConfigData"}, "prod") {
		t.Fatal("expected prod to match Production")
	}
	if !TagMatches([]string{"Test_Tag"}, "test tag") {
		t.Fatal("expected test tag to match Test_Tag")
	}
	if TagMatches([]string{"Development"}, "prod") {
		t.Fatal("expected no match for prod in Development")
	}
}

func TestGenerateRandomSecret(t *testing.T) {
	hexSecret, err := GenerateRandomSecret("hex", 64)
	if err != nil {
		t.Fatalf("GenerateRandomSecret hex error: %v", err)
	}
	if len(hexSecret) != 64 {
		t.Fatalf("unexpected hex length: %d", len(hexSecret))
	}
	if !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(strings.ToLower(hexSecret)) {
		t.Fatalf("expected hex output, got %q", hexSecret)
	}

	alphaSecret, err := GenerateRandomSecret("alphanumeric", 32)
	if err != nil {
		t.Fatalf("GenerateRandomSecret alphanumeric error: %v", err)
	}
	if len(alphaSecret) != 32 {
		t.Fatalf("unexpected alphanumeric length: %d", len(alphaSecret))
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(alphaSecret) {
		t.Fatalf("expected alphanumeric output, got %q", alphaSecret)
	}

	key128, err := GenerateRandomSecret("key128", 999)
	if err != nil {
		t.Fatalf("GenerateRandomSecret key128 error: %v", err)
	}
	if len(key128) != 32 {
		t.Fatalf("unexpected key128 hex length: %d", len(key128))
	}

	key256, err := GenerateRandomSecret("key256", 999)
	if err != nil {
		t.Fatalf("GenerateRandomSecret key256 error: %v", err)
	}
	if len(key256) != 64 {
		t.Fatalf("unexpected key256 hex length: %d", len(key256))
	}

	base64Secret, err := GenerateRandomSecret("base64", 44)
	if err != nil {
		t.Fatalf("GenerateRandomSecret base64 error: %v", err)
	}
	if len(base64Secret) != 44 {
		t.Fatalf("unexpected base64 length: %d", len(base64Secret))
	}

	base64URLSecret, err := GenerateRandomSecret("base64url", 44)
	if err != nil {
		t.Fatalf("GenerateRandomSecret base64url error: %v", err)
	}
	if len(base64URLSecret) != 44 {
		t.Fatalf("unexpected base64url length: %d", len(base64URLSecret))
	}

	defaultLen, err := GenerateRandomSecret("alphanumeric", 0)
	if err != nil {
		t.Fatalf("GenerateRandomSecret default-length error: %v", err)
	}
	if len(defaultLen) != 32 {
		t.Fatalf("expected default length 32, got %d", len(defaultLen))
	}

	if _, err := GenerateRandomSecret("invalid", 32); err == nil {
		t.Fatal("expected unsupported type error")
	}
}
