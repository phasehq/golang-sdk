package phase

import (
	"strings"
	"testing"

	"github.com/phasehq/golang-sdk/phase/misc"
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
	if !p.IsServiceToken || p.IsUserToken || p.TokenType != "Service" || p.Prefix != "pss_service" || p.PesVersion != "v1" {
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
	if !p.IsUserToken || p.IsServiceToken || p.TokenType != "User" || p.Prefix != "pss_user" {
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

func TestAppKeyResponseToMap(t *testing.T) {
	resp := &misc.AppKeyResponse{
		UserID:          "user-1",
		AccountID:       "account-1",
		WrappedKeyShare: "wks",
		Apps: []misc.App{
			{ID: "app-1", Name: "Backend"},
		},
	}
	m := appKeyResponseToMap(resp)

	if m["user_id"] != "user-1" {
		t.Fatalf("unexpected user_id in map: %v", m["user_id"])
	}
	if m["account_id"] != "account-1" {
		t.Fatalf("unexpected account_id in map: %v", m["account_id"])
	}
	if _, ok := m["apps"]; !ok {
		t.Fatal("expected apps key in map")
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
