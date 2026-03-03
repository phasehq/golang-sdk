package phase

// Integration tests that run a full CRUD cycle against a mock HTTP server
// populated with real crypto fixtures captured from a local Phase test instance.
// No live server is required: all HTTP is intercepted by httptest.NewServer.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// testToken is from the local Phase test instance (example-app/development).
// The crypto material embedded in the fixtures below is only valid together
// with this specific token.
const testToken = "pss_user:v1:" +
	"9d5356eae3618da040c61b50349f291d4db9c74da5315caeb65da25ee5d0d8b7:" +
	"170d014dae1a2d76130e4eb6579fe1edce5c4ea0b69794cd6a18978769120709:" +
	"e1e5018e0829a1142c79afa5f70c01c8d4889b15116553d266e761851ad11197:" +
	"b5b26ee93f0b68cecfa53c4a7dc8ffcb75bbecdd1f56930a9118a1e4a72b34f9"

// tokensFixture is a minimal AppKeyResponse containing only example-app /
// Development.  UUIDs for user/org/account are anonymised; all crypto blobs
// (wrapped_seed, wrapped_salt, identity_key, wrapped_key_share) are real so
// that the SDK's decryption pipeline succeeds.
const tokensFixture = `{
  "account_id": "00000000-0000-0000-0000-000000000001",
  "offline_enabled": false,
  "organisation": {"id": "00000000-0000-0000-0000-000000000002", "name": "Test Org"},
  "user_id": "00000000-0000-0000-0000-000000000003",
  "wrapped_key_share": "3fbd711ef2d5266c30d104f2831690939cc020c01963da275163e32b0f1596a34ebdb795714e6005e42f5cd65a767f6f4eb1f0c29342c8da2cfb6a042cd1e7a258250c11c6a9c676fc3ab1ed87b8576f22a8b43ca12ffc6da79eef0cbe44988534da40c031e87dbd",
  "apps": [
    {
      "id": "95721375-69c6-4e1e-b0aa-8deffca4dd5a",
      "name": "example-app",
      "encryption": "SSE",
      "environment_keys": [
        {
          "id": "6ffa6604-7096-4e90-8a41-3784975c1a8f",
          "identity_key": "53b9d2b5e10cd1919dd1828959c292484b6a0c0b97853b04abbf078b13053c75",
          "wrapped_seed": "ph:v1:ee47a425e193b4915aa3a7015e6a5d750adbdbda1425d4b908715e0ceb420b19:F6+YKR6y6zWxGaBdTOMllfS6ZtnrW4XDfTg2V3aaFPaMNP3JYCcz9zFwBLQpPBj8XxbABG3zQyzwy+yKLUHkCBTaPG2XbaHewzpSgJmnMaU75LgbCdij6lgk2wdnH8qMukOhO3ALmmE=",
          "wrapped_salt": "ph:v1:60d05a1e1824e1cf58a0529797b0406e181e504077c2a9d3938132c54e72ce15:KfN7VdKQVP7PKziCp8BTnpXQbelFH2jY27EA3JZYP1sPFlyxC2BX6iHd/MjatZGubzTPa+xSAFJ/5gsaSJ/RTe9OFAjeC/imdwCijxLKUfmVxnXvRC1QBtZl54x0MauNIEx0IfeW+m4=",
          "created_at": "2025-09-25T07:48:21.706815Z",
          "deleted_at": null,
          "paths": null,
          "service_account": null,
          "updated_at": "2025-09-25T07:48:21.706822Z",
          "user": "00000000-0000-0000-0000-000000000003",
          "environment": {
            "id": "588fbfee-d572-4627-8a83-17c65702ad5d",
            "name": "Development",
            "env_type": "DEV",
            "created_at": "2025-09-25T07:48:21.703854Z",
            "updated_at": "2025-09-25T07:48:21.703854Z"
          }
        }
      ]
    }
  ]
}`

// secretsFixtureMultiPath is used to test path-scoped Update.
// It has two secrets with identical key names but different paths.
// Both are encrypted with the same env keypair as secretsFixture.
const secretsFixtureMultiPath = `[
  {
    "id": "fca7e863-85bc-4969-9db0-b5c678e4489e",
    "key": "ph:v1:77a788dee04a28aaa2bb44a77e18fbae614fec9717f61f96c5cd31a5e621ee00:KMYbYB6PbPMlMbYkbsN+FjCkXdhrB9Ok24dusEFVPA946dGxznDG7fiuD0mBf4xF7oH9Ejoe8WOn4KTorg==",
    "value": "ph:v1:2ded5d855cbc67bec0973b00aad74136d637c2c2b3d23d239e570073b083732e:3GiNM647gv8twOjJaCI0NTIkyeJID6Mi41c7fpF1fLGtqTO/HPBlEzdVHHKXFdSMhaZni5if19fA8fs=",
    "comment": "",
    "key_digest": "639673a7ed8cd7188e75ed60a2e24e5752119d27b642db367cf747dd02bbdb6c",
    "environment": "588fbfee-d572-4627-8a83-17c65702ad5d",
    "folder": null, "override": null, "path": "/alpha", "tags": [], "type": "static", "version": 1,
    "created_at": "2025-09-25T07:48:21.865291Z", "updated_at": "2025-09-25T07:48:21.865303Z"
  },
  {
    "id": "b2a7f67f-3d59-4dd8-8462-4a7f17d63bd3",
    "key": "ph:v1:77a788dee04a28aaa2bb44a77e18fbae614fec9717f61f96c5cd31a5e621ee00:KMYbYB6PbPMlMbYkbsN+FjCkXdhrB9Ok24dusEFVPA946dGxznDG7fiuD0mBf4xF7oH9Ejoe8WOn4KTorg==",
    "value": "ph:v1:83105db4144674fbda57e41d572e949d00e5fddda4962924d814d99f6f7be642:8joUdNCOQ/VsJ66ZBU1B7hgx6LqVfCkJ1va8I58ZYGz/ihMz2bnDGLmvmTrxPbB5lNUU0NFv4LsZg32B",
    "comment": "",
    "key_digest": "639673a7ed8cd7188e75ed60a2e24e5752119d27b642db367cf747dd02bbdb6c",
    "environment": "588fbfee-d572-4627-8a83-17c65702ad5d",
    "folder": null, "override": null, "path": "/beta", "tags": [], "type": "static", "version": 1,
    "created_at": "2025-09-25T07:48:21.876136Z", "updated_at": "2025-09-25T07:48:21.876142Z"
  }
]`

// secretsFixture contains two encrypted secrets from the live capture.
// Secret IDs are kept real so Delete tests can assert the correct ID is sent.
const secretsFixture = `[
  {
    "id": "fca7e863-85bc-4969-9db0-b5c678e4489e",
    "key": "ph:v1:77a788dee04a28aaa2bb44a77e18fbae614fec9717f61f96c5cd31a5e621ee00:KMYbYB6PbPMlMbYkbsN+FjCkXdhrB9Ok24dusEFVPA946dGxznDG7fiuD0mBf4xF7oH9Ejoe8WOn4KTorg==",
    "value": "ph:v1:2ded5d855cbc67bec0973b00aad74136d637c2c2b3d23d239e570073b083732e:3GiNM647gv8twOjJaCI0NTIkyeJID6Mi41c7fpF1fLGtqTO/HPBlEzdVHHKXFdSMhaZni5if19fA8fs=",
    "comment": "ph:v1:4ba0a5eccc6fbe77feb8fc69bdadde755e865685c412f634b6d4013b61287044:JlP9baaBeI9m+oFBaIk/weVuyu6/6bQ+x1w9abVc1kZwtkP5IgHQBQ==",
    "key_digest": "639673a7ed8cd7188e75ed60a2e24e5752119d27b642db367cf747dd02bbdb6c",
    "environment": "588fbfee-d572-4627-8a83-17c65702ad5d",
    "folder": null,
    "override": null,
    "path": "/",
    "tags": [],
    "type": "static",
    "version": 1,
    "created_at": "2025-09-25T07:48:21.865291Z",
    "updated_at": "2025-09-25T07:48:21.865303Z"
  },
  {
    "id": "b2a7f67f-3d59-4dd8-8462-4a7f17d63bd3",
    "key": "ph:v1:084a19c4c7a6b7581646467a0d793c7a3e6c23796b825737d7140861b261193e:d/bTNZvpipr86YXHbPVcMkIfpIzVAt9SsFl4vjqTgooD5IZ9ZbTuYMoGi1QBOmmpi6Z0LRuRuBsP5EjdsfHKUw==",
    "value": "ph:v1:83105db4144674fbda57e41d572e949d00e5fddda4962924d814d99f6f7be642:8joUdNCOQ/VsJ66ZBU1B7hgx6LqVfCkJ1va8I58ZYGz/ihMz2bnDGLmvmTrxPbB5lNUU0NFv4LsZg32B",
    "comment": "ph:v1:2c265f9b643349cfa196ad27ab105b70e2e6aea7f7cb17d60928f7249ebb0e1a:faBnvpajNcXnYbmamDwpbRDXV2Kq5PwhDinlfWLYrfTbT9JzEltx0A==",
    "key_digest": "7ecc5e08ea64b9b898f275ca6b7b44b6b7da50923491e1d6f978adcde40420dc",
    "environment": "588fbfee-d572-4627-8a83-17c65702ad5d",
    "folder": null,
    "override": null,
    "path": "/",
    "tags": [],
    "type": "static",
    "version": 1,
    "created_at": "2025-09-25T07:48:21.876136Z",
    "updated_at": "2025-09-25T07:48:21.876142Z"
  }
]`

// ---- mock server ------------------------------------------------------------

type mockPhaseServer struct {
	*httptest.Server

	secretsBody  string
	mu           sync.Mutex
	postPayloads []map[string]interface{}
	putPayloads  []map[string]interface{}
	deletedIDs   []string
	postCalls    int32
	putCalls     int32
	deleteCalls  int32
}

func newMockPhaseServer() *mockPhaseServer {
	return newMockPhaseServerWithFixture(secretsFixture)
}

func newMockPhaseServerWithFixture(fixture string) *mockPhaseServer {
	ms := &mockPhaseServer{secretsBody: fixture}
	mux := http.NewServeMux()
	mux.HandleFunc("/service/secrets/tokens/", ms.handleTokens)
	mux.HandleFunc("/service/secrets/", ms.handleSecrets)
	ms.Server = httptest.NewServer(mux)
	return ms
}

func (ms *mockPhaseServer) handleTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, tokensFixture)
}

func (ms *mockPhaseServer) handleSecrets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		fmt.Fprint(w, ms.secretsBody)
	case http.MethodPost:
		atomic.AddInt32(&ms.postCalls, 1)
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ms.mu.Lock()
		ms.postPayloads = append(ms.postPayloads, body)
		ms.mu.Unlock()
	case http.MethodPut:
		atomic.AddInt32(&ms.putCalls, 1)
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ms.mu.Lock()
		ms.putPayloads = append(ms.putPayloads, body)
		ms.mu.Unlock()
	case http.MethodDelete:
		atomic.AddInt32(&ms.deleteCalls, 1)
		var body map[string][]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		ms.mu.Lock()
		ms.deletedIDs = append(ms.deletedIDs, body["secrets"]...)
		ms.mu.Unlock()
	}
}

func newTestClient(t *testing.T, srv *mockPhaseServer) *Phase {
	t.Helper()
	p, err := New(testToken, srv.URL, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// ---- tests ------------------------------------------------------------------

func TestIntegrationGet(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	secrets, err := p.Get(GetOptions{AppName: "example-app", EnvName: "development"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
	for _, s := range secrets {
		if s.Key == "" {
			t.Error("secret has empty Key")
		}
		if s.Value == "" {
			t.Error("secret has empty Value")
		}
		if s.Application != "example-app" {
			t.Errorf("expected Application=example-app, got %q", s.Application)
		}
		if s.Environment != "Development" {
			t.Errorf("expected Environment=Development, got %q", s.Environment)
		}
		if s.Path != "/" {
			t.Errorf("expected Path=/, got %q", s.Path)
		}
	}
}

func TestIntegrationGetSingleKey(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	// First a full Get to learn the real key names
	all, err := p.Get(GetOptions{AppName: "example-app", EnvName: "development"})
	if err != nil {
		t.Fatalf("Get all: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected at least one secret")
	}
	targetKey := all[0].Key

	// Now fetch by key name
	got, err := p.Get(GetOptions{AppName: "example-app", EnvName: "development", Keys: []string{targetKey}})
	if err != nil {
		t.Fatalf("Get single: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(got))
	}
	if got[0].Key != targetKey {
		t.Errorf("expected key %q, got %q", targetKey, got[0].Key)
	}
}

func TestIntegrationCreate(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	err := p.Create(CreateOptions{
		AppName:       "example-app",
		EnvName:       "development",
		KeyValuePairs: []KeyValuePair{{Key: "NEW_KEY", Value: "new_value"}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if atomic.LoadInt32(&srv.postCalls) != 1 {
		t.Fatalf("expected 1 POST, got %d", srv.postCalls)
	}

	srv.mu.Lock()
	payload := srv.postPayloads[0]
	srv.mu.Unlock()

	secrets, ok := payload["secrets"].([]interface{})
	if !ok || len(secrets) != 1 {
		t.Fatalf("expected 1 secret in POST body, got %v", payload)
	}
	sec := secrets[0].(map[string]interface{})
	for _, field := range []string{"key", "value", "keyDigest", "path"} {
		if v, _ := sec[field].(string); v == "" {
			t.Errorf("POST payload missing or empty field %q", field)
		}
	}
	// key and value must be Phase ciphertexts
	if k, _ := sec["key"].(string); len(k) < 5 || k[:3] != "ph:" {
		t.Errorf("key is not a Phase ciphertext: %q", sec["key"])
	}
}

func TestIntegrationUpdate(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	// Discover a real key name via Get
	all, err := p.Get(GetOptions{AppName: "example-app", EnvName: "development"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	targetKey := all[0].Key

	err = p.Update(UpdateOptions{
		AppName: "example-app",
		EnvName: "development",
		Key:     targetKey,
		Value:   "updated_value",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if atomic.LoadInt32(&srv.putCalls) != 1 {
		t.Fatalf("expected 1 PUT, got %d", srv.putCalls)
	}

	srv.mu.Lock()
	payload := srv.putPayloads[0]
	srv.mu.Unlock()

	secrets, ok := payload["secrets"].([]interface{})
	if !ok || len(secrets) != 1 {
		t.Fatalf("expected 1 secret in PUT body, got %v", payload)
	}
	sec := secrets[0].(map[string]interface{})
	if id, _ := sec["id"].(string); id != "fca7e863-85bc-4969-9db0-b5c678e4489e" {
		t.Errorf("PUT sent wrong secret ID: %q", id)
	}
	if v, _ := sec["value"].(string); len(v) < 5 || v[:3] != "ph:" {
		t.Errorf("updated value is not a Phase ciphertext: %q", v)
	}
}

func TestIntegrationUpdateMissingKey(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	err := p.Update(UpdateOptions{
		AppName: "example-app",
		EnvName: "development",
		Key:     "KEY_THAT_DOES_NOT_EXIST",
		Value:   "x",
	})
	if err == nil {
		t.Fatal("expected error for missing key, got nil")
	}
	var notFound *ErrSecretNotFound
	if !errors.As(err, &notFound) {
		t.Errorf("expected *ErrSecretNotFound, got %T: %v", err, err)
	}
	if notFound.Key != "KEY_THAT_DOES_NOT_EXIST" {
		t.Errorf("expected Key=KEY_THAT_DOES_NOT_EXIST, got %q", notFound.Key)
	}
	if atomic.LoadInt32(&srv.putCalls) != 0 {
		t.Error("PUT should not be called when key is not found")
	}
}

func TestIntegrationDelete(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	// Discover a real key name via Get
	all, err := p.Get(GetOptions{AppName: "example-app", EnvName: "development"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	targetKey := all[0].Key

	keysNotFound, err := p.Delete(DeleteOptions{
		AppName:      "example-app",
		EnvName:      "development",
		KeysToDelete: []string{targetKey},
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(keysNotFound) != 0 {
		t.Errorf("expected no keys-not-found, got %v", keysNotFound)
	}
	if atomic.LoadInt32(&srv.deleteCalls) != 1 {
		t.Fatalf("expected 1 DELETE, got %d", srv.deleteCalls)
	}

	srv.mu.Lock()
	ids := srv.deletedIDs
	srv.mu.Unlock()

	if len(ids) != 1 || ids[0] != "fca7e863-85bc-4969-9db0-b5c678e4489e" {
		t.Errorf("DELETE sent wrong IDs: %v", ids)
	}
}

func TestIntegrationDeleteMissingKey(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()
	p := newTestClient(t, srv)

	keysNotFound, err := p.Delete(DeleteOptions{
		AppName:      "example-app",
		EnvName:      "development",
		KeysToDelete: []string{"GHOST_KEY"},
	})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(keysNotFound) != 1 || keysNotFound[0] != "GHOST_KEY" {
		t.Errorf("expected [GHOST_KEY] in not-found list, got %v", keysNotFound)
	}
	if atomic.LoadInt32(&srv.deleteCalls) != 0 {
		t.Error("DELETE should not be called when no IDs were resolved")
	}
}

// TestIntegrationUpdatePathScoped verifies that when two secrets share the same
// key name but live in different paths, Update with SourcePath only touches the
// secret in the specified path and not the first match it encounters.
func TestIntegrationUpdatePathScoped(t *testing.T) {
	// Both secrets in the fixture share the same encrypted key name but have
	// paths "/alpha" and "/beta". We update with SourcePath="/beta" and confirm
	// the PUT payload carries the ID of the /beta secret, not the /alpha one.
	srv := newMockPhaseServerWithFixture(secretsFixtureMultiPath)
	defer srv.Close()
	p := newTestClient(t, srv)

	// Discover the shared key name from a Get (no path filter — returns both).
	all, err := p.Get(GetOptions{AppName: "example-app", EnvName: "development"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("expected secrets, got none")
	}
	sharedKey := all[0].Key // both secrets decrypt to the same key name

	err = p.Update(UpdateOptions{
		AppName:    "example-app",
		EnvName:    "development",
		Key:        sharedKey,
		Value:      "new_value",
		SourcePath: "/beta",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if atomic.LoadInt32(&srv.putCalls) != 1 {
		t.Fatalf("expected 1 PUT, got %d", srv.putCalls)
	}

	srv.mu.Lock()
	payload := srv.putPayloads[0]
	srv.mu.Unlock()

	secrets, _ := payload["secrets"].([]interface{})
	sec := secrets[0].(map[string]interface{})
	// Must be the /beta secret's ID, not /alpha's
	if id, _ := sec["id"].(string); id != "b2a7f67f-3d59-4dd8-8462-4a7f17d63bd3" {
		t.Errorf("expected /beta secret ID, got %q (wrong path matched)", id)
	}
}

// TestGetConcurrentRaceFree verifies that concurrent Get calls do not race on
// the shared secretsCache. Run with -race to catch unsynchronised access.
func TestGetConcurrentRaceFree(t *testing.T) {
	srv := newMockPhaseServer()
	defer srv.Close()

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)

	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			p, err := New(testToken, srv.URL, false)
			if err != nil {
				errs[i] = err
				return
			}
			_, errs[i] = p.Get(GetOptions{AppName: "example-app", EnvName: "development"})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}
