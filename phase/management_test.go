package phase

// Wire-level tests for the management API against a mock server: request paths,
// query parameters, snake_case bodies, 2xx handling and typed errors.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Auth   string
	Body   map[string]interface{}
}

type mockManagementServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
	// responses maps "METHOD path" to a status code and body
	responses map[string]struct {
		status int
		body   string
	}
}

func newMockManagementServer() *mockManagementServer {
	ms := &mockManagementServer{responses: map[string]struct {
		status int
		body   string
	}{}}
	ms.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := recordedRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization")}
		if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
			_ = json.Unmarshal(raw, &rec.Body)
		}
		ms.mu.Lock()
		ms.requests = append(ms.requests, rec)
		resp, ok := ms.responses[r.Method+" "+r.URL.Path]
		ms.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"App not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.status)
		_, _ = w.Write([]byte(resp.body))
	}))
	return ms
}

func (ms *mockManagementServer) respond(method, path string, status int, body string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.responses[method+" "+path] = struct {
		status int
		body   string
	}{status, body}
}

func (ms *mockManagementServer) last() recordedRequest {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	return ms.requests[len(ms.requests)-1]
}

func TestManagementCreateApp(t *testing.T) {
	srv := newMockManagementServer()
	defer srv.Close()
	srv.respond("POST", "/service/public/v1/apps/", 201, `{"id":"app-1","name":"payments","description":"","sseEnabled":true,
		"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z",
		"environments":[{"id":"env-1","name":"Development","envType":"dev","index":0}]}`)
	p, err := New(testToken, srv.URL, false)
	if err != nil {
		t.Fatal(err)
	}

	app, err := p.CreateApp(CreateAppOptions{Name: "payments", Environments: []string{"dev", "prod"}})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if !app.SSEEnabled || app.ID != "app-1" || len(app.Environments) != 1 || app.Environments[0].EnvType != "dev" {
		t.Errorf("response not decoded: %+v", app)
	}

	req := srv.last()
	if req.Auth != "Bearer User 9d5356eae3618da040c61b50349f291d4db9c74da5315caeb65da25ee5d0d8b7" {
		t.Errorf("unexpected Authorization header %q", req.Auth)
	}
	if req.Body["name"] != "payments" {
		t.Errorf("name not sent: %v", req.Body)
	}
	if envs, _ := req.Body["environments"].([]interface{}); len(envs) != 2 {
		t.Errorf("environments not sent: %v", req.Body)
	}
	if _, present := req.Body["description"]; present {
		t.Error("empty description must be omitted so the server keeps its default")
	}
}

func TestManagementListAndDelete(t *testing.T) {
	srv := newMockManagementServer()
	defer srv.Close()
	srv.respond("GET", "/service/public/v1/environments/", 200, `{"data":[{"id":"e1","name":"Development","envType":"dev","index":0},{"id":"e2","name":"Production","envType":"prod","index":2}]}`)
	srv.respond("DELETE", "/service/public/v1/apps/app-1/", 204, "")
	p, _ := New(testToken, srv.URL, false)

	envs, err := p.ListEnvironments("app-1")
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	if len(envs) != 2 || envs[1].Name != "Production" || envs[1].Index != 2 {
		t.Errorf("envelope not decoded: %+v", envs)
	}
	if q := srv.last().Query; q != "app_id=app-1" {
		t.Errorf("expected app_id query, got %q", q)
	}

	if err := p.DeleteApp("app-1"); err != nil {
		t.Errorf("a 204 with an empty body must succeed, got %v", err)
	}
	if req := srv.last(); req.Method != "DELETE" || req.Path != "/service/public/v1/apps/app-1/" {
		t.Errorf("unexpected delete request %+v", req)
	}
}

func TestManagementNotFoundIsTypedAPIError(t *testing.T) {
	srv := newMockManagementServer()
	defer srv.Close()
	p, _ := New(testToken, srv.URL, false)

	_, err := p.GetApp("missing")
	var apiErr *network.APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 404 || apiErr.Detail != "App not found" {
		t.Fatalf("expected APIError 404 with server detail, got %T %v", err, err)
	}
}

func TestManagementServiceAccountBodies(t *testing.T) {
	srv := newMockManagementServer()
	defer srv.Close()
	srv.respond("POST", "/service/public/v1/service-accounts/", 201, `{"id":"sa-1","name":"ci","role":{"id":"r1","name":"Developer"},
		"initialToken":{"id":"t1","name":"Default","expiresAt":null,"token":"pss_service:v2:a:b:c:d","bearerToken":"ServiceAccount a"}}`)
	srv.respond("PUT", "/service/public/v1/service-accounts/sa-1/access/", 200, `{"id":"sa-1","name":"ci","apps":[{"id":"app-1","name":"payments","environments":[{"id":"e1","name":"Development","envType":"dev"}]}]}`)
	srv.respond("POST", "/service/public/v1/service-accounts/sa-1/tokens/", 201, `{"id":"t2","name":"deploy","expiresAt":"2027-01-01T00:00:00Z","token":"pss_service:v2:w:x:y:z","bearerToken":"ServiceAccount w"}`)
	srv.respond("POST", "/service/public/v1/members/invites/", 201, `{"id":"inv-1","inviteeEmail":"dev@example.com","role":{"id":"r1","name":"Developer"},"valid":true}`)
	p, _ := New(testToken, srv.URL, false)

	sa, err := p.CreateServiceAccount(CreateServiceAccountOptions{Name: "ci", RoleID: "r1", TokenName: "Default"})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if sa.InitialToken == nil || sa.InitialToken.Token != "pss_service:v2:a:b:c:d" || sa.Role.Name != "Developer" {
		t.Errorf("initial token not decoded: %+v", sa)
	}
	if body := srv.last().Body; body["role_id"] != "r1" || body["token_name"] != "Default" {
		t.Errorf("service account body must use snake_case keys: %v", body)
	}

	if _, err := p.SetServiceAccountAccess("sa-1", []AppAccessInput{{ID: "app-1", EnvironmentIDs: []string{"e1", "e2"}}}); err != nil {
		t.Fatalf("SetServiceAccountAccess: %v", err)
	}
	apps, _ := srv.last().Body["apps"].([]interface{})
	if len(apps) != 1 {
		t.Fatalf("apps not sent: %v", srv.last().Body)
	}
	if app := apps[0].(map[string]interface{}); app["id"] != "app-1" || len(app["environments"].([]interface{})) != 2 {
		t.Errorf("access body must be {id, environments:[ids]}: %v", app)
	}

	tok, err := p.CreateServiceAccountToken("sa-1", CreateServiceAccountTokenOptions{Name: "deploy", ExpiresIn: 3600})
	if err != nil {
		t.Fatalf("CreateServiceAccountToken: %v", err)
	}
	if tok.Token != "pss_service:v2:w:x:y:z" || tok.ExpiresAt == nil {
		t.Errorf("token not decoded: %+v", tok)
	}
	if body := srv.last().Body; body["expires_in"] != float64(3600) || body["expires_at"] != nil {
		t.Errorf("expires_in must be sent as an integer without expires_at: %v", body)
	}
	if _, err := p.CreateServiceAccountToken("sa-1", CreateServiceAccountTokenOptions{Name: "x", ExpiresAt: "2027-01-01T00:00:00Z", ExpiresIn: 5}); err != nil {
		t.Fatal(err)
	}
	if body := srv.last().Body; body["expires_at"] != "2027-01-01T00:00:00Z" || body["expires_in"] != nil {
		t.Errorf("expires_at must take precedence over expires_in: %v", body)
	}

	inv, err := p.CreateInvite(CreateInviteOptions{Email: "dev@example.com", RoleID: "r1"})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	if inv.ID != "inv-1" || !inv.Valid {
		t.Errorf("invite not decoded: %+v", inv)
	}
	if body := srv.last().Body; body["email"] != "dev@example.com" || body["role_id"] != "r1" {
		t.Errorf("invite body: %v", body)
	}
}

func TestManagementOfflineModeRefused(t *testing.T) {
	p, _ := New(testToken, "http://127.0.0.1:1", false)
	p.SetOfflineConfig(&OfflineConfig{CacheDir: t.TempDir(), Offline: true})
	if _, err := p.ListApps(); err == nil {
		t.Fatal("management calls must fail fast in offline mode")
	}
}
