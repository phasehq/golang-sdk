package phase

// Management API: apps, environments, roles, members, invites and service accounts.
//
// These wrap the Phase public REST API ({host}/service/public/v1/...). Unlike the
// secret methods, which encrypt client-side, the management endpoints exchange plain
// JSON; the server handles all key wrapping. Responses are camelCase JSON and request
// bodies are snake_case, matching the console. A pss_service:v2 (ServiceAccount) or
// pss_user (User) token is required.

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/phasehq/golang-sdk/v2/phase/network"
)

// App is a Phase application.
type App struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SSEEnabled  bool   `json:"sseEnabled"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	// Environments is only populated by CreateApp.
	Environments []Environment `json:"environments,omitempty"`
}

// Environment is an environment within an app.
type Environment struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	EnvType   string `json:"envType"` // dev, staging, prod or custom
	Index     int    `json:"index"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// RoleRef identifies a role by ID and name.
type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Role is an organisation role. Permissions is only populated by GetRole.
type Role struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Color       string          `json:"color"`
	IsDefault   bool            `json:"isDefault"`
	CreatedAt   string          `json:"createdAt"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
}

// Member is an organisation member. Apps is only populated by the access methods.
type Member struct {
	ID        string      `json:"id"`
	Username  string      `json:"username"`
	FullName  string      `json:"fullName"`
	Email     string      `json:"email"`
	Role      *RoleRef    `json:"role"`
	CreatedAt string      `json:"createdAt"`
	UpdatedAt string      `json:"updatedAt"`
	Apps      []AppAccess `json:"apps,omitempty"`
}

// Invite is a pending organisation invite.
type Invite struct {
	ID           string     `json:"id"`
	InviteeEmail string     `json:"inviteeEmail"`
	Role         *RoleRef   `json:"role"`
	InvitedBy    *InvitedBy `json:"invitedBy"`
	CreatedAt    string     `json:"createdAt"`
	ExpiresAt    string     `json:"expiresAt"`
	Valid        bool       `json:"valid"`
}

// InvitedBy identifies who created an invite: a member (Email) or a service account (Name).
type InvitedBy struct {
	Type  string `json:"type"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// ServiceAccount is an organisation service account. Tokens and Apps are only
// populated by the detail methods; InitialToken only by CreateServiceAccount.
type ServiceAccount struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Role         *RoleRef              `json:"role"`
	CreatedAt    string                `json:"createdAt"`
	UpdatedAt    string                `json:"updatedAt"`
	Tokens       []ServiceAccountToken `json:"tokens,omitempty"`
	Apps         []AppAccess           `json:"apps,omitempty"`
	InitialToken *ServiceAccountToken  `json:"initialToken,omitempty"`
}

// ServiceAccountToken describes a service account token. Token (the full
// pss_service:v2 string) and BearerToken are only returned when the token is created.
type ServiceAccountToken struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	CreatedAt   string  `json:"createdAt"`
	ExpiresAt   *string `json:"expiresAt"`
	Token       string  `json:"token,omitempty"`
	BearerToken string  `json:"bearerToken,omitempty"`
}

// AppAccess lists the environments of an app that a principal can access.
type AppAccess struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Environments []EnvironmentRef `json:"environments"`
}

// EnvironmentRef identifies an environment.
type EnvironmentRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	EnvType string `json:"envType"`
}

// AppAccessInput grants access to the listed environment IDs of an app.
type AppAccessInput struct {
	ID             string   `json:"id"`
	EnvironmentIDs []string `json:"environments"`
}

// CREATE APP
type CreateAppOptions struct {
	Name         string
	Description  string
	Environments []string // custom environment names; Development, Staging and Production are created when empty
}

// UPDATE APP
type UpdateAppOptions struct {
	Name        string  // empty leaves the name unchanged
	Description *string // nil leaves the description unchanged; an empty string clears it
}

// CREATE INVITE
type CreateInviteOptions struct {
	Email  string
	RoleID string
}

// CREATE SERVICE ACCOUNT
type CreateServiceAccountOptions struct {
	Name      string
	RoleID    string
	TokenName string // name of the initial token; defaults to "Default"
	TeamID    string // optional owning team
}

// UPDATE SERVICE ACCOUNT
type UpdateServiceAccountOptions struct {
	Name   string // empty leaves the name unchanged
	RoleID string // empty leaves the role unchanged
}

// CREATE SERVICE ACCOUNT TOKEN
type CreateServiceAccountTokenOptions struct {
	Name      string
	ExpiresAt string // RFC 3339 timestamp with offset; takes precedence over ExpiresIn
	ExpiresIn int    // seconds until expiry; when both are unset the token never expires
}

type listEnvelope[T any] struct {
	Data []T `json:"data"`
}

// publicAPI performs a request against the public REST API and decodes the JSON response into out.
func (p *Phase) publicAPI(method, path string, query url.Values, payload interface{}, out interface{}) error {
	if p.offlineConfig != nil && p.offlineConfig.Offline {
		return fmt.Errorf("the management API is not available in offline mode")
	}
	body, err := network.PublicAPIRequest(p.TokenType, p.AppToken, p.Host, method, path, query, payload)
	if err != nil {
		return err
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}

func listPublic[T any](p *Phase, path string, query url.Values) ([]T, error) {
	var envelope listEnvelope[T]
	if err := p.publicAPI("GET", path, query, nil, &envelope); err != nil {
		return nil, err
	}
	return envelope.Data, nil
}

// ---- Apps ----
//
// ListApps returns end-to-end encrypted apps too, but every other app and environment
// method below is refused with an authorization error unless the app has server-side
// encryption enabled (App.SSEEnabled). Apps created with CreateApp always have it.

// ListApps returns the apps the token can access.
func (p *Phase) ListApps() ([]App, error) {
	return listPublic[App](p, "v1/apps/", nil)
}

// CreateApp creates a server-side encrypted app and returns it with its environments.
func (p *Phase) CreateApp(opts CreateAppOptions) (*App, error) {
	payload := map[string]interface{}{"name": opts.Name}
	if opts.Description != "" {
		payload["description"] = opts.Description
	}
	if len(opts.Environments) > 0 {
		payload["environments"] = opts.Environments
	}
	var app App
	if err := p.publicAPI("POST", "v1/apps/", nil, payload, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

// GetApp returns a single app by ID.
func (p *Phase) GetApp(appID string) (*App, error) {
	var app App
	if err := p.publicAPI("GET", "v1/apps/"+url.PathEscape(appID)+"/", nil, nil, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

// UpdateApp renames an app and/or changes its description.
func (p *Phase) UpdateApp(appID string, opts UpdateAppOptions) (*App, error) {
	payload := map[string]interface{}{}
	if opts.Name != "" {
		payload["name"] = opts.Name
	}
	if opts.Description != nil {
		payload["description"] = *opts.Description
	}
	var app App
	if err := p.publicAPI("PUT", "v1/apps/"+url.PathEscape(appID)+"/", nil, payload, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

// DeleteApp permanently deletes an app, including its environments and secrets.
func (p *Phase) DeleteApp(appID string) error {
	return p.publicAPI("DELETE", "v1/apps/"+url.PathEscape(appID)+"/", nil, nil, nil)
}

// ---- Environments ----

// ListEnvironments returns the environments of an app that the token can access.
func (p *Phase) ListEnvironments(appID string) ([]Environment, error) {
	return listPublic[Environment](p, "v1/environments/", url.Values{"app_id": {appID}})
}

// CreateEnvironment creates a custom environment in an app.
func (p *Phase) CreateEnvironment(appID, name string) (*Environment, error) {
	var env Environment
	if err := p.publicAPI("POST", "v1/environments/", url.Values{"app_id": {appID}}, map[string]string{"name": name}, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// GetEnvironment returns a single environment by ID.
func (p *Phase) GetEnvironment(envID string) (*Environment, error) {
	var env Environment
	if err := p.publicAPI("GET", "v1/environments/"+url.PathEscape(envID)+"/", nil, nil, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// UpdateEnvironment renames an environment.
func (p *Phase) UpdateEnvironment(envID, name string) (*Environment, error) {
	var env Environment
	if err := p.publicAPI("PUT", "v1/environments/"+url.PathEscape(envID)+"/", nil, map[string]string{"name": name}, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// DeleteEnvironment permanently deletes an environment and its secrets.
func (p *Phase) DeleteEnvironment(envID string) error {
	return p.publicAPI("DELETE", "v1/environments/"+url.PathEscape(envID)+"/", nil, nil, nil)
}

// ---- Roles ----

// ListRoles returns the organisation's roles (without permission details).
func (p *Phase) ListRoles() ([]Role, error) {
	return listPublic[Role](p, "v1/roles/", nil)
}

// GetRole returns a single role, including its permissions.
func (p *Phase) GetRole(roleID string) (*Role, error) {
	var role Role
	if err := p.publicAPI("GET", "v1/roles/"+url.PathEscape(roleID)+"/", nil, nil, &role); err != nil {
		return nil, err
	}
	return &role, nil
}

// ---- Members ----

// ListMembers returns the organisation's members.
func (p *Phase) ListMembers() ([]Member, error) {
	return listPublic[Member](p, "v1/members/", nil)
}

// GetMember returns a single member by membership ID.
func (p *Phase) GetMember(memberID string) (*Member, error) {
	var member Member
	if err := p.publicAPI("GET", "v1/members/"+url.PathEscape(memberID)+"/", nil, nil, &member); err != nil {
		return nil, err
	}
	return &member, nil
}

// UpdateMemberRole assigns a new role to a member.
func (p *Phase) UpdateMemberRole(memberID, roleID string) (*Member, error) {
	var member Member
	if err := p.publicAPI("PUT", "v1/members/"+url.PathEscape(memberID)+"/", nil, map[string]string{"role_id": roleID}, &member); err != nil {
		return nil, err
	}
	return &member, nil
}

// DeleteMember removes a member from the organisation.
func (p *Phase) DeleteMember(memberID string) error {
	return p.publicAPI("DELETE", "v1/members/"+url.PathEscape(memberID)+"/", nil, nil, nil)
}

// GetMemberAccess returns the apps and environments a member can access.
func (p *Phase) GetMemberAccess(memberID string) (*Member, error) {
	var member Member
	if err := p.publicAPI("GET", "v1/members/"+url.PathEscape(memberID)+"/access/", nil, nil, &member); err != nil {
		return nil, err
	}
	return &member, nil
}

// SetMemberAccess replaces a member's app and environment access with the given set.
// An empty slice revokes all access. Only server-side encrypted apps can be granted.
func (p *Phase) SetMemberAccess(memberID string, apps []AppAccessInput) (*Member, error) {
	if apps == nil {
		apps = []AppAccessInput{}
	}
	var member Member
	if err := p.publicAPI("PUT", "v1/members/"+url.PathEscape(memberID)+"/access/", nil, map[string]interface{}{"apps": apps}, &member); err != nil {
		return nil, err
	}
	return &member, nil
}

// ---- Invites ----

// ListInvites returns the organisation's pending, unexpired invites.
func (p *Phase) ListInvites() ([]Invite, error) {
	return listPublic[Invite](p, "v1/members/invites/", nil)
}

// CreateInvite invites an email address to the organisation with the given role.
func (p *Phase) CreateInvite(opts CreateInviteOptions) (*Invite, error) {
	var invite Invite
	payload := map[string]string{"email": opts.Email, "role_id": opts.RoleID}
	if err := p.publicAPI("POST", "v1/members/invites/", nil, payload, &invite); err != nil {
		return nil, err
	}
	return &invite, nil
}

// DeleteInvite cancels a pending invite.
func (p *Phase) DeleteInvite(inviteID string) error {
	return p.publicAPI("DELETE", "v1/members/invites/"+url.PathEscape(inviteID)+"/", nil, nil, nil)
}

// ---- Service accounts ----

// ListServiceAccounts returns the organisation's service accounts.
func (p *Phase) ListServiceAccounts() ([]ServiceAccount, error) {
	return listPublic[ServiceAccount](p, "v1/service-accounts/", nil)
}

// CreateServiceAccount creates a service account with server-side key management. The
// returned InitialToken carries the full token string, which is not retrievable later.
func (p *Phase) CreateServiceAccount(opts CreateServiceAccountOptions) (*ServiceAccount, error) {
	payload := map[string]string{"name": opts.Name, "role_id": opts.RoleID}
	if opts.TokenName != "" {
		payload["token_name"] = opts.TokenName
	}
	if opts.TeamID != "" {
		payload["team_id"] = opts.TeamID
	}
	var sa ServiceAccount
	if err := p.publicAPI("POST", "v1/service-accounts/", nil, payload, &sa); err != nil {
		return nil, err
	}
	return &sa, nil
}

// GetServiceAccount returns a service account with its tokens and app access.
func (p *Phase) GetServiceAccount(serviceAccountID string) (*ServiceAccount, error) {
	var sa ServiceAccount
	if err := p.publicAPI("GET", "v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/", nil, nil, &sa); err != nil {
		return nil, err
	}
	return &sa, nil
}

// UpdateServiceAccount renames a service account and/or changes its role.
func (p *Phase) UpdateServiceAccount(serviceAccountID string, opts UpdateServiceAccountOptions) (*ServiceAccount, error) {
	payload := map[string]string{}
	if opts.Name != "" {
		payload["name"] = opts.Name
	}
	if opts.RoleID != "" {
		payload["role_id"] = opts.RoleID
	}
	var sa ServiceAccount
	if err := p.publicAPI("PUT", "v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/", nil, payload, &sa); err != nil {
		return nil, err
	}
	return &sa, nil
}

// DeleteServiceAccount deletes a service account and revokes its tokens.
func (p *Phase) DeleteServiceAccount(serviceAccountID string) error {
	return p.publicAPI("DELETE", "v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/", nil, nil, nil)
}

// SetServiceAccountAccess replaces a service account's app and environment access with
// the given set. An empty slice revokes all access. Only server-side encrypted apps can be granted.
func (p *Phase) SetServiceAccountAccess(serviceAccountID string, apps []AppAccessInput) (*ServiceAccount, error) {
	if apps == nil {
		apps = []AppAccessInput{}
	}
	var sa ServiceAccount
	if err := p.publicAPI("PUT", "v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/access/", nil, map[string]interface{}{"apps": apps}, &sa); err != nil {
		return nil, err
	}
	return &sa, nil
}

// CreateServiceAccountToken mints a new token for a service account. The full token
// string is only returned by this call.
func (p *Phase) CreateServiceAccountToken(serviceAccountID string, opts CreateServiceAccountTokenOptions) (*ServiceAccountToken, error) {
	if opts.ExpiresIn < 0 {
		return nil, fmt.Errorf("ExpiresIn must be a positive number of seconds, got %d", opts.ExpiresIn)
	}
	payload := map[string]interface{}{"name": opts.Name}
	if opts.ExpiresAt != "" {
		payload["expires_at"] = opts.ExpiresAt
	} else if opts.ExpiresIn > 0 {
		payload["expires_in"] = opts.ExpiresIn
	}
	var token ServiceAccountToken
	if err := p.publicAPI("POST", "v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens/", nil, payload, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// DeleteServiceAccountToken revokes a service account token.
func (p *Phase) DeleteServiceAccountToken(serviceAccountID, tokenID string) error {
	return p.publicAPI("DELETE", "v1/service-accounts/"+url.PathEscape(serviceAccountID)+"/tokens/"+url.PathEscape(tokenID)+"/", nil, nil, nil)
}
