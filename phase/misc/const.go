package misc

import (
	"regexp"
)

const (
	Version           = "2.0.0"
	PhVersion         = "v1"
	PhaseCloudAPIHost = "https://console.phase.dev"
)

var (
	VerifySSL  = true
	PhaseDebug = false
)

var (

	// Compiled regex patterns
	PssUserPattern    = regexp.MustCompile(`^pss_user:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$`)
	PssServicePattern = regexp.MustCompile(`^pss_service:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$`)

	// Regex to identify secret references
	SecretRefRegex = regexp.MustCompile(`\$\{([^}]+)\}`)
)

type Environment struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	EnvType string `json:"env_type"`
}

type EnvironmentKey struct {
	ID          string      `json:"id"`
	Environment Environment `json:"environment"`
	IdentityKey string      `json:"identity_key"`
	WrappedSeed string      `json:"wrapped_seed"`
	WrappedSalt string      `json:"wrapped_salt"`
	CreatedAt   string      `json:"created_at"`
	UpdatedAt   string      `json:"updated_at"`
	DeletedAt   *string     `json:"deleted_at"`
	User        *string     `json:"user"`
}

type App struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Encryption      string           `json:"encryption"`
	EnvironmentKeys []EnvironmentKey `json:"environment_keys"`
}

type Organisation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AppKeyResponse struct {
	UserID          string        `json:"user_id"`
	AccountID       string        `json:"account_id"`
	Organisation    *Organisation `json:"organisation"`
	OfflineEnabled  bool          `json:"offline_enabled"`
	WrappedKeyShare string        `json:"wrapped_key_share"`
	Apps            []App         `json:"apps"`
}

type GetContextOptions struct {
	AppName string
	AppID   string
	EnvName string
}

type FindEnvironmentKeyOptions struct {
	EnvName string
	AppName string
	AppID   string
}
