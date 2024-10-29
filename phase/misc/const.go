package misc

import (
	"regexp"
)

const (
	Version           = "1.0.1"
	PhVersion         = "v1"
	PhaseCloudAPIHost = "https://console.phase.dev"
)

var (
	VerifySSL  = false
	PhaseDebug = false
)

var (

	// Compiled regex patterns
	PssUserPattern    = regexp.MustCompile(`^pss_user:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$`)
	PssServicePattern = regexp.MustCompile(`^pss_service:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64}):([a-fA-F0-9]{64})$`)

	// CrossEnvPattern   = regexp.MustCompile(`\$\{(.+?)\.(.+?)\}`)
	// LocalRefPattern   = regexp.MustCompile(`\$\{([^.]+?)\}`)

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

type AppKeyResponse struct {
	WrappedKeyShare string `json:"wrapped_key_share"`
	Apps            []App  `json:"apps"`
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
