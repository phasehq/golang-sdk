# Phase Go SDK

The Phase Go SDK provides end-to-end encrypted secret management for your applications. Pure Go — no CGO or system dependencies required.

## Features

- End-to-end encrypted secret CRUD operations
- Cross-environment and cross-application secret referencing
- Dynamic secrets with lease management
- Personal secret overrides
- Bulk operations (multi-key get, bulk create, bulk delete)
- Tag and path-based filtering
- Pure Go — no CGO, no libsodium

### Secret Referencing Syntax

| Reference Syntax                           | Application      | Environment      | Path                              | Secret Key            | Description                                                 |
|-------------------------------------------|------------------|------------------|-----------------------------------|------------------------|-------------------------------------------------------------|
| `${KEY}`                                   | Same application | Same environment | `/`                               | KEY                   | Local reference in the same environment and root path (/).  |
| `${staging.DEBUG}`                         | Same application | `staging`        | `/` (root of staging environment) | DEBUG                 | Cross-environment reference to a secret at the root (/).    |
| `${prod./frontend/SECRET_KEY}`             | Same application | `prod`           | `/frontend/`                      | SECRET_KEY            | Cross-environment reference to a secret in a specific path. |
| `${/backend/payments/STRIPE_KEY}`          | Same application | Same environment | `/backend/payments/`              | STRIPE_KEY            | Local reference with a specified path.                      |
| `${backend_api::production./frontend/KEY}` | `backend_api`    | `production`     | `/frontend/`                      | KEY                   | Cross-application reference to a secret in a specific path. |

## Installation

```bash
go get github.com/phasehq/golang-sdk/v2/phase
```

```go
import "github.com/phasehq/golang-sdk/v2/phase"
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/phasehq/golang-sdk/v2/phase"
)

func main() {
    // Accepts service tokens (pss_service:v1/v2) and user tokens (pss_user:v1)
    token := "pss_service:v1:....."
    host := "https://console.phase.dev" // Change for self-hosted instances
    debug := false

    p, err := phase.New(token, host, debug)
    if err != nil {
        log.Fatalf("Failed to initialize Phase client: %v", err)
    }

    // Get secrets
    secrets, err := p.Get(phase.GetOptions{
        EnvName: "Development",
        AppName: "MyApp",
    })
    if err != nil {
        log.Fatalf("Failed to get secrets: %v", err)
    }

    for _, s := range secrets {
        fmt.Printf("%s=%s\n", s.Key, s.Value)
    }
}
```

## Usage

### Creating Secrets

```go
err := p.Create(phase.CreateOptions{
    KeyValuePairs: []phase.KeyValuePair{
        {Key: "API_KEY", Value: "my_api_secret"},
        {Key: "DB_HOST", Value: "localhost:5432"},
    },
    EnvName: "Production",
    AppName: "MyApp",       // Or use AppID: "app-id-here"
    Path:    "/api/config", // Optional, defaults to /
})
```

### Getting Secrets

```go
// Get all secrets in an environment
secrets, err := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
})

// Get specific keys
secrets, err := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
    Keys:    []string{"API_KEY", "DB_HOST"},
})

// Filter by tag and path
secrets, err := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
    Tag:     "backend",
    Path:    "/api/config",
})

// Include dynamic secrets with leases
secrets, err := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
    Dynamic: true,
    Lease:   true,
})

// Get raw values without resolving ${REF} references
secrets, err := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
    Raw:     true,
})
```

Each secret is returned as a `SecretResult`:

```go
type SecretResult struct {
    Key          string
    Value        string
    Comment      string
    Path         string
    Application  string
    Environment  string
    Tags         []string
    Overridden   bool         // true if a personal override is active
    IsDynamic    bool         // true for dynamic secrets
    DynamicGroup string       // provider group label for dynamic secrets
}
```

### Updating a Secret

```go
result, err := p.Update(phase.UpdateOptions{
    EnvName: "Production",
    AppName: "MyApp",
    Key:     "API_KEY",
    Value:   "my_updated_api_secret",
})
```

### Deleting Secrets

```go
keysNotFound, err := p.Delete(phase.DeleteOptions{
    EnvName:      "Production",
    AppName:      "MyApp",
    KeysToDelete: []string{"API_KEY", "OLD_SECRET"},
    Path:         "/api/config", // Optional
})

if len(keysNotFound) > 0 {
    fmt.Printf("Keys not found: %v\n", keysNotFound)
}
```

### Secret References

`Get()` automatically resolves `${REF}` syntax in secret values before returning results, including cross-environment and cross-application references:

```go
// References are resolved automatically — no extra steps needed
secrets, _ := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
})

for _, s := range secrets {
    // s.Value already has all ${REF} references resolved
    fmt.Printf("%s=%s\n", s.Key, s.Value)
}
```

To get raw, unresolved values (e.g. for display or inspection), set `Raw: true`:

```go
secrets, _ := p.Get(phase.GetOptions{
    EnvName: "Production",
    AppName: "MyApp",
    Raw:     true,
})

for _, s := range secrets {
    // s.Value contains the original ${REF} syntax, not the resolved value
    fmt.Printf("%s=%s\n", s.Key, s.Value)
}
```

## Overrides

Create or update a personal override for a secret:

```go
// Create a secret with an override value
err := p.Create(phase.CreateOptions{
    KeyValuePairs: []phase.KeyValuePair{
        {Key: "API_URL", Value: "https://api.example.com"},
    },
    EnvName:       "Development",
    AppName:       "MyApp",
    OverrideValue: "http://localhost:3000", // Personal override
})

// Update override for existing secret
_, err := p.Update(phase.UpdateOptions{
    EnvName:  "Development",
    AppName:  "MyApp",
    Key:      "API_URL",
    Value:    "http://localhost:4000",
    Override: true,
})

// Toggle override on/off
_, err := p.Update(phase.UpdateOptions{
    EnvName:        "Development",
    AppName:        "MyApp",
    Key:            "API_URL",
    ToggleOverride: true,
})
```

For more information, see the [Phase Docs](https://docs.phase.dev/sdks/go).

If you encounter any issues or have questions, please file an issue on the [GitHub repository](https://github.com/phasehq/golang-sdk) or contact our support team over [Slack](https://slack.phase.dev).
