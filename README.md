# Phase Secrets Management SDK for Go

The Phase Secrets SDK provides a Go package for managing secrets in your application environments using the Phase service. This SDK allows you to create, retrieve, update, and delete secrets with end-to-end encryption using just a few lines of code.

## Features

- End-to-end encrypted secret CRUD operations
- Cross-environment and local environment secret referencing
- Bulk secret operations
- Pure Golang (No CGO)

### Secret Referencing Syntax

| Reference Syntax                           | Application      | Environment      | Path                              | Secret Key            | Description                                                 |
|-------------------------------------------|------------------|------------------|-----------------------------------|------------------------|-------------------------------------------------------------|
| `${KEY}`                                   | Same application | Same environment | `/`                               | KEY                   | Local reference in the same environment and root path (/).  |
| `${staging.DEBUG}`                         | Same application | `staging`        | `/` (root of staging environment) | DEBUG                 | Cross-environment reference to a secret at the root (/).    |
| `${prod./frontend/SECRET_KEY}`             | Same application | `prod`           | `/frontend/`                      | SECRET_KEY            | Cross-environment reference to a secret in a specific path. |
| `${/backend/payments/STRIPE_KEY}`          | Same application | Same environment | `/backend/payments/`              | STRIPE_KEY            | Local reference with a specified path.                      |
| `${backend_api::production./frontend/KEY}` | `backend_api`    | `production`     | `/frontend/`                      | KEY                   | Cross-application reference to a secret in a specific path. |

## Installation

### Installing the SDK

To start using the Phase SDK in your Go project, install it using `go get`:

```bash
go get github.com/phasehq/golang-sdk/phase
```

Import the SDK in your Go files:

```go
import "github.com/phasehq/golang-sdk/phase"
```

## Configuration

Initialize the SDK with your service token and host information:

```go
package main

import (
    "log"
    "github.com/phasehq/golang-sdk/phase"
)

func main() {
    serviceToken := "pss_service:v1:....."
    host := "https://console.phase.dev" // Change this for a self-hosted instance of Phase
    debug := false // For logging verbosity, disable in production

    phaseClient := phase.Init(serviceToken, host, debug)
    if phaseClient == nil {
        log.Fatal("Failed to initialize Phase client")
    }
}
```

## Usage

### Creating a Secret

Define key-value pairs, specify the environment and application (using either name or ID), and optionally set paths for each key:

```go
opts := phase.CreateSecretsOptions{
    KeyValuePairs: []map[string]string{
        {"API_KEY": "api_secret"},
    },
    EnvName:    "Production",
    AppName:    "MyApp", // Or use AppID: "app-id-here"
    SecretPath: map[string]string{"API_KEY": "/api/keys"}, // Optional, default path: /
}

err := phaseClient.Create(opts)
if err != nil {
    log.Fatalf("Failed to create secret: %v", err)
}
```

### Retrieving a Secret

Provide the environment name, application (name or ID), key to find, and optionally a tag and path:

```go
getOpts := phase.GetSecretOptions{
    EnvName:   "Production",
    AppName:   "MyApp", // Or use AppID: "app-id-here"
    KeyToFind: "API_KEY",
}

secret, err := phaseClient.Get(getOpts)
if err != nil {
    log.Fatalf("Failed to get secret: %v", err)
} else {
    log.Printf("Secret: %+v", secret)
}
```

### Updating a Secret

Provide the new value along with the environment name, application (name or ID), key, and optionally the path:

```go
updateOpts := phase.SecretUpdateOptions{
    EnvName:    "Production",
    AppName:    "MyApp", // Or use AppID: "app-id-here"
    Key:        "API_KEY",
    Value:      "my_updated_api_secret",
    SecretPath: "/api/keys", // Optional, default path: /
}

err := phaseClient.Update(updateOpts)
if err != nil {
    log.Fatalf("Failed to update secret: %v", err)
}
```

### Deleting a Secret

Specify the environment name, application (name or ID), key to delete, and optionally the path:

```go
deleteOpts := phase.DeleteSecretOptions{
    EnvName:     "Production",
    AppName:     "MyApp", // Or use AppID: "app-id-here"
    KeyToDelete: "API_KEY",
    SecretPath:  "/api/keys", // Optional, default path: /
}

err := phaseClient.Delete(deleteOpts)
if err != nil {
    log.Fatalf("Failed to delete secret: %v", err)
}
```

For more information on advanced usage, including detailed API references and best practices, please refer to the [Phase Docs](https://docs.phase.dev/sdks/go).


If you encounter any issues or have questions, please file an issue on the [GitHub repository](https://github.com/phasehq/golang-sdk) or contact our support team over [Slack](https://slack.phase.dev).
