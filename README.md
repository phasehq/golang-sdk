# Phase Secrets Management SDK for Go

The Phase Secrets SDK provides a Go package for managing secrets in your application environments using the Phase service. This SDK allows you to create, retrieve, update, and delete secrets with end-to-end encryption using just a few lines of code.

## Features

- End-to-end encrypted secret CRUD operations
- Cross-environment and local environment secret referencing
- Bulk secret operations

### Secret Referencing Syntax

| Reference Syntax                  | Environment      | Path                              | Secret Key            | Description                                                 |
|-----------------------------------|------------------|-----------------------------------|------------------------|-------------------------------------------------------------|
| `${KEY}`                          | Same environment | `/`                               | KEY                   | Local reference in the same environment and root path (/).  |
| `${staging.DEBUG}`                | `staging`        | `/` (root of staging environment) | DEBUG                 | Cross-environment reference to a secret at the root (/).    |
| `${prod./frontend/SECRET_KEY}`    | `prod`           | `/frontend/`                      | SECRET_KEY            | Cross-environment reference to a secret in a specific path. |
| `${/backend/payments/STRIPE_KEY}` | Same environment | `/backend/payments/`              | STRIPE_KEY            | Local reference with a specified path.                      |

## Installation

This SDK uses the `sodium` package to perform cryptographic operations, on most system you will need to install the `libsodium` library as a system dependency. Here's how you can install `libsodium` or its development packages on different platforms, including macOS, Ubuntu, Debian, Arch Linux, Alpine Linux, and Windows.

This SDK uses the `sodium` package for cryptographic operations. On most systems, you'll need to install the `libsodium` library as a system dependency.

#### macOS
```sh
brew install libsodium
```

#### Fedora
```sh
sudo dnf install libsodium-devel
```

#### Ubuntu and Debian
```sh
sudo apt-get update && sudo apt-get install libsodium-dev
```

#### Arch Linux
```sh
sudo pacman -Syu libsodium
```

#### Alpine Linux
```sh
sudo apk add libsodium-dev
```

#### Windows
For Windows, download pre-built binaries from the [libsodium GitHub releases page](https://github.com/jedisct1/libsodium/releases). Choose the appropriate version for your system architecture and follow the included instructions.

On Windows, the process is a bit different due to the variety of development environments. However, you can download pre-built binaries from the official [libsodium GitHub releases page](https://github.com/jedisct1/libsodium/releases). Choose the appropriate version for your system architecture (e.g., Win32 or Win64), download it, and follow the instructions included to integrate `libsodium` with your development environment. For development with Visual Studio, you'll typically include the header files and link against the `libsodium.lib` or `libsodium.dll` file.

If you're using a package manager like `vcpkg` or `chocolatey`, you can also find `libsodium` packages available for installation:

- Using `vcpkg`:
  ```sh
  vcpkg install libsodium
  ```
- Using `chocolatey`:
  ```sh
  choco install libsodium
  ```

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
