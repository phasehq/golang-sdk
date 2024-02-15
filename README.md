# Phase Secrets Management SDK

The Phase Secrets SDK provides a Go package for managing secrets in your application environments using the Phase service. This SDK let's you create, retrieve, update, and delete secrets, with end-to-end encryption with just a few lines of code.

## Features:

- End-to-end encrypting secret CRUD
- Cross and local env secret referencing
- Built in handling of rate limiting

### Secret referencing syntax:

| Reference syntax                  | Environment      | Path                              | Secret Key Being Referenced | Description                                                        |
| --------------------------------- | ---------------- | --------------------------------- | --------------------------- | ------------------------------------------------------------------ |
| `${KEY}`                          | same environment | `/                                | KEY                         | Local reference in the same environment and path root (/).         |
| `${staging.DEBUG}`                | `dev`            | `/` (root of staging environment) | DEBUG                       | Cross-environment reference to a secret at the root (/).           |
| `${prod./frontend/SECRET_KEY}`    | `prod`           | `/frontend/`                      | SECRET_KEY                  | Cross-environment reference to a secret in a specific path.        |
| `${/backend/payments/STRIPE_KEY}` | same environment | `/backend/payments/`              | STRIPE_KEY                  | Local reference with a specified path within the same environment. |

## Installation

This SDK uses the `sodium` package to perform cryptographic operations, on most system you will need to install the `libsodium` library as a system dependency. Here's how you can install `libsodium` or its development packages on different platforms, including macOS, Ubuntu, Debian, Arch Linux, Alpine Linux, and Windows.

### macOS

```sh
brew install libsodium
```

## Fedora

```sh
sudo dnf install libsodium-devel
```

### Ubuntu and Debian

```sh
sudo apt-get update && sudo apt-get install libsodium-dev
```

### Arch Linux

```sh
sudo pacman -Syu libsodium
```

### Alpine Linux

```sh
sudo apk add libsodium-dev
```

### Windows

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

Remember, after installing the library, you might need to configure your project or environment variables to locate the `libsodium` libraries correctly, especially on Windows.

Next, start using the Phase SDK in your Go project, install it using `go get`:

```bash
go get github.com/phasehq/golang-sdk/phase
```

Make sure to import the SDK in your Go files:

```go
import "github.com/phasehq/golang-sdk/phase"
```

## Configuration

Before you can interact with the Phase service, you need to initialize the SDK with your service token and the host information.

```go
package main

import (
    "log"
    "github.com/phasehq/golang-sdk/phase"
)

func main() {
    serviceToken := "pss_service:v1:....."
    host := "https://console.phase.dev" // Change this for a self hosted instance of Phase
    debug := false

    phaseClient := phase.Init(serviceToken, host, debug)
    if phaseClient == nil {
        log.Fatal("Failed to initialize Phase client")
    }
}
```

## Creating a Secret

To create new secrets, define key-value pairs, specify the environment and application name, and optionally set paths for each key.

```go
opts := phase.CreateSecretsOptions{
    KeyValuePairs: []map[string]string{
        {"API_KEY": "api_secret"},
    },
    EnvName:    "Production",
    AppName:    "MyApp",
    SecretPath: map[string]string{"API_KEY": "/api/keys"}, // Optional, default path: /
}

err := phaseClient.Create(opts)
if err != nil {
    log.Fatalf("Failed to create secret: %v", err)
}
```

## Retrieving a Secret

To retrieve a secret, provide the environment name, application name, key to find, and optionally a tag and path.

```go
getOpts := phase.GetSecretOptions{
    EnvName:   "Production",
    AppName:   "MyApp",
    KeyToFind: "API_KEY",
}

secret, err := phaseClient.Get(getOpts)
if err != nil {
    log.Fatalf("Failed to get secret: %v", err)
} else {
    log.Printf("Secret: %+v", secret)
}
```

## Updating a Secret

To update an existing secret, provide the new value along with the environment name, application name, key, and optionally the path.

```go
updateOpts := phase.SecretUpdateOptions{
    EnvName:    "Production",
    AppName:    "MyApp",
    Key:        "API_KEY",
    Value:      "my_updated_api_secret",
    SecretPath: "/api/keys", // Optional, default path: /
}

err := phaseClient.Update(updateOpts)
if err != nil {
    log.Fatalf("Failed to update secret: %v", err)
}
```

## Deleting a Secret

To delete a secret, specify the environment name, application name, key to delete, and optionally the path.

```go
deleteOpts := phase.DeleteSecretOptions{
    EnvName:     "Production",
    AppName:     "MyApp",
    KeyToDelete: "API_KEY",
    SecretPath:  "/api/keys", // Optional, default path: /
}

err := phaseClient.Delete(deleteOpts)
if err != nil {
    log.Fatalf("Failed to delete secret: %v", err)
}
```

For more information and advanced usage, refer to the [Phase Docs](https://docs.phase.dev/sdks/go).

---
