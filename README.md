# Phase Secrets Management SDK

The Phase Secrets SDK provides a Go package for managing secrets in your application environments using the Phase service. This SDK let's you create, retrieve, update, and delete secrets, with end-to-end encryption with just a few lines of code.

## Installation

To start using the Phase SDK in your Go project, install it using `go get`:

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

For more information and advanced usage, refer to the official Phase documentation.

---
