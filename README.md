# kmip-go

[![CI](https://github.com/cyphera-labs/kmip-go/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/kmip-go/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/kmip-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/kmip-go/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

KMIP client for Go — connect to any KMIP-compliant key management server.

Supports Thales CipherTrust, IBM SKLM, Entrust KeyControl, Fortanix, HashiCorp Vault Enterprise, and any KMIP 1.4 server.

```
go get github.com/cyphera-labs/kmip-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    kmip "github.com/cyphera-labs/kmip-go"
)

func main() {
    client, err := kmip.NewClient(kmip.ClientOptions{
        Host:       "kmip-server.corp.internal",
        ClientCert: "/path/to/client.pem",
        ClientKey:  "/path/to/client-key.pem",
        CACert:     "/path/to/ca.pem",
    })
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Fetch a key by name (locate + get in one call)
    key, err := client.FetchKey("my-encryption-key")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Key: %x\n", key) // raw key bytes

    // Or step by step:
    ids, _ := client.Locate("my-key")
    result, _ := client.Get(ids[0])
    fmt.Printf("Key material: %x\n", result.KeyMaterial)

    // Create a new AES-256 key on the server
    created, _ := client.Create("new-key-name", kmip.AlgorithmAES, 256)
    fmt.Println(created.UniqueIdentifier)
}
```

## Operations

| Operation | Method | Description |
|-----------|--------|-------------|
| Locate | `client.Locate(name)` | Find keys by name, returns unique IDs |
| Get | `client.Get(id)` | Fetch key material by unique ID |
| Create | `client.Create(name, algo, length)` | Create a new symmetric key |
| Fetch | `client.FetchKey(name)` | Locate + Get in one call |

## Authentication

KMIP uses mutual TLS (mTLS). Provide:
- **Client certificate** — identifies your application to the KMS
- **Client private key** — proves ownership of the certificate
- **CA certificate** — validates the KMS server's certificate

```go
client, err := kmip.NewClient(kmip.ClientOptions{
    Host:       "kmip.corp.internal",
    Port:       5696,                    // default KMIP port
    ClientCert: "/etc/kmip/client.pem",
    ClientKey:  "/etc/kmip/client-key.pem",
    CACert:     "/etc/kmip/ca.pem",
    Timeout:    10 * time.Second,        // connection timeout
})
```

## TTLV Codec

The low-level TTLV (Tag-Type-Length-Value) encoder/decoder is also exported for advanced use:

```go
import kmip "github.com/cyphera-labs/kmip-go"

// Build custom KMIP messages
msg := kmip.EncodeStructure(kmip.TagRequestMessage, ...)

// Parse raw KMIP responses
parsed, err := kmip.DecodeTTLV(responseBytes, 0)
```

## Supported KMS Servers

| Server | KMIP Version | Tested |
|--------|-------------|--------|
| Thales CipherTrust Manager | 1.x, 2.0 | Planned |
| IBM SKLM | 1.x, 2.0 | Planned |
| Entrust KeyControl | 1.x, 2.0 | Planned |
| Fortanix DSM | 2.0 | Planned |
| HashiCorp Vault Enterprise | 1.4 | Planned |
| PyKMIP (test server) | 1.0-2.0 | CI |

## Zero Dependencies

This library uses only Go standard library (`crypto/tls`, `crypto/x509`, `encoding/binary`). No external dependencies.

## Status

Alpha. KMIP 1.4 operations: Locate, Get, Create.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
