# sesat2

`sesat2` is a robust and flexible Go library for building secure HTTP clients. It provides a builder-based API to easily configure timeouts, default headers, and, most importantly, destination blocking to prevent Server-Side Request Forgery (SSRF) and other unauthorized access.

## Features

- **SSRF Protection:** Block specific hosts, IP addresses, and CIDR ranges.
- **Predefined Blocklists:** Includes built-in protection for cloud metadata services, loopback addresses, and private IP ranges (RFC 1918, etc.).
- **DNS-Aware Blocking:** Automatically resolves hostnames and checks all resulting IP addresses against blocklists.
- **Interceptor Support:** Easily add middleware-like interceptors to your HTTP requests.
- **Fluent Builder API:** Clean and expressive way to configure your `http.Client`.
- **Customizable Transport:** Wrap existing `http.Transport` or let `sesat2` manage it for you.

## Installation

```bash
go get github.com/theirish81/sesat2
```

## Quick Start

### Basic Secure Client

```go
package main

import (
    "fmt"
    "github.com/theirish81/sesat2"
)

func main() {
    // Create a client that blocks common internal/private destinations
    client, err := sesat2.New().
        WithDefaultBlockedDestinations().
        Build()
    
    if err != nil {
        panic(err)
    }

    // This request will fail if it targets a blocked IP or host
    resp, err := client.Get("http://169.254.169.254/latest/meta-data/")
    if err != nil {
        fmt.Printf("Blocked as expected: %v\n", err)
    }
}
```

### Advanced Configuration

```go
client, err := sesat2.New().
    WithTimeout(10 * time.Second).
    WithHeaders(http.Header{
        "User-Agent": []string{"MyApp/1.0"},
    }).
    WithBlockedHosts("internal.example.com").
    WithBlockedIPRanges(sesat2.PrivateBlockedIPs...).
    WithInterceptor(func(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
        fmt.Printf("Requesting: %s\n", req.URL)
        return next(req)
    }).
    Build()
```

## Security Defaults

The `WithDefaultBlockedDestinations()` method enables a comprehensive suite of protections:

- **Cloud Metadata:** Blocks AWS, GCP, Azure, and other cloud providers' metadata endpoints (e.g., `169.254.169.254`).
- **Loopback:** Blocks `localhost` and `127.0.0.1/::1`.
- **Private IP Ranges:** Blocks RFC 1918 (e.g., `10.0.0.0/8`, `192.168.0.0/16`) and other non-routable ranges.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [LICENSE](LICENSE) file included in the repository.
