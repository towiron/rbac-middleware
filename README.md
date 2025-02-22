# RBAC Middleware for Go
[![GoDoc](https://img.shields.io/badge/godoc-reference-blue.svg)](https://github.com/towiron/rbac-middleware)

[![GitHub Workflow](https://github.com/towiron/rbac-middleware/actions/workflows/go.yaml/badge.svg?branch=main)](https://github.com/towiron/rbac-middleware/actions/workflows/go.yaml)
[![codecov](https://codecov.io/gh/towiron/rbac-middleware/graph/badge.svg?token=IING0E9DE0)](https://codecov.io/gh/towiron/rbac-middleware)
[![Go Report Card](https://goreportcard.com/badge/github.com/towiron/rbac-middleware)](https://goreportcard.com/report/github.com/towiron/rbac-middleware)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/towiron/rbac-middleware)
![GitHub Tag](https://img.shields.io/github/v/tag/towiron/rbac-middleware)

A robust Role-Based Access Control (RBAC) middleware for Go HTTP services, leveraging Casbin for authorization and JWT for authentication.

## Features

- JWT token-based authentication
- Flexible role extraction from JWT claims
- Casbin-powered authorization rules
- Easy integration with standard `net/http` handlers
- Support for multiple roles per user
- Built-in uber-fx integration

## Installation

```bash
go get github.com/towiron/rbac-middleware
```

## Quick Start

```go
package main

import (
    "net/http"
    rbacMiddleware "github.com/towiron/rbac-middleware"
)

func main() {
    // Initialize the middleware
    middleware, err := rbacMiddleware.New(rbacMiddleware.Options{
        ModelPath:  "path/to/model.conf",
        PolicyPath: "path/to/policy.csv",
    })
    if err != nil {
        panic(err)
    }

    // Create your handler
    handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Protected resource"))
    })

    // Wrap your handler with the middleware
    protected := middleware.Inject(handler)

    // Start the server
    http.ListenAndServe(":8080", protected)
}
```

## Configuration

### Casbin Model File (model.conf)

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
```

### Casbin Policy File (policy.csv)

```csv
p, admin, /api/users, GET
p, admin, /api/users, POST
p, user, /api/users, GET
```

## JWT Token Format

The middleware expects JWT tokens in the Authorization header with the following format:

```
Authorization: Bearer <token>
```

The JWT token should contain a `roles` claim that can be either:
- A single string: `"roles": "admin"`
- An array of strings: `"roles": ["admin", "user"]`

Example token payload:
```json
{
    "sub": "1234567890",
    "roles": ["admin", "user"],
    "iat": 1516239022
}
```

## Integration with uber-fx

```go
package main

import (
    "go.uber.org/fx"
    rbacMiddleware "github.com/towiron/rbac-middleware"
)

func main() {
    app := fx.New(
        rbacMiddleware.Module,
        fx.Provide(
            func() rbacMiddleware.Options {
                return rbacMiddleware.Options{
                    ModelPath:  "path/to/model.conf",
                    PolicyPath: "path/to/policy.csv",
                }
            },
        ),
        // ... other providers and invokes
    )
    app.Run()
}
```

## Error Handling

The middleware returns the following HTTP status codes:
- `401 Unauthorized`: Missing or invalid JWT token
- `403 Forbidden`: Valid token but insufficient permissions
- Original handler response: Successful authorization

## Development Workflow

1. Install dependencies:
   ```bash
   make install-deps
   ```

2. Make your changes and run linter:
   ```bash
   make lint
   ```

3. Run tests and check coverage:
   ```bash
   make test
   make test-cover
   ```

4. Generate and review coverage visualization:
   ```bash
   make test-cover-svg
   # or
   make test-cover-html
   ```

5. Check documentation locally:
   ```bash
   make doc
   # Open http://localhost:6060/pkg/github.com/towiron/rbac-middleware/
   ```


## TODO: License 

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Considerations

1. **Token Verification**: By default, the middleware doesn't verify JWT signatures. In production, implement proper token verification.

## Example Use Cases

### Basic API Protection

```go
// Define your routes with different permission levels
middleware.enforcer.AddPolicy("admin", "/api/admin/*", "GET")
middleware.enforcer.AddPolicy("user", "/api/users/*", "GET")

// Protected admin endpoint
http.Handle("/api/admin/", middleware.Inject(adminHandler))

// Protected user endpoint
http.Handle("/api/users/", middleware.Inject(userHandler))
```

### Multiple Roles

```go
// Allow access if user has any of the required roles
middleware.enforcer.AddPolicy("editor", "/api/content", "POST")
middleware.enforcer.AddPolicy("admin", "/api/content", "POST")
```

## Support

For bugs and feature requests, please open an issue in the GitHub repository.


Before starting development, install the required dependencies:

```bash
make install-deps
```

This will install:
- golangci-lint - for code linting
- go-cover-treemap - for coverage visualization
- godoc - for documentation serving

### Available Make Commands

```bash
# Run linter
make lint

# Serve documentation at http://localhost:6060/pkg/github.com/towiron/rbac-middleware/
make doc

# Run tests with race detection and generate coverage profile
make test

# Show total test coverage percentage
make test-cover

# Generate coverage visualization in SVG format
make test-cover-svg

# Open coverage report in browser
make test-cover-html

# Install development dependencies
make install-deps
```