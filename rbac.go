// Package rbacMiddleware provides Role-Based Access Control (RBAC) middleware for HTTP services
// using Casbin as the authorization engine and JWT tokens for role information.
package rbacMiddleware

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/fx"
)

// RBACMiddleware implements HTTP middleware for role-based access control.
// It validates JWT tokens and enforces access policies using Casbin.
type RBACMiddleware struct {
	enforcer *casbin.Enforcer
}

// Options configures the RBAC middleware.
type Options struct {
	// ModelPath is the path to the Casbin model file.
	// The model file defines the RBAC model structure and assertion rules.
	ModelPath string

	// PolicyPath is the path to the Casbin policy file.
	// The policy file contains the actual authorization rules.
	PolicyPath string
}

// Module provides the RBAC middleware for uber-fx dependency injection.
// Usage:
//
//	fx.New(
//	    rbacMiddleware.Module,
//	    fx.Provide(func() rbacMiddleware.Options {
//	        return rbacMiddleware.Options{
//	            ModelPath:  "path/to/model.conf",
//	            PolicyPath: "path/to/policy.csv",
//	        }
//	    }),
//	)
var Module = fx.Provide(New)

// New creates a new RBAC middleware instance with the given options.
// It initializes a Casbin enforcer using the provided model and policy paths.
// Returns an error if the enforcer cannot be created.
func New(opts Options) (*RBACMiddleware, error) {
	enforcer, err := casbin.NewEnforcer(opts.ModelPath, opts.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC enforcer: %w", err)
	}

	return &RBACMiddleware{
		enforcer: enforcer,
	}, nil
}

// Inject returns an http.Handler that performs RBAC checks before calling the next handler.
// It expects a JWT token in the Authorization header with the format "Bearer <token>".
// The token should contain a "roles" claim with either a string or array of strings.
//
// The middleware will return:
//   - 401 Unauthorized if the token is missing or invalid
//   - 403 Forbidden if the user's roles don't have permission for the requested path and method
//   - Forward to the next handler if authorization is successful
func (rm *RBACMiddleware) Inject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token = strings.TrimPrefix(token, "Bearer ")

		claims, err := extractRolesFromClaims(token)
		if err != nil {
			log.Printf("failed to extract claims: %s", err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !rm.checkPermission(claims, r.URL.Path, r.Method) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractRolesFromClaims extracts user roles from a JWT token.
// The token is parsed without verification (unsafe for production use).
// The function expects a "roles" claim that can be either:
//   - a single string
//   - an array of strings
//   - an array of interface{} that can be converted to strings
//
// Returns an error if:
//   - the token cannot be parsed
//   - the claims cannot be extracted
//   - the roles claim has an invalid format
func extractRolesFromClaims(tokenString string) (roles []string, err error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("claims not found")
	}

	roles, err = parseClaimsString(claims["roles"])
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// parseClaimsString converts a claim value to a slice of strings.
// It handles three possible input types:
//   - string: converted to a single-element slice
//   - []string: used as-is
//   - []interface{}: each element must be convertible to string
//
// Returns an error if the input type is not supported or
// if any element in []interface{} cannot be converted to string.
func parseClaimsString(key any) ([]string, error) {
	var cs []string
	switch v := key.(type) {
	case string:
		cs = append(cs, v)
	case []string:
		cs = v
	case []any:
		for _, a := range v {
			vs, ok := a.(string)
			if !ok {
				return nil, fmt.Errorf("%v is invalid", key)
			}
			cs = append(cs, vs)
		}
	default:
		return nil, fmt.Errorf("%v is invalid type", key)
	}

	return cs, nil
}

// checkPermission verifies if any of the user's roles allow access to the requested path and method.
// It uses the Casbin enforcer to check each role against the policy rules.
// Returns true if any role has permission, false otherwise.
// Note: Errors from the enforcer are ignored - consider this behavior for production use.
func (rm *RBACMiddleware) checkPermission(roles []string, path, method string) bool {
	for _, role := range roles {
		if ok, _ := rm.enforcer.Enforce(role, path, method); ok {
			return true
		}
	}

	return false
}
