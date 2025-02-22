package rbacMiddleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseClaimsString(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    []string
		wantErr bool
	}{
		{
			name:    "single string",
			input:   "admin",
			want:    []string{"admin"},
			wantErr: false,
		},
		{
			name:    "string slice",
			input:   []string{"admin", "user"},
			want:    []string{"admin", "user"},
			wantErr: false,
		},
		{
			name:    "interface slice",
			input:   []any{"admin", "user"},
			want:    []string{"admin", "user"},
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    []string{""},
			wantErr: false,
		},
		{
			name:    "nil input",
			input:   nil,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid type",
			input:   123,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "mixed interface slice",
			input:   []any{"admin", 123},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseClaimsString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseClaimsString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !equalStringSlices(got, tt.want) {
				t.Errorf("parseClaimsString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractRolesFromClaims(t *testing.T) {
	tests := []struct {
		name     string
		claims   jwt.MapClaims
		want     []string
		wantErr  bool
		errMatch string
	}{
		{
			name:     "single role string",
			claims:   jwt.MapClaims{"roles": "admin"},
			want:     []string{"admin"},
			wantErr:  false,
			errMatch: "",
		},
		{
			name:     "multiple roles array",
			claims:   jwt.MapClaims{"roles": []any{"admin", "user"}},
			want:     []string{"admin", "user"},
			wantErr:  false,
			errMatch: "",
		},
		{
			name:     "string array roles",
			claims:   jwt.MapClaims{"roles": []string{"admin", "user"}},
			want:     []string{"admin", "user"},
			wantErr:  false,
			errMatch: "",
		},
		{
			name:     "missing roles claim",
			claims:   jwt.MapClaims{},
			want:     nil,
			wantErr:  true,
			errMatch: "invalid type",
		},
		{
			name:     "invalid roles type",
			claims:   jwt.MapClaims{"roles": 123},
			want:     nil,
			wantErr:  true,
			errMatch: "invalid type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.claims)
			tokenString, err := token.SignedString([]byte("test-secret"))
			if err != nil {
				t.Fatalf("failed to create test token: %v", err)
			}

			got, err := extractRolesFromClaims(tokenString)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractRolesFromClaims() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMatch != "" && err != nil && !contains(err.Error(), tt.errMatch) {
				t.Errorf("extractRolesFromClaims() error = %v, should contain %v", err, tt.errMatch)
				return
			}
			if !tt.wantErr && !equalStringSlices(got, tt.want) {
				t.Errorf("extractRolesFromClaims() = %v, want %v", got, tt.want)
			}
		})
	}
}

//nolint:errcheck // ignore error for testing
func TestRBACMiddleware_Inject(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tmpModelfile, err := os.CreateTemp(tmpDir, "model.conf")
	if err != nil {
		t.Fatal(err)
	}

	_, err = tmpModelfile.WriteString(`[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	tmpModelfile.Close()

	tmpPolicyfile, err := os.CreateTemp(tmpDir, "policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	tmpPolicyfile.Close()

	tests := []struct {
		name          string
		token         string
		path          string
		method        string
		wantStatus    int
		setupEnforcer func(*RBACMiddleware)
	}{
		{
			name:       "valid token and permissions",
			token:      createTestToken([]string{"admin"}),
			path:       "/api/users",
			method:     "GET",
			wantStatus: http.StatusOK,
			setupEnforcer: func(rm *RBACMiddleware) {
				rm.enforcer.AddPolicy("admin", "/api/users", "GET")
			},
		},
		{
			name:       "missing token",
			token:      "",
			path:       "/api/users",
			method:     "GET",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "invalid token format",
			token:      "not-a-jwt-token",
			path:       "/api/users",
			method:     "GET",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unauthorized role",
			token:      createTestToken([]string{"user"}),
			path:       "/api/admin",
			method:     "POST",
			wantStatus: http.StatusForbidden,
			setupEnforcer: func(rm *RBACMiddleware) {
				rm.enforcer.AddPolicy("admin", "/api/admin", "POST")
			},
		},
		{
			name:       "multiple roles one authorized",
			token:      createTestToken([]string{"user", "admin"}),
			path:       "/api/admin",
			method:     "GET",
			wantStatus: http.StatusOK,
			setupEnforcer: func(rm *RBACMiddleware) {
				rm.enforcer.AddPolicy("admin", "/api/admin", "GET")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware, err := New(Options{
				ModelPath:  tmpModelfile.Name(),
				PolicyPath: tmpPolicyfile.Name(),
			})
			if err != nil {
				t.Fatalf("failed to create middleware: %v", err)
			}

			if tt.setupEnforcer != nil {
				tt.setupEnforcer(middleware)
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tt.token))
			}

			rec := httptest.NewRecorder()

			handler := middleware.Inject(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("Inject() status = %v, want %v", rec.Code, tt.wantStatus)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func createTestToken(roles []string) string {
	claims := jwt.MapClaims{
		"roles": roles,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))
	return tokenString
}
