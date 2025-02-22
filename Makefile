.PHONY: install-deps lint doc test test-cover test-cover-svg test-cover-html
.SILENT:

TEST_COVER_EXCLUDE_DIR := `go list ./... | grep -v -E '/cmd|/mocks|/app$$|/rbac-middleware'`

# Install development dependencies
install-deps:
	@GOBIN=$(CURDIR)/temp/bin go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@GOBIN=$(CURDIR)/temp/bin go install github.com/nikolaydubina/go-cover-treemap@latest
	@GOBIN=$(CURDIR)/temp/bin go install golang.org/x/tools/cmd/godoc@latest



# Run linter
lint:
	@$(CURDIR)/temp/bin/golangci-lint run -c .golangci.yaml --path-prefix . --fix



# Serve documentation at http://localhost:6060/pkg/github.com/towiron/rbac-middleware/
doc:
	@echo documentation is available at http://localhost:6060/pkg/github.com/towiron/rbac-middleware/
	@$(CURDIR)/temp/bin/godoc -http=localhost:6060



# Run tests with race detection and generate coverage profile
test:
	@go test --cover --coverprofile=$(CURDIR)/temp/coverage.out $(TEST_COVER_EXCLUDE_DIR) --race
# Show total test coverage percentage
test-cover:
	@go tool cover -func=$(CURDIR)/temp/coverage.out | grep total | grep -oE '[0-9]+(\.[0-9]+)?%'
# Generate coverage visualization in SVG format
test-cover-svg:
	@$(CURDIR)/temp/bin/go-cover-treemap -coverprofile $(CURDIR)/temp/coverage.out > coverage.svg
# Open coverage report in browser
test-cover-html:
	@go tool cover -html="temp/coverage.out"
