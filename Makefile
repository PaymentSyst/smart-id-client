# Makefile for Smart-ID Go Client

.PHONY: help build test test-coverage test-race test-bench clean lint fmt vet mod-tidy mod-verify example install-tools

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Build targets
build: ## Build the library
	@echo "Building Smart-ID Go Client..."
	@go build ./...

example: ## Build and run the example
	@echo "Building and running example..."
	@cd example && go build -o smart-id-example . && ./smart-id-example

# Test targets
test: ## Run all tests
	@echo "Running tests..."
	@go test ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@go test -cover ./...
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race: ## Run tests with race detection
	@echo "Running tests with race detection..."
	@go test -race ./...

test-bench: ## Run benchmark tests
	@echo "Running benchmark tests..."
	@go test -bench=. -benchmem ./...

test-verbose: ## Run tests with verbose output
	@echo "Running tests with verbose output..."
	@go test -v ./...

test-short: ## Run tests in short mode
	@echo "Running short tests..."
	@go test -short ./...

# Code quality targets
lint: ## Run linter (requires golangci-lint)
	@echo "Running linter..."
	@golangci-lint run

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

# Dependency management
mod-tidy: ## Tidy go modules
	@echo "Tidying go modules..."
	@go mod tidy

mod-verify: ## Verify go modules
	@echo "Verifying go modules..."
	@go mod verify

mod-download: ## Download go modules
	@echo "Downloading go modules..."
	@go mod download

# Development tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/tools/cmd/goimports@latest

# Security
security: ## Run security checks (requires gosec)
	@echo "Running security checks..."
	@gosec ./...

install-security-tools: ## Install security tools
	@echo "Installing security tools..."
	@go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Clean targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@go clean ./...
	@rm -f coverage.out coverage.html
	@rm -f example/smart-id-example
	@rm -rf dist/

# Documentation
docs: ## Generate documentation
	@echo "Generating documentation..."
	@go doc -all ./...

docs-serve: ## Serve documentation locally (requires godoc)
	@echo "Serving documentation on http://localhost:6060"
	@godoc -http=:6060

install-doc-tools: ## Install documentation tools
	@echo "Installing documentation tools..."
	@go install golang.org/x/tools/cmd/godoc@latest

# Release targets
check-release: test test-race vet lint ## Run all checks before release
	@echo "All checks passed! Ready for release."

# Docker targets (if needed in the future)
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t smart-id-client .

docker-test: ## Run tests in Docker
	@echo "Running tests in Docker..."
	@docker run --rm smart-id-client make test

# Development workflow
dev: fmt vet test ## Run development workflow (format, vet, test)
	@echo "Development workflow completed!"

ci: mod-tidy fmt vet test test-race ## Run CI workflow
	@echo "CI workflow completed!"

# Package info
info: ## Show package information
	@echo "Package: github.com/PaymentSyst/smart-id-client"
	@echo "Go version: $(shell go version)"
	@echo "Dependencies:"
	@go list -m all

# Generate version info (if versioning is implemented)
version: ## Show version information
	@echo "Smart-ID Go Client"
	@echo "Git commit: $(shell git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
	@echo "Git branch: $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo 'unknown')"
	@echo "Build time: $(shell date -u '+%Y-%m-%d %H:%M:%S UTC')"

# All targets for comprehensive testing
all: clean mod-tidy fmt vet lint test test-race test-bench ## Run all checks and tests
	@echo "All targets completed successfully!"
