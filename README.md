# Milo OpenFGA Auth Provider

A Kubernetes controller that enables Milo to use OpenFGA as the authorization provider for managing access to all resources in the control plane.

## 🚀 Quick Start

### DevContainer (Recommended)
```bash
# Open in VSCode, accept "Reopen in Container" prompt, then:
make dev-setup
```

### Local Development
```bash
git clone <repository>
cd auth-provider-openfga
make dev-setup    # Requires Docker + Go + Make
```

## 🛠️ Essential Commands

```bash
make dev-setup          # Complete environment setup
make dev-deploy         # Deploy/redeploy application
make dev-status         # Check environment status
make dev-logs           # View application logs
make test               # Run tests
```

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| **[Development Guide](docs/development.md)** | Complete setup, workflow, and troubleshooting |
| **[Architecture Guide](docs/architecture.md)** | System design, components, and data flow |
| **[API Reference](docs/api.md)** | Custom resources and webhook specifications |
| **[Contributing Guide](docs/contributing.md)** | Code standards, PR process, and testing |

## 🏗️ Project Structure

```
├── config/               # Kubernetes manifests and Kustomize overlays
│   ├── default/          # Base application configuration
│   ├── bootstrap/        # Infrastructure (cert-manager, OpenFGA)
│   └── local-dev/        # Development environment
├── internal/             # Application logic
├── test/                 # E2E tests
└── docs/                 # Detailed documentation
```

## 🤝 Quick Contributing

1. `make dev-setup` - Set up environment
2. Make your changes
3. `make test && make test-e2e` - Verify changes
4. Submit PR

For detailed guidelines, see [Contributing Guide](docs/contributing.md).
