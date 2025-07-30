# Configuration Structure

This directory contains a layered configuration structure that separates concerns between platform infrastructure, application dependencies, and application components.

## Directory Structure

```
config/
├── platform/                      # Cluster-wide infrastructure
│   ├── cert-manager/              # TLS certificate management for entire cluster
│   └── kustomization.yaml         # Platform services composition
├── dependencies/                  # Application-specific infrastructure
│   ├── openfga/                   # Authorization service (app-specific)
│   └── kustomization.yaml         # App dependencies composition
├── base/                          # Core application components
│   ├── services/                  # Application services
│   ├── rbac/                      # Security resources
│   └── kustomization.yaml         # Application composition
├── environments/                  # Environment-specific overlays
│   ├── local-development/         # Local dev environment
│   ├── testing/                   # CI/E2E testing
│   └── production-example/        # Production example (for reference)
├── components/                    # Optional Kustomize components
│   ├── tls-certs/                 # TLS certificate configuration
│   ├── prometheus-monitoring/     # Metrics and monitoring
│   └── network-policies/          # Network security policies
└── infrastructure/                # Convenience wrapper (platform + dependencies)
    └── kustomization.yaml         # Combined infrastructure
```

## Deployment Layers

### 1. Platform Layer (`platform/`)

> [!NOTE]
> This layer will eventually be replaced by a centralized platform layer that
> enables sharing test infrastructure across all applications.

**Purpose**: Cluster-wide services that support multiple applications
**Managed by**: Cluster administrators
**Frequency**: Once per cluster, rarely updated

Services include:
- cert-manager (TLS certificate management)
- Cluster monitoring (if added)
- Ingress controllers (if added)

**Deployment**: `make platform-deploy`

### 2. Dependencies Layer (`dependencies/`)
**Purpose**: External services required by this specific application
**Managed by**: Application teams
**Frequency**: Per application deployment, updated occasionally

Services include:
- OpenFGA (authorization service)
- Application-specific databases (if added)

**Deployment**: `make dependencies-deploy`

### 3. Application Layer (`base/` + `environments/`)
**Purpose**: The core application and environment-specific configurations
**Managed by**: Application teams
**Frequency**: Updated frequently during development

**Deployment**: `make dev-deploy` (includes infrastructure) or `make dev-deploy-fast` (app only)

## Components (Optional Features)

### TLS Certificates (`components/tls-certs/`)

Enables HTTPS for metrics and webhook endpoints using cert-manager. **The component is issuer-agnostic** - certificate issuers are configured per environment.

**Usage:**
```yaml
components:
  - ../../components/tls-certs

# Configure certificate issuers per environment
replacements:
  - source:
      kind: ClusterIssuer
      name: your-environment-issuer
      fieldPath: metadata.name
    targets:
      - select:
          kind: Certificate
          name: webhook-server-cert
        fieldPaths:
          - spec.issuerRef.name
      - select:
          kind: Certificate
          name: metrics-server-cert
        fieldPaths:
          - spec.issuerRef.name
```

**Environment Examples:**

| Environment | Issuer Type | Use Case |
|-------------|-------------|----------|
| Development | Self-signed CA | Local development, fast setup |
| Testing | Self-signed CA | CI/CD, E2E testing |
| Staging | Let's Encrypt Staging | Pre-production validation |
| Production | Let's Encrypt Production | Public endpoints |
| Enterprise | Corporate CA | Internal PKI compliance |

**Features:**
- ✅ HTTPS metrics endpoint (port 8443)
- ✅ TLS webhook certificates
- ✅ Automatic cert-manager integration
- ✅ Environment-specific issuer configuration
- ✅ ServiceMonitor TLS configuration

### Prometheus Monitoring (`components/prometheus-monitoring/`)

Enables Prometheus ServiceMonitor for metrics collection.

**Features:**
- ✅ ServiceMonitor for controller metrics
- ✅ HTTPS support (when used with tls-certs component)
- ✅ Proper RBAC for metrics access

### Network Policies (`components/network-policies/`)

Provides network security isolation and access control.

**Features:**
- ✅ Default deny-all policy
- ✅ Selective metrics access (namespaces with `metrics: enabled`)
- ✅ Webhook traffic controls
- ✅ HTTPS metrics port (8443) support

## Environment Configuration Patterns

### Development (`environments/local-development/`)
- Self-signed certificates for simplicity
- Prometheus monitoring enabled
- Latest image tags
- Single replica deployments

### Testing (`environments/testing/`)
- Self-signed certificates (different CA from dev)
- All security components enabled
- Test image tags
- Network policies for security validation

### Production Example (`environments/production-example/`)
**Note**: This is a reference example. Real production configs are managed by infrastructure teams.

- Let's Encrypt certificates
- High availability (3 replicas)
- Resource limits and requests
- All security components enabled
- Production image tags

## Deployment Options

### Quick Start (All-in-One)
```bash
make dev-deploy          # Platform + Dependencies + Application
```

### Layered Deployment
```bash
make platform-deploy     # 1. Deploy cluster infrastructure
make dependencies-deploy # 2. Deploy app dependencies
make dev-deploy-fast     # 3. Deploy application only
```

### Custom Component Selection

Enable/disable components per environment by adding/removing from the `components:` section:

```yaml
components:
  # Core monitoring
  - ../../components/prometheus-monitoring

  # Enable TLS (optional)
  - ../../components/tls-certs

  # Enable network security (optional)
  - ../../components/network-policies
```

## TLS Certificate Management

### Flexible Issuer Configuration

The TLS component separates **certificate creation** from **issuer management**:

1. **Certificate Resources**: Defined in the component (reusable)
2. **Issuer Selection**: Configured per environment using Kustomize replacements
3. **Application Configuration**: Automatically patched for HTTPS

This allows the same certificate component to work with:
- Self-signed certificates (development/testing)
- Let's Encrypt (staging/production)
- Corporate CAs (enterprise environments)
- Any cert-manager compatible issuer

### Certificate Lifecycle

1. **Platform Layer**: Deploys cert-manager cluster-wide
2. **Environment Layer**: Creates appropriate certificate issuers
3. **TLS Component**: Creates certificate resources and configures application
4. **cert-manager**: Issues and manages certificate lifecycle automatically

## Validation

Validate all configurations:
```bash
make validate-configs
```

This ensures all layers and environments build correctly without deployment.
