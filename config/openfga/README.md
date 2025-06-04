# OpenFGA Kustomization

This directory contains a Kustomize program that deploys OpenFGA using the
official Helm chart with in-memory storage backend.

## Overview

This configuration deploys:
- OpenFGA server with in-memory datastore
- OpenFGA playground (development UI)
- Namespace: `openfga-system`

## Features

- **In-Memory Storage**: Uses memory datastore (suitable for
  development/testing)
- **No Persistence**: Data is ephemeral and will be lost on pod restart
- **Playground Enabled**: Web UI available for testing authorization models
- **Resource Limits**: Configured with reasonable defaults for development

## Deployment

To deploy OpenFGA using this configuration:

```bash
kubectl apply -k config/openfga
```

## Accessing OpenFGA

After deployment, you can access OpenFGA:

1. **API Server**: Port 8080 (HTTP) and 8081 (gRPC)
2. **Playground**: Port 3000 (if enabled)

To port-forward for local access:

```bash
# API server
kubectl port-forward -n openfga-system svc/openfga 8080:8080

# Playground
kubectl port-forward -n openfga-system svc/openfga 3000:3000
```

## Configuration

### In-Memory Storage

This configuration uses the memory datastore engine:
```yaml
datastore:
  engine: memory
```

### Custom Configuration

To customize the deployment:
1. Edit `values-patch.yaml` for additional Helm values
2. Create patches in the `kustomization.yaml` file
3. Add additional resources as needed

## Important Notes

⚠️ **Data Persistence**: Since this uses in-memory storage, all data will be
lost when the pod restarts. This configuration is intended for development and
testing only.

For production deployments, consider using a persistent datastore like
PostgreSQL.

## References

- [OpenFGA Helm Charts](https://github.com/openfga/helm-charts)
- [OpenFGA Documentation](https://openfga.dev/docs)
- [Kustomize Documentation](https://kustomize.io/)
