#!/bin/bash
set -e

echo "🚀 Setting up Auth Provider OpenFGA development environment..."

# Detect architecture for ARM64 compatibility
ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
elif [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
fi

# Install Kind
echo "📦 Installing Kind..."
curl -Lo ./kind "https://kind.sigs.k8s.io/dl/latest/kind-linux-${ARCH}"
chmod +x ./kind
mv ./kind /usr/local/bin/kind

# Install Kubebuilder
echo "📦 Installing Kubebuilder..."
curl -L -o kubebuilder "https://go.kubebuilder.io/dl/latest/linux/${ARCH}"
chmod +x kubebuilder
mv kubebuilder /usr/local/bin/

# Install kubectl (if not already installed via feature)
if ! command -v kubectl &> /dev/null; then
    echo "📦 Installing kubectl..."
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/kubectl
fi

# Install Helm (if not already installed via feature)
if ! command -v helm &> /dev/null; then
    echo "📦 Installing Helm..."
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Install FluxCD CLI
echo "📦 Installing FluxCD CLI..."
curl -s https://fluxcd.io/install.sh | bash

# Install Go tools as vscode user (Go environment is set up for vscode user)
echo "🔧 Installing Go development tools..."
sudo -u vscode bash << 'EOF'
# Install a compatible version of air for Go 1.23.9
go install github.com/air-verse/air@v1.61.1 || echo "⚠️  Warning: Could not install air, continuing..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || echo "⚠️  Warning: Could not install golangci-lint, continuing..."
EOF

# Verify installations
echo "✅ Verifying installations..."
kind version || echo "⚠️  Warning: Kind not found"
kubebuilder version || echo "⚠️  Warning: Kubebuilder not found"
kubectl version --client || echo "⚠️  Warning: kubectl not found"
helm version || echo "⚠️  Warning: Helm not found"
flux version || echo "⚠️  Warning: FluxCD not found"
sudo -u vscode go version || echo "⚠️  Warning: Go not found for vscode user"

echo "🎉 Auth Provider OpenFGA development environment setup complete!"
echo ""
echo "🔧 Available tools:"
echo "  - Kind: $(kind version 2>/dev/null | head -n1 || echo 'Not available')"
echo "  - Kubebuilder: $(kubebuilder version 2>/dev/null | grep -o 'KubeBuilderVersion:"[^"]*"' | cut -d'"' -f2 || echo 'Not available')"
echo "  - kubectl: $(kubectl version --client 2>/dev/null | grep -o 'v[0-9.]*' | head -n1 || echo 'Not available')"
echo "  - Helm: $(helm version 2>/dev/null | grep -o 'v[0-9.]*' | head -n1 || echo 'Not available')"
echo "  - FluxCD: $(flux version 2>/dev/null | grep -o 'v[0-9.]*' | head -n1 || echo 'Not available')"
echo "  - Go tools: Available in vscode user environment"
echo ""
