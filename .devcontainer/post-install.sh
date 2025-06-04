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
    KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt)
    curl -LO "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/${ARCH}/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/kubectl
fi

# Install Helm (if not already installed via feature)
if ! command -v helm &> /dev/null; then
    echo "📦 Installing Helm..."
    curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | tee /usr/share/keyrings/helm.gpg > /dev/null
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main" | tee /etc/apt/sources.list.d/helm-stable-debian.list
    apt-get update
    apt-get install helm -y
fi

# Install FluxCD CLI
echo "📦 Installing FluxCD CLI..."
curl -s https://fluxcd.io/install.sh | bash
# FluxCD installer already places flux in /usr/local/bin/flux

# Create Kind network if it doesn't exist
if ! docker network ls | grep -q kind; then
    echo "🌐 Creating Kind network..."
    docker network create -d=bridge --subnet=172.19.0.0/24 kind
fi

# Install Go tools
echo "🔧 Installing Go development tools..."
# Install a compatible version of air for Go 1.23.9
go install github.com/air-verse/air@v1.61.1 || echo "⚠️  Warning: Could not install air, continuing..."
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest || echo "⚠️  Warning: Could not install golangci-lint, continuing..."

# Verify installations
echo "✅ Verifying installations..."
kind version
kubebuilder version
kubectl version --client
helm version
flux version --client
go version

echo "🎉 Development environment setup complete!"
echo "📖 Quick start:"
echo "   make help              # Show available commands"
echo "   make dev-setup         # Setup complete development environment"
echo "   make dev-status        # Check environment status"
