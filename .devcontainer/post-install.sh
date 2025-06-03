#!/bin/bash
set -e

echo "🚀 Setting up Auth Provider OpenFGA development environment..."

# Install Kind
echo "📦 Installing Kind..."
curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
chmod +x ./kind
mv ./kind /usr/local/bin/kind

# Install Kubebuilder
echo "📦 Installing Kubebuilder..."
curl -L -o kubebuilder https://go.kubebuilder.io/dl/latest/linux/amd64
chmod +x kubebuilder
mv kubebuilder /usr/local/bin/

# Install kubectl (if not already installed via feature)
if ! command -v kubectl &> /dev/null; then
    echo "📦 Installing kubectl..."
    KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt)
    curl -LO "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
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
mv ./flux /usr/local/bin/flux

# Create Kind network if it doesn't exist
if ! docker network ls | grep -q kind; then
    echo "🌐 Creating Kind network..."
    docker network create -d=bridge --subnet=172.19.0.0/24 kind
fi

# Install Go tools
echo "🔧 Installing Go development tools..."
go install github.com/air-verse/air@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

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
