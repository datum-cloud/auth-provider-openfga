# Image URL to use all building/pushing image targets
IMG ?= auth-provider-openfga:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN="$(shell go env GOPATH)/bin"
else
GOBIN="$(shell go env GOBIN)"
endif

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	"$(CONTROLLER_GEN)" rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	"$(CONTROLLER_GEN)" object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet setup-envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell "$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path)" go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

# TODO(user): To use a different vendor for e2e tests, modify the setup under 'tests/e2e'.
# The default setup assumes Kind is pre-installed and builds/loads the Manager Docker image locally.
# CertManager is installed by default; skip with:
# - CERT_MANAGER_INSTALL_SKIP=true
.PHONY: test-e2e
test-e2e: manifests generate fmt vet docker-build chainsaw ## Run the e2e tests. Expected an isolated environment using Kind.
	@command -v $(KIND) >/dev/null 2>&1 || { \
		echo "Kind is not installed. Please install Kind manually."; \
		exit 1; \
	}
	@$(KIND) get clusters | grep -q "^$(CLUSTER_NAME)$$" || { \
		echo "Kind cluster '$(CLUSTER_NAME)' is not running. Please run 'make kind-create' first."; \
		exit 1; \
	}
	$(KIND) load docker-image ${IMG} --name $(CLUSTER_NAME)
	kustomize build config/test-e2e --enable-helm | kubectl apply --server-side --wait=true -f -
	@echo "Waiting for cert-manager components to be ready..."
	@kubectl wait --for=condition=Available deployment cert-manager -n cert-manager --timeout=300s
	@kubectl wait --for=condition=Available deployment cert-manager-webhook -n cert-manager --timeout=300s
	@kubectl wait --for=condition=Available deployment cert-manager-cainjector -n cert-manager --timeout=300s
	@echo "Waiting for CA certificate to be ready..."
	@kubectl wait --for=condition=Ready certificate auth-provider-openfga-auth-provider-openfga-ca-cert -n cert-manager --timeout=300s
	@echo "Waiting for ClusterIssuers to be ready..."
	@kubectl wait --for=condition=Ready clusterissuer auth-provider-openfga-selfsigned-cluster-issuer --timeout=300s
	@kubectl wait --for=condition=Ready clusterissuer auth-provider-openfga-auth-provider-openfga-ca-cluster-issuer --timeout=300s
	@echo "Waiting for controller manager to be ready..."
	@kubectl wait --for=condition=Available deployment auth-provider-openfga-controller-manager -n auth-provider-openfga-system --timeout=300s
	@echo "Waiting for webhook to be ready..."
	@kubectl wait --for=condition=Available deployment auth-provider-openfga-authz-webhook -n auth-provider-openfga-system --timeout=300s
	@echo "Waiting for OpenFGA to be ready..."
	@kubectl wait --for=condition=Available deployment openfga -n openfga-system --timeout=300s
	@echo "All components are ready. Running chainsaw tests..."
	"$(CHAINSAW)" test test/

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	"$(GOLANGCI_LINT)" run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	"$(GOLANGCI_LINT)" run --fix

.PHONY: lint-config
lint-config: golangci-lint ## Verify golangci-lint linter configuration
	"$(GOLANGCI_LINT)" config verify

.PHONY: lint-ci
lint-ci: golangci-lint ## Run linting with CI-like configuration
	@echo "🔍 Running linter with same config as CI..."
	"$(GOLANGCI_LINT)" run --config=.golangci.yml
	@echo "✅ Linting completed successfully - ready for CI!"

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager cmd/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/main.go

# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	$(CONTAINER_TOOL) build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}

# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name auth-provider-openfga-builder
	$(CONTAINER_TOOL) buildx use auth-provider-openfga-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm auth-provider-openfga-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default > dist/install.yaml

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	"$(KUSTOMIZE)" build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	"$(KUSTOMIZE)" build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

##@ Kind Cluster Management

CLUSTER_NAME ?= auth-provider-openfga

.PHONY: kind-create
kind-create: ## Create a new kind cluster with FluxCD installed.
	@echo "Creating kind cluster: $(CLUSTER_NAME)"
	@if $(KIND) get clusters | grep -q "^$(CLUSTER_NAME)$$"; then \
		echo "Kind cluster '$(CLUSTER_NAME)' already exists"; \
	else \
		echo "Creating kind cluster configuration..."; \
		echo 'kind: Cluster' > /tmp/kind-config.yaml; \
		echo 'apiVersion: kind.x-k8s.io/v1alpha4' >> /tmp/kind-config.yaml; \
		echo 'nodes:' >> /tmp/kind-config.yaml; \
		echo '- role: control-plane' >> /tmp/kind-config.yaml; \
		echo '  kubeadmConfigPatches:' >> /tmp/kind-config.yaml; \
		echo '  - |' >> /tmp/kind-config.yaml; \
		echo '    kind: InitConfiguration' >> /tmp/kind-config.yaml; \
		echo '    nodeRegistration:' >> /tmp/kind-config.yaml; \
		echo '      kubeletExtraArgs:' >> /tmp/kind-config.yaml; \
		echo '        node-labels: "ingress-ready=true"' >> /tmp/kind-config.yaml; \
		echo '  extraPortMappings:' >> /tmp/kind-config.yaml; \
		echo '  - containerPort: 80' >> /tmp/kind-config.yaml; \
		echo '    hostPort: 80' >> /tmp/kind-config.yaml; \
		echo '    protocol: TCP' >> /tmp/kind-config.yaml; \
		echo '  - containerPort: 443' >> /tmp/kind-config.yaml; \
		echo '    hostPort: 443' >> /tmp/kind-config.yaml; \
		echo '    protocol: TCP' >> /tmp/kind-config.yaml; \
		$(KIND) create cluster --name $(CLUSTER_NAME) --config /tmp/kind-config.yaml || exit 1; \
		rm -f /tmp/kind-config.yaml; \
		echo "Kind cluster '$(CLUSTER_NAME)' created successfully"; \
	fi
	@echo "Waiting for cluster to be ready..."
	@$(KUBECTL) wait --for=condition=Ready nodes --all --timeout=300s
	@echo "Installing Flux..."
	@test -f "$(FLUX)" || { \
		echo "Installing Flux CLI..."; \
		mkdir -p "$(LOCALBIN)"; \
		FLUX_VERSION=$$(curl -s https://api.github.com/repos/fluxcd/flux2/releases/latest | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'); \
		OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
		ARCH=$$(uname -m); \
		case $$ARCH in x86_64) ARCH="amd64";; arm64|aarch64) ARCH="arm64";; esac; \
		curl -sL "https://github.com/fluxcd/flux2/releases/download/$${FLUX_VERSION}/flux_$${FLUX_VERSION#v}_$${OS}_$${ARCH}.tar.gz" | tar xz -C "$(LOCALBIN)" flux; \
		chmod +x "$(FLUX)"; \
	}
	@"$(FLUX)" install
	@$(KUBECTL) wait --for=condition=Ready pods --all -n flux-system --timeout=300s
	@echo "Kind cluster '$(CLUSTER_NAME)' is ready with FluxCD installed!"
	@echo "Infrastructure (cert-manager, etc.) will be deployed via Flux when you run 'make dev-deploy'"

.PHONY: kind-delete
kind-delete: ## Delete the kind cluster.
	@echo "Deleting kind cluster: $(CLUSTER_NAME)"
	@if $(KIND) get clusters | grep -q "^$(CLUSTER_NAME)$$"; then \
		$(KIND) delete cluster --name $(CLUSTER_NAME); \
		echo "Kind cluster '$(CLUSTER_NAME)' deleted successfully"; \
	else \
		echo "Kind cluster '$(CLUSTER_NAME)' does not exist"; \
	fi

.PHONY: kind-reset
kind-reset: kind-delete kind-create ## Delete and recreate the kind cluster.

.PHONY: kind-load-image
kind-load-image: docker-build ## Load the built Docker image into the kind cluster.
	@echo "Loading image ${IMG} into kind cluster $(CLUSTER_NAME)"
	$(KIND) load docker-image ${IMG} --name $(CLUSTER_NAME)

##@ Development Environment

.PHONY: dev-check-prereqs
dev-check-prereqs: ## Check development prerequisites
	@echo "🔍 Checking development prerequisites..."
	@command -v docker >/dev/null 2>&1 || { \
		echo "❌ Docker is required but not installed."; \
		echo "💡 Install Docker: https://docs.docker.com/get-docker/"; \
		echo "💡 Or use the DevContainer which has everything pre-installed"; \
		exit 1; \
	}
	@echo "✅ Docker found: $$(docker --version)"
	@command -v go >/dev/null 2>&1 || { \
		echo "❌ Go is required but not installed."; \
		echo "💡 Install Go: https://golang.org/dl/"; \
		exit 1; \
	}
	@echo "✅ Go found: $$(go version)"
	@echo "✅ Prerequisites check passed!"

.PHONY: dev-setup
dev-setup: dev-check-prereqs ## Setup complete development environment
	@echo "🚀 Setting up Auth Provider OpenFGA development environment..."
	@if $(KIND) get clusters 2>/dev/null | grep -q "^$(CLUSTER_NAME)$$"; then \
		echo "⚠️  Kind cluster '$(CLUSTER_NAME)' already exists."; \
		echo "Choose an option:"; \
		echo "  1) Continue with existing cluster"; \
		echo "  2) Reset cluster (delete and recreate)"; \
		echo "  3) Exit"; \
		read -p "Enter choice [1-3]: " choice; \
		case $$choice in \
			1) echo "✅ Using existing cluster";; \
			2) echo "🔄 Resetting cluster..."; $(MAKE) kind-delete;; \
			3) echo "👋 Goodbye!"; exit 0;; \
			*) echo "❌ Invalid choice"; exit 1;; \
		esac; \
	fi
	@echo "📦 Installing/checking development tools..."
	@$(MAKE) localbin-dir
	@$(MAKE) kind-create
	@$(MAKE) dev-deploy
	@echo ""
	@echo "🎉 Development environment setup complete!"
	@echo "📖 Quick commands:"
	@echo "  make dev-status         # Check environment status"
	@echo "  make dev-logs           # View application logs"
	@echo "  make dev-forward-metrics # Access metrics at localhost:8080"
	@echo "  make help               # View all available commands"

.PHONY: dev-deploy
dev-deploy: manifests generate kustomize docker-build kind-load-image ## Deploy to development environment
	@echo "🚀 Deploying to development environment..."
	@echo "📦 Deploying infrastructure and core services via Flux..."
	"$(KUSTOMIZE)" build config/bootstrap | $(KUBECTL) apply --server-side --wait=true -f -
	@echo "⏳ Waiting for infrastructure HelmReleases to be ready..."
	@$(KUBECTL) wait --for=condition=Ready helmrelease/cert-manager -n cert-manager --timeout=240s
	@$(KUBECTL) wait --for=condition=Ready helmrelease/cert-manager-csi-driver -n cert-manager --timeout=240s
	@$(KUBECTL) wait --for=condition=Ready helmrelease/openfga -n openfga-system --timeout=240s
	@echo "🛠️ Deploying application components..."
	cd config/manager && "$(KUSTOMIZE)" edit set image controller=${IMG}
	"$(KUSTOMIZE)" build config/local-dev | $(KUBECTL) apply --server-side --wait=true -f -
	@echo "⏳ Waiting for application deployments to be ready..."
	@$(KUBECTL) wait --for=condition=Available deployment --all -n auth-provider-openfga-system --timeout=180s
	@echo "✅ Development environment deployed successfully!"

.PHONY: dev-undeploy
dev-undeploy: kustomize ## Remove development environment deployments
	@echo "🗑️ Removing development environment..."
	"$(KUSTOMIZE)" build config/local-dev | $(KUBECTL) delete --ignore-not-found=true -f -

.PHONY: dev-reset
dev-reset: dev-undeploy dev-deploy ## Reset development environment

.PHONY: dev-logs
dev-logs: ## Show logs from development deployment
	@echo "=== Controller Manager Logs ==="
	@$(KUBECTL) logs -l control-plane=controller-manager -n auth-provider-openfga-system --tail=50 -f

.PHONY: dev-logs-webhook
dev-logs-webhook: ## Show logs from authz webhook
	@echo "=== AuthZ Webhook Logs ==="
	@$(KUBECTL) logs -l app.kubernetes.io/name=openfga-authz-webhook -n auth-provider-openfga-system --tail=50 -f

.PHONY: dev-status
dev-status: ## Show development environment status
	@echo "=== Cluster Info ==="
	@$(KUBECTL) cluster-info
	@echo ""
	@echo "=== Auth Provider OpenFGA Pods ==="
	@$(KUBECTL) get pods -n auth-provider-openfga-system
	@echo ""
	@echo "=== OpenFGA Pods ==="
	@$(KUBECTL) get pods -n openfga-system
	@echo ""
	@echo "=== Services ==="
	@$(KUBECTL) get services -n auth-provider-openfga-system
	@$(KUBECTL) get services -n openfga-system

.PHONY: dev-forward-metrics
dev-forward-metrics: ## Forward metrics port for local access
	@echo "Forwarding metrics port 8080..."
	@echo "Access metrics at http://localhost:8080/metrics"
	@$(KUBECTL) port-forward -n auth-provider-openfga-system svc/auth-provider-openfga-controller-manager-metrics-service 8080:8080

.PHONY: dev-forward-openfga
dev-forward-openfga: ## Forward OpenFGA port for local access
	@echo "Forwarding OpenFGA port 8080..."
	@echo "Access OpenFGA at http://localhost:8081"
	@$(KUBECTL) port-forward -n openfga-system svc/openfga 8081:8080

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
.PHONY: localbin-dir
localbin-dir:
	mkdir -p "$(LOCALBIN)"

## Tool Binaries
KUBECTL ?= kubectl
KIND ?= kind
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
CHAINSAW ?= $(LOCALBIN)/chainsaw
FLUX ?= $(LOCALBIN)/flux

## Tool Versions
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.17.2
#ENVTEST_VERSION is the version of controller-runtime release branch to fetch the envtest setup script (i.e. release-0.20)
ENVTEST_VERSION ?= $(shell go list -m -f "{{ .Version }}" sigs.k8s.io/controller-runtime | awk -F'[v.]' '{printf "release-%d.%d", $$2, $$3}')
#ENVTEST_K8S_VERSION is the version of Kubernetes to use for setting up ENVTEST binaries (i.e. 1.31)
ENVTEST_K8S_VERSION ?= $(shell go list -m -f "{{ .Version }}" k8s.io/api | awk -F'[v.]' '{printf "1.%d", $$3}')
GOLANGCI_LINT_VERSION ?= $(shell cat .golangci-version 2>/dev/null || echo "v2.1.6")
CHAINSAW_VERSION ?= v0.2.12

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): localbin-dir
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): localbin-dir
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: setup-envtest
setup-envtest: envtest ## Download the binaries required for ENVTEST in the local bin directory.
	@echo "Setting up envtest binaries for Kubernetes version $(ENVTEST_K8S_VERSION)..."
	@"$(ENVTEST)" use $(ENVTEST_K8S_VERSION) --bin-dir "$(LOCALBIN)" -p path || { \
		echo "Error: Failed to set up envtest binaries for version $(ENVTEST_K8S_VERSION)."; \
		exit 1; \
	}

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): localbin-dir
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): localbin-dir
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: chainsaw
chainsaw: $(CHAINSAW) ## Download chainsaw locally if necessary.
$(CHAINSAW): localbin-dir
	$(call go-install-tool,$(CHAINSAW),github.com/kyverno/chainsaw,$(CHAINSAW_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@if [ ! -f "$(1)-$(3)" ]; then \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f "$(1)" || true ;\
GOBIN="$(LOCALBIN)" go install $${package} ;\
mv "$(1)" "$(1)-$(3)" ;\
fi ;\
ln -sf "$(1)-$(3)" "$(1)"
endef

.PHONY: validate-local-dev
validate-local-dev: kustomize ## Validate local-dev configuration
	@echo "🔍 Validating local-dev configuration..."
	@echo "Building configuration:"
	@"$(KUSTOMIZE)" build config/local-dev | head -20
	@echo "Checking for deployment resources with correct names:"
	@"$(KUSTOMIZE)" build config/local-dev | grep -A 5 "kind: Deployment" | grep "name:" || echo "No deployments found"
	@echo "✅ Local-dev configuration validated"

.PHONY: validate-configs
validate-configs: validate-local-dev ## Validate all configurations
	@echo "🔍 Validating core configurations..."
	@echo "Bootstrap configuration:"
	@"$(KUSTOMIZE)" build config/bootstrap > /dev/null && echo "✅ Bootstrap config builds successfully"
	@echo "Default configuration:"
	@"$(KUSTOMIZE)" build config/default > /dev/null && echo "✅ Default config builds successfully"
	@echo "✅ Core configurations validated"
	@echo "Note: test-e2e validation skipped (requires external dependencies)"
