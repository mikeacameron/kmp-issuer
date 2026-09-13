# Image to build and deploy.
IMG ?= ghcr.io/mikeacameron/kmp-issuer:latest

# Namespace the controller is deployed into.
NAMESPACE ?= kmp-issuer-system

# Tool versions.
CONTROLLER_TOOLS_VERSION ?= v0.17.1

LOCALBIN ?= $(shell pwd)/bin
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

##@ Development

.PHONY: tidy
tidy: ## Resolve the module dependencies and write go.sum.
	go mod tidy

.PHONY: fmt
fmt: ## Format the code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: test
test: fmt vet ## Run the unit tests.
	go test ./... -coverprofile cover.out

.PHONY: build
build: fmt vet ## Build the manager binary into bin/.
	go build -o bin/manager ./cmd

.PHONY: run
run: ## Run the manager against the cluster in ~/.kube/config.
	go run ./cmd --cluster-resource-namespace=$(NAMESPACE)

##@ Code generation

$(LOCALBIN):
	mkdir -p $(LOCALBIN)

.PHONY: controller-gen
controller-gen: $(LOCALBIN) ## Install controller-gen into bin/.
	test -s $(CONTROLLER_GEN) || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: manifests
manifests: controller-gen ## Regenerate the CRDs and RBAC from the code annotations.
	$(CONTROLLER_GEN) rbac:roleName=kmp-issuer-manager-role crd paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Regenerate the deepcopy functions.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

##@ Container image

.PHONY: docker-build
docker-build: ## Build the container image.
	docker build -t $(IMG) .

.PHONY: docker-push
docker-push: ## Push the container image.
	docker push $(IMG)

##@ Deployment

.PHONY: install
install: ## Install the CRDs into the current cluster.
	kubectl apply -f config/crd/bases

.PHONY: uninstall
uninstall: ## Remove the CRDs from the current cluster.
	kubectl delete --ignore-not-found -f config/crd/bases

.PHONY: deploy
deploy: ## Deploy the controller into the current cluster.
	cd config/manager && kustomize edit set image ghcr.io/mikeacameron/kmp-issuer=$(IMG)
	kustomize build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Remove the controller from the current cluster.
	kustomize build config/default | kubectl delete --ignore-not-found -f -
