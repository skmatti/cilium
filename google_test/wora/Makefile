GCP_PROJECT ?= anthos-networking-ci
IMAGE_REGISTRY ?= gcr.io/$(GCP_PROJECT)
IMAGE_TAG ?= $(USER)

TBENV ?= prod

ifndef WORA_BASE_IMAGE_REGISTRY
ifeq ($(TBENV), prod)
WORA_BASE_IMAGE_REGISTRY ?= $(IMAGE_REGISTRY)/applications
else ifeq ($(TBENV), int)
WORA_BASE_IMAGE_REGISTRY ?= $(IMAGE_REGISTRY)/staging/applications
else
$(error "Found TBENV=$(TBENV). Supported values are 'prod' and 'int'.")
endif
endif

WORA_BASE_IMAGE_NAME ?= anthos-networking-test-workloads
WORA_BASE_IMAGE_TAG ?= latest

WORA_IMAGE_REGISTRY ?= $(WORA_BASE_IMAGE_REGISTRY)
WORA_IMAGE_NAME ?= $(WORA_BASE_IMAGE_NAME)

WORA_IMAGE_TAG ?= $(IMAGE_TAG)

WORA_IMAGE_FULL_NAME = $(WORA_IMAGE_REGISTRY)/$(WORA_IMAGE_NAME):$(WORA_IMAGE_TAG)

WORA_DOCKERFILE_DIR ?= $(CURDIR)
WORA_DOCKERFILE = $(realpath $(WORA_DOCKERFILE_DIR)/Dockerfile)

ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY ?= us-central1-docker.pkg.dev/anthos-networking-ci/gke-component-images
ADVANCEDDATAPATH_BASE_IMAGE_NAME ?= advanceddatapath
ADVANCEDDATAPATH_BASE_IMAGE_TAG = 0.0.1001

ADVANCEDDATAPATH_IMAGE_REGISTRY ?= $(ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY)
ADVANCEDDATAPATH_IMAGE_NAME ?= $(ADVANCEDDATAPATH_BASE_IMAGE_NAME)

ADVANCEDDATAPATH_IMAGE_SUFFIX ?= $(USER)
ADVANCEDDATAPATH_IMAGE_TAG ?= "$(ADVANCEDDATAPATH_BASE_IMAGE_TAG)-$(ADVANCEDDATAPATH_IMAGE_SUFFIX)"

ifeq ($(ADVANCEDDATAPATH_IMAGE_TAG), $(ADVANCEDDATAPATH_BASE_IMAGE_TAG))
$(error "Cannot overwrite existing base image: $(ADVANCEDDATAPATH_BASE_IMAGE_TAG)")
endif

ADVANCEDDATAPATH_IMAGE_FULL_NAME = $(ADVANCEDDATAPATH_IMAGE_REGISTRY)/$(ADVANCEDDATAPATH_IMAGE_NAME):$(ADVANCEDDATAPATH_IMAGE_TAG)

ADVANCEDDATAPATH_DOCKERFILE_DIR ?= $(CURDIR)/gke_component_override
ADVANCEDDATAPATH_DOCKERFILE = $(realpath $(ADVANCEDDATAPATH_DOCKERFILE_DIR)/Dockerfile)

# Cilium version to be used in the advanceddatapath image for component override.
CILIUM_TAG ?= nightly

# Working directory for intermediate files.
WORKDIR ?= .

# Intermediate location for package dependencies.
VENDOR=$(WORKDIR)/vendor

# Allow for options in docker build.
DOCKER_BUILD_OPTIONS ?=

# Make all targets PHONY.
MAKEFLAGS += --always-make

##@ General

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

print-% : ## Print environment variables.
	$(info $*=$($*)) @true

##@ Provisioning

provision-gke:
	ADVANCEDDATAPATH_IMAGE_TAG=$(ADVANCEDDATAPATH_IMAGE_TAG) \
	ADVANCEDDATAPATH_IMAGE_FULL_NAME=$(ADVANCEDDATAPATH_IMAGE_FULL_NAME) \
	TBCONFIG="$(TBCONFIG)" \
	./provision_gke.sh

##@ Container images

configure-docker: ## Configure docker.
	gcloud auth configure-docker

ifeq ($(WORA_DOCKERFILE_DIR),$(CURDIR))

DOCKER_BUILD_EXTRA_ARGS += --build-arg=VENDOR="$(VENDOR)"

wora-image: wora-vendor

endif

wora-vendor: ## Fetch package dependencies.
	GOWORK=off go mod vendor -o $(VENDOR)

wora-image: ## Build WORA image.
	docker build $(DOCKER_BUILD_OPTIONS) \
		--build-arg=BASE_IMAGE_REGISTRY="$(WORA_BASE_IMAGE_REGISTRY)" \
		--build-arg=BASE_IMAGE_NAME="$(WORA_BASE_IMAGE_NAME)" \
		--build-arg=BASE_IMAGE_TAG="$(WORA_BASE_IMAGE_TAG)" \
		$(DOCKER_BUILD_EXTRA_ARGS) \
		-t "$(WORA_IMAGE_FULL_NAME)" \
		-f "$(WORA_DOCKERFILE)" \
		"$(CURDIR)"
	@echo "Built image with TBENV=$(TBENV)."

push-wora-image: ## Push WORA image.
	docker push $(WORA_IMAGE_FULL_NAME)
	@echo "Pushed image with TBENV=$(TBENV)."

advanceddatapath-image: ## Build advanceddatapath image.
	docker build \
		--platform=x86_64 \
		--build-arg=BASE_IMAGE_REGISTRY="$(ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY)" \
		--build-arg=BASE_IMAGE_NAME="$(ADVANCEDDATAPATH_BASE_IMAGE_NAME)" \
		--build-arg=BASE_IMAGE_TAG="$(ADVANCEDDATAPATH_BASE_IMAGE_TAG)" \
		--build-arg=cilium_tag="$(CILIUM_TAG)" \
		-t "${ADVANCEDDATAPATH_IMAGE_FULL_NAME}" \
		-f "${ADVANCEDDATAPATH_DOCKERFILE}" \
		"$(CURDIR)"

push-advanceddatapath-image: ## Push advanceddatapath image.
	docker push "${ADVANCEDDATAPATH_IMAGE_FULL_NAME}"
