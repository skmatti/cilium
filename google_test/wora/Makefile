GCP_PROJECT ?= anthos-networking-ci
IMAGE_REGISTRY ?= gcr.io/$(GCP_PROJECT)
IMAGE_TAG ?= $(USER)

WORA_BASE_IMAGE_REGISTRY ?= $(IMAGE_REGISTRY)/wora
WORA_BASE_IMAGE_NAME ?= anthos-networking-test-workloads
WORA_BASE_IMAGE_TAG ?= latest

WORA_IMAGE_REGISTRY ?= $(WORA_BASE_IMAGE_REGISTRY)
WORA_IMAGE_NAME ?= $(WORA_BASE_IMAGE_NAME)

WORA_IMAGE_TAG ?= $(IMAGE_TAG)

WORA_IMAGE_FULL_NAME = $(WORA_IMAGE_REGISTRY)/$(WORA_IMAGE_NAME):$(WORA_IMAGE_TAG)

WORA_DOCKERFILE_DIR ?= $(CURDIR)
WORA_DOCKERFILE = $(realpath $(WORA_DOCKERFILE_DIR)/Dockerfile)

CILIUM_E2E_IMAGE_NAME = cilium-e2e
CILIUM_E2E_IMAGE_FULL_NAME = $(WORA_IMAGE_REGISTRY)/$(CILIUM_E2E_IMAGE_NAME):$(WORA_IMAGE_TAG)
CILIUM_E2E_DOCKERFILE = $(realpath $(CURDIR)/Dockerfile)

# Base images are copied from us-central1-docker.pkg.dev/gke-component-images/gke-component-images
ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY ?= us-central1-docker.pkg.dev/anthos-networking-ci/gke-component-images
ADVANCEDDATAPATH_BASE_IMAGE_NAME ?= advanceddatapath
ADVANCEDDATAPATH_BASE_IMAGE_TAG ?= 32.3.16

ADVANCEDDATAPATH_IMAGE_REGISTRY ?= $(ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY)
ADVANCEDDATAPATH_IMAGE_NAME ?= $(ADVANCEDDATAPATH_BASE_IMAGE_NAME)

ADVANCEDDATAPATH_IMAGE_SUFFIX ?= $(USER)

ifneq ($(ADVANCEDDATAPATH_IMAGE_SUFFIX),)
ADVANCEDDATAPATH_IMAGE_TAG ?= "$(ADVANCEDDATAPATH_BASE_IMAGE_TAG)-$(ADVANCEDDATAPATH_IMAGE_SUFFIX)"
else
ADVANCEDDATAPATH_IMAGE_TAG ?= $(ADVANCEDDATAPATH_BASE_IMAGE_TAG)
endif

ADVANCEDDATAPATH_IMAGE_FULL_NAME = $(ADVANCEDDATAPATH_IMAGE_REGISTRY)/$(ADVANCEDDATAPATH_IMAGE_NAME):$(ADVANCEDDATAPATH_IMAGE_TAG)

ADVANCEDDATAPATH_DOCKERFILE_DIR ?= $(CURDIR)/gke_component_override
ADVANCEDDATAPATH_DOCKERFILE = $(realpath $(ADVANCEDDATAPATH_DOCKERFILE_DIR)/Dockerfile)

# Cilium version to be used in the advanceddatapath image for component override.
CILIUM_DOCKER_IMAGE_TAG ?= nightly
DOCKER_IMAGE_TAG ?= nightly

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

provision-gke: ## Update version of advanceddatapath component.
	ADVANCEDDATAPATH_IMAGE_TAG=$(ADVANCEDDATAPATH_IMAGE_TAG) \
	ADVANCEDDATAPATH_IMAGE_FULL_NAME=$(ADVANCEDDATAPATH_IMAGE_FULL_NAME) \
	TBCONFIG="$(TBCONFIG)" \
	./provision_gke.sh

##@ Container images

comma =,

# Command requires a comma-separated list of top-level registry names that need
# to be accessed to pull and push images. The expression generates this list
# from Cilium and advanceddatapath component registry names. See
# http://yaqs/5946736126617190400#a1n6.
configure-docker: ## Configure docker.
	gcloud auth configure-docker \
		$(subst $(eval) $(eval),$(comma),$(sort $(foreach path,$(WORA_BASE_IMAGE_REGISTRY) $(WORA_IMAGE_REGISTRY) $(ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY) $(ADVANCEDDATAPATH_IMAGE_REGISTRY),$(firstword $(subst /, , $(path))))))

ifeq ($(WORA_DOCKERFILE_DIR),$(filter $(WORA_DOCKERFILE_DIR), $(CURDIR) multistage))

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

push-wora-image: ## Push WORA image.
	docker push "$(WORA_IMAGE_FULL_NAME)"

check-advanceddatapath-image-tag: ## Prevent overwriting component image tag.
ifeq ($(ADVANCEDDATAPATH_IMAGE_TAG),$(ADVANCEDDATAPATH_BASE_IMAGE_TAG))
	@error "Refusing to overwrite advanceddatapath base image."
endif

advanceddatapath-image: check-advanceddatapath-image-tag ## Build advanceddatapath image.
	docker build \
		--build-arg=BASE_IMAGE_REGISTRY="$(ADVANCEDDATAPATH_BASE_IMAGE_REGISTRY)" \
		--build-arg=BASE_IMAGE_NAME="$(ADVANCEDDATAPATH_BASE_IMAGE_NAME)" \
		--build-arg=BASE_IMAGE_TAG="$(ADVANCEDDATAPATH_BASE_IMAGE_TAG)" \
		--build-arg=CILIUM_IMAGE_REGISTRY="$(IMAGE_REGISTRY)" \
		--build-arg=CILIUM_IMAGE_TAG="$(CILIUM_DOCKER_IMAGE_TAG)" \
		--build-arg=CILIUM_OPERATOR_IMAGE_TAG="$(DOCKER_IMAGE_TAG)" \
		-t "${ADVANCEDDATAPATH_IMAGE_FULL_NAME}" \
		-f "${ADVANCEDDATAPATH_DOCKERFILE}" \
		"$(CURDIR)"

push-advanceddatapath-image: check-advanceddatapath-image-tag ## Push advanceddatapath image.
	docker push "${ADVANCEDDATAPATH_IMAGE_FULL_NAME}"

##@ WORA test images

cilium-e2e-image: wora-vendor ## Build general E2E WORA test image.
	docker build $(DOCKER_BUILD_OPTIONS) \
		--build-arg=BASE_IMAGE_REGISTRY="$(WORA_BASE_IMAGE_REGISTRY)" \
		--build-arg=BASE_IMAGE_NAME="$(WORA_BASE_IMAGE_NAME)" \
		--build-arg=BASE_IMAGE_TAG="$(WORA_BASE_IMAGE_TAG)" \
		--build-arg=VENDOR="$(VENDOR)" \
		$(DOCKER_BUILD_EXTRA_ARGS) \
		-t "$(CILIUM_E2E_IMAGE_FULL_NAME)" \
		-f "$(CILIUM_E2E_DOCKERFILE)" \
		"$(CURDIR)"

push-cilium-e2e-image: ## Push general E2E wora test image.
	docker push "$(CILIUM_E2E_IMAGE_FULL_NAME)"
