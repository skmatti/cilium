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
