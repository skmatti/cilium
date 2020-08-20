#!/bin/bash

# This can be invoked by hand to build and push local dev cilium and operator
# images to dev project registry for further testing.

DOCKER_IMAGE_TAG=my-cilium make docker-image
docker tag cilium/cilium:my-cilium gcr.io/$USER-gke-dev/cilium:my-cilium
docker push gcr.io/$USER-gke-dev/cilium:my-cilium
docker tag cilium/operator:my-cilium gcr.io/$USER-gke-dev/cilium-operator:my-cilium
docker push gcr.io/$USER-gke-dev/cilium-operator:my-cilium
