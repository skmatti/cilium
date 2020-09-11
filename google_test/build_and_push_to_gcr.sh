#!/bin/bash

# This can be invoked by hand to build and push local dev cilium and operator
# images to dev project registry for further testing.

TAG=my-cilium

DOCKER_IMAGE_TAG=$TAG make docker-image
docker tag cilium/cilium:$TAG gcr.io/$USER-gke-dev/cilium:$TAG
docker push gcr.io/$USER-gke-dev/cilium:$TAG
docker tag cilium/operator-generic:$TAG gcr.io/$USER-gke-dev/cilium-operator:$TAG
docker push gcr.io/$USER-gke-dev/cilium-operator:$TAG
