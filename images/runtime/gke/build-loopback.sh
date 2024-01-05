#!/bin/sh -e

CGO_ENABLED=0 go build \
  -C gke/plugins \
  -o /gke/loopback \
  -mod=vendor \
  -ldflags="-s -w -extldflags -static -X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=$(git -C gke/plugins describe --tags --dirty)" \
  ./plugins/main/loopback
