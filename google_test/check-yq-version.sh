#!/bin/bash

# Checks that yq is installed and has version 4 or higher.
check_yq_version() {
  local version
  version="$(yq --version 2>/dev/null | cut -d' ' -f3)"
  if [[ -z "${version}" ]]; then
    echo "Error: yq not found. Please install yq v4: go install github.com/mikefarah/yq/v4@latest" >&2
    return 1
  fi

  if [[ "$(printf '%s\n%s\n' "${version}" "4" | sort -V | tail -n 1 || true)" != "${version}" ]]; then
    echo "Error: yq version ${version} < 4. Please install yq v4: go install github.com/mikefarah/yq/v4@latest" >&2
    return 1
  fi

  return 0
}

check_yq_version
