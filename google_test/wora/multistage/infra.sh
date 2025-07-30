#!/bin/bash

set -eux

# Runs the multistage tool in a Docker container to apply new addon configuration
# with different Cilium versions in a tailorbird cluster.
update_addon() {
	gcloud auth configure-docker us-docker.pkg.dev --quiet
	local artifacts="${1:?}"
	local addon_gspath="${2:?}"
	local image="us-docker.pkg.dev/anthos-networking-ci/apps/multistage-infra:latest"

	echo "Running multistage-infra container..." >&2
	docker run --pull=always \
		-v "${artifacts}":"${artifacts}" "${image}" \
		--artifacts-dir="${artifacts}" \
		--addon-path="${addon_gspath}"

	echo "multistage-infra container finished successfully." >&2
}

update_addon "${ARTIFACTS_BASE:?}" "${TARGET_ADDON_CONFIG:?}"
