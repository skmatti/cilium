#!/bin/bash

# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
set -e
set -u
set -o pipefail

# Config git client for Prow to pull source code.
if [[ -n "${GIT_HTTP_COOKIEFILE}" ]]; then
    echo "Add git config from prow cookie"
    git config --global user.name "${GIT_USER_NAME}"
    git config --global user.email "${GIT_USER_EMAIL}"
    git config --global http.cookiefile "${GIT_HTTP_COOKIEFILE}"

    echo "Add gerrit redirects to git config"
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf sso://gke-internal.git.corp.google.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf sso://gke-internal
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf https://gke-internal.git.corp.google.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf git://gke-internal.git.corp.google.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf git://gke-internal.googlesource.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf git+ssh://gke-internal.git.corp.google.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf git+ssh://gke-internal.googlesource.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf ssh://gke-internal.git.corp.google.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf ssh://gke-internal.googlesource.com
    git config --add --global url."https://gke-internal.googlesource.com".insteadOf sso://gke-internal.googlesource.com
    export GOPRIVATE='*.googlesource.com,*.git.corp.google.com'
fi

# Get credentails to use tailorbied and create the kind cluster
echo "Getting credentials for tailorbird-prod..."
gcloud container clusters get-credentials tailorbird-prod \
--region us-west2 --project tailorbird

ROOKERY_CONFIG="${ROOKERY_CONFIG:-google_test/upstream_test/tailorbird/rookery-kind.yaml}"
kubetest2-tailorbird \
	--up --down \
	--tbconfig "${ROOKERY_CONFIG}" \
	--test exec -- \
	./google_test/upstream_test/conformance/run_k8s_conformance_test.sh
