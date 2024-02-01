#!/bin/bash

# Config git client for Prow to pull source code.
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
