#!/bin/bash

set -o xtrace

ROOT="$(dirname "${BASH_SOURCE[0]}")"

export TBENV=${TBENV:-int}

# For manual runs:
#  - use PROW_JOB_ID to use predictable run id.
#  - set RUN_DOWN=false

# This will be used by run.sh to revert KUBECONFIG env var change made by kt2-tb.
# Without this, nested tb controlplane login will write to SUT cluster's kubeconfig.
export OLD_KUBECONFIG="${KUBECONFIG}"

kubetest2-tailorbird \
    --verbose \
    --up \
    --down="${RUN_DOWN:-true}" \
    --tbconfig="${ROOT}/${TBCONFIG:-"sut.yaml"}" \
    --tbenv="${TBENV}" \
    --test=exec \
    -- \
    "${ROOT}/run.sh"
