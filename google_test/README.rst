Google Test Orchestration for Cilium on GoB
================================
This dir contains scripts that Google internally uses to orchestrate
Cilium's tests.

Golang Unit Tests
=================

These tests are run as automatic prow job on gke prow cluster, but the
actual tests run in a separate GCP project owned by anthos-datapath-dev@
to provide better debuggability.

When a git push creates a PR in the internal GoB repo, a code change event
will trigger PROW to spin up a workload pod with a synced repo. The synced
repo has the current PR on top of HEAD. In the workload repo,
`presubmit-unit.sh` runs to spin up a VM with testing image in dedicated
GCP project `gke-anthos-datapath-presubmits` and ship the synced repo to
the target testing VM. In the testing VM, `unit-test-local.sh` is
triggered to launch the actual unit tests.

Detailed doc can be found at go/cilium-ut-on-gob.
