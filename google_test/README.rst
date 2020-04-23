Google Test Orchestration for Cilium on GoB
================================
This dir contains scripts that Google internally uses to orchestrate
Cilium's tests.

Unit Tests
==========

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

Runtime Tests
=============

Runtime Tests cover tests in `cilium/test/runtime` but instead of
VirtualBox, they are triggered by a prow job and executed in GCE.
`runtime-test-gce-vagrantfile` is the GCE equivalent of
`cilium/test/Vagrantfile`.

E2E Tests
=========

These tests are run as automatic prow job on gke prow cluster, but the
actual tests run in a separate GCP project owned by anthos-datapath-dev@
to provide better control and debuggability.

When a periodic job/comment trigger kicks in, a Prow job is started
automatically runs `e2e.sh`, which syncs the current HEAD, builds
cilium/cilium-operator images, pushs images to testing GCP project and
runs the ginkgo tests there.
