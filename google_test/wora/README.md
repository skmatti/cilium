# WORA tests

The code in this folder adapts the Tailorbird Write-Once-Run-Anywhere (WORA)
[prototype][] to run a Tailorbird test application against a cluster.

For more information, and a user guide, see the [project page][project].

## Status

There are currently several periodic and presubmit Prow jobs running WORA tests.

These jobs currently run either a general end-to-end test suite or the
Kubernetes conformance test suite, and support running against a locally-built
Cilium version.

## Code location

### Application plugin base images

- [WORA base image (README)][worabase]

### Cilium WORA tests

- [Cilium WORA tests (README)][ciliumwora]

## Test configuration

> Note: End users should use only the variables below to configure a test. Other
> environment variables that affect the test, such as `TBENV`, are used for
> plugin development, and should not be set by end users.

End users can use the following environment variables to configure a test:

`CILIUM_GITREF`: If set, will be used to build new Cilium images and use an
add-on manager to use these images to provision the cluster. If not set, will
provision the cluster with the default version of Cilium for the selected
platform version.

`PATCH_CONTENT_DIR`: If set, files at this location will be used as a base to
generate the add-on configuration containing the newly built Cilium images. If
not set, will generate an add-on configuration that only updates the Cilium and
Cilium-operator images, from
[these templates](addon/patch_content/abm1.28.0-gke.311/image-only-templates/).
This is a workaround for b/327682436.

`TBCONFIG`: Tailorbird rookery configuration used to provision the cluster.
There are several configurations defined:

1. `sut-abm-gce.yaml` (default): ABM on GCE.
2. `sut-abm-atl.yaml`: ABM on vSphere (in the ATL lab).
3. `sut-abm-mtv.yaml`: ABM on vSphere (in the MTV lab).
4. `sut-gdce.yaml`: GDCE staging.
5. `sut-gke.yaml`: GKE (with nightly build of the advanced datapath component).

`WORA_BASE_IMAGE_TAG`: Image tag for the application plugin base image. Test
binaries are added to this image to create the application plugin image used for
the test. Defaults to `latest`.

`WORA_CONFIG`: Tailorbird rookery configuration for the WORA test application.
This configuration determines which test to run. There are currently two
configurations defined:

1. `integration_test.yaml` (default): Run the general end-to-end test suite.
2. `conformance_test.yaml`: Run the Kubernetes conformance test suite.

`WORA_DOCKERFILE_DIR`: Test applications generally require a test binary to be
built and included in the WORA test application image. This variable selects the
Dockerfile to be used for this build. This can be an absolute path or a path
relative to the Prow entrypoint script. The build context is always the location
of the entrypoint script. Two options are currently provided:

1. Unset (default): Include the `e2e.test` binary built from
   [e2e_suite_test.go](./e2e_suite_test.go).
2. `conformance`: Include the Kubernetes conformance test suite.

`WORA_IMAGE_TAG`: If this variable is set, assume that the WORA test application
has been built earlier and use this tag for the test. Default is unset.

Currently there are several test configurations set up to run periodically (see
below).

## Prow jobs

There are currently periodic and presubmit jobs defined [here][ciliumprowjobs].

[ciliumprowjobs]:
  https://source.corp.google.com/h/gke-internal/codesearch/+/master:test-infra/prow/gob/config/gke-internal-review.googlesource.com/third_party/cilium/gke-internal_cilium.yaml

### Periodic jobs

The following jobs are currently running periodically and displayed on TestGrid:

1. [wora-abm-gce_cilium][]: General end-to-end test suite on ABM on GCE, using a
   locally-built version of Cilium.
2. [wora-conformance-abm-gce_cilium][]: Kubernetes conformance test suite on ABM
   on GCE, using a locally-built version of Cilium.
3. [wora-abm-atl_cilium][]: General end-to-end test suite on ABM on vSphere in
   the ATL lab, using a locally-built version of Cilium.
4. [wora-abm-mtv_cilium][]: General end-to-end test suite on ABM on vSphere in
   the MTV lab, using a locally-built version of Cilium.
5. [wora-gdce_cilium][]: General end-to-end test suite on GDCE staging, using a
   locally-built version of Cilium.
6. [wora-conformance-gdce_cilium][]: Kubernetes conformance test suite on GDCE
   staging, using a locally-built version of Cilium.
7. [wora-gke_cilium][]: General end-to-end test suite on GKE, using a nightly
   build of the GKE advanced datapath component.
8. [wora-conformance-gke_cilium][]: Kubernetes conformance test suite on GKE,
   using a nightly build of the GKE advanced datapath component.

> Note: The first six jobs above set `CILIUM_GITREF=v1.13-anthos1.28`.

[wora-abm-gce_cilium]:
  https://testgrid.corp.google.com/cilium#wora-abm-gce_cilium
[wora-conformance-abm-gce_cilium]:
  https://testgrid.corp.google.com/cilium#wora-conformance-abm-gce_cilium
[wora-abm-atl_cilium]:
  https://testgrid.corp.google.com/cilium#wora-abm-atl_cilium
[wora-abm-mtv_cilium]:
  https://testgrid.corp.google.com/cilium#wora-abm-mtv_cilium
[wora-gdce_cilium]: https://testgrid.corp.google.com/cilium#wora-gdce_cilium
[wora-conformance-gdce_cilium]:
  https://testgrid.corp.google.com/cilium#wora-conformance-gdce_cilium
[wora-gke_cilium]: https://testgrid.corp.google.com/cilium#wora-gke_cilium
[wora-conformance-gke_cilium]:
  https://testgrid.corp.google.com/cilium#wora-conformance-gke_cilium

### Presubmit jobs

Several presubmit jobs are defined and can be triggered by the following
comments:

1. `/test wora-abm-gce`: General end-to-end test suite on ABM on GCE.
2. `/test wora-conformance-abm-gce`: Kubernetes conformance test suite on ABM on
   GCE.
3. `/test wora-abm-atl`: General end-to-end test suite on ABM on vSphere in the
   ATL lab.
4. `/test wora-conformance-abm-atl`: Kubernetes conformance test suite on ABM on
   vSphere in the ATL lab.
5. `/test wora-abm-mtv`: General end-to-end test suite on ABM on vSphere in the
   MTV lab.
6. `/test wora-conformance-abm-mtv`: Kubernetes conformance test suite on ABM on
   GCE.
7. `/test wora-gdce`: General end-to-end test on GDCE staging. This job builds
   Cilium from the `v1.12.6-anthos1.15-gke4.2` branch, matching the Cilium
   branch currently used in GDCE staging.
8. `/test wora-conformance-gdce`: General end-to-end test on GDCE staging. This
   job builds Cilium from the `v1.12.6-anthos1.15-gke4.2` branch, matching the
   Cilium branch currently used in GDCE staging.
9. `/test wora-gke`: General end-to-end test suite on GKE, using a nightly build
   of the GKE advanced datapath component.
10. `/test wora-conformance-gke`: Kubernetes conformance test suite on GKE,
    using a nightly build of the GKE advanced datapath component.

> Note: Jobs 1–6 above skip the Cilium build. This is due to a bug building
> Cilium from `HEAD` on `master` ([b/327440595][]). Jobs that build Cilium from
> `v1.13-anthos1.28` branch can be triggered with `/test wora-abm-gce-v1.13` and
> `/test wora-conformance-abm-gce-v1.13`.

## Manual runs

> Note: Instructions assume running from the top of the [cilium] repo.

Tests can be run manually with the following command line. Set `PROW_JOB_ID` to
something unique, for instance including your user name:

```shell
PROW_JOB_ID="${USER}-1" TBCONFIG=sut-abm-gce.yaml ./google_test/wora/prow_entrypoint.sh
```

Other variables may be set as described in
[Test configuration](#test-configuration).

You can also add `RUN_DOWN=false` to suppress SUT termination at the end. This
allows multiple runs with same SUT.

[cilium]:
  https://gke-internal-review.git.corp.google.com/admin/repos/third_party/cilium

## References

- [Design doc][design].
- [Project page][project].

[b/327440595]: https://b.corp.google.com/issues/327440595
[ciliumwora]:
  https://source.corp.google.com/h/gke-internal/third_party/cilium/+/master:google_test/wora/
[design]:
  https://goto.google.com/anthos-networking-e2e-test-infrastructure-design
[project]: https://goto.google.com/asmg-anthos-networking-ci-project
[prototype]:
  https://source.corp.google.com/h/team/tailorbird-team/tailorbird/+/master:tests/e2e/wora/
[worabase]:
  https://source.corp.google.com/h/gke-internal/anthos-networking/+/main:test-infra/anthos-networking-test-workloads/
