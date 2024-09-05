# OC Update Specs

This file contains OC update spec templates. OC update spec's are specifications for GDCH tailorbird plugin to appropriately update GDCH environment. OC update specs are expected to be a list of JSON objects with the following fields.

- subcomponent: the relevant OC subcomponent to be overridden. This will always be "cilium" for this repo.
- image_reference: the OC image reference. This is the particular GDCH image name that will be overridden. The relevant image name can be found in the corresponding [external_images.bzl file](https://source.corp.google.com/h/gke-internal/private-cloud/+/main:oc/unet/images/external_images.bzl;l=79;drc=78e31633e151221b8de866fb465005a8c29a2c8d). Note that GDCH may have multiple image names for a particular function (e.g. cilium operator) due to different configurations of GDCH cluster.
- docker_image: the specific docker image to be used.

## Example

```JSON
[
  {
    "subcomponent": "cilium",
    "image_reference": "lancer_cilium_cilium_129",
    "docker_image": "gcr.io/anthos-networking-ci/integration-test/cilium/cilium:c115023f83ac2b40966312c0f29a035b24f65d02-dpv2"
  },
  ...
]
```

A OC update spec template will have placeholder text of either `${CILIUM_IMAGE}` or `${CILIUM_OPERATOR_IMAGE}`. These values will be populated by the framework with the relevant generated Cilium images during provisioning.
