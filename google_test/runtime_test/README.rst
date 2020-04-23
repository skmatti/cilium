*************
Runtime Tests
*************

Docker Container for Prow Job
=============================

A CL is submitted to GoB will trigger a Prow job,
gke-advanced-datapath-presubmit-integration, which runs tests specified
in cilium/test/runtime. This docker container provides minimal components
to launch Runtime Tests.

To create a new docker image:

PROJ=gke-anthos-datapath-presubmits
IMAGE=cilium-runtime-test-host
TAG=$(TZ=':America/Los_Angeles' date '+%Y%m%d')

gcloud auth configure-docker --project=$PROJ
docker build -t runtime-test-env .
docker tag runtime-test-env gcr.io/$PROJ/$IMAGE:$TAG
docker push gcr.io/$PROJ/$IMAGE:$TAG
