#!/bin/bash

echo "Usage:"
echo "  ./setup-devbox.sh [INSTANCE] [IMAGE] [IMAGE-PROJECT]"
echo ""

if [ $# -eq 3 ]; then
  INSTANCE=$1
  IMAGE=$2
  IMAGE_PROJECT=$3
else
  INSTANCE="devbox"
  IMAGE="gcilium-devbox-20210209"
  IMAGE_PROJECT="gke-anthos-datapath-presubmits"
fi

echo "Using values:"
echo " INSTANCE: $INSTANCE"
echo " IMAGE: $IMAGE"
echo " IMAGE-PROJECT: $IMAGE_PROJECT"

gscp='gcloud compute scp'
gssh='gcloud compute ssh'

# Exit on error.
set -e
# Echo all the commands.
set -x

# Create the instance.
gcloud compute instances create $INSTANCE --image=$IMAGE --image-project=$IMAGE_PROJECT --min-cpu-platform="Intel Skylake" --machine-type="n1-standard-32"
# TODO(valas): Find better way to find if instance is up.
sleep 60

cd ..
tar cfz /tmp/cilium-repo-snapshot.tar.gz *
$gssh $INSTANCE --command "mkdir -p ~/cilium/"
$gscp /tmp/cilium-repo-snapshot.tar.gz $INSTANCE:~/cilium/
rm /tmp/cilium-repo-snapshot.tar.gz
$gssh $INSTANCE --command "cd cilium && tar zxf cilium-repo-snapshot.tar.gz"

# Bring up K8s.
$gssh $INSTANCE --command "cd cilium/google_dev && ./package/1-bringup-k8s.sh"
echo "Done with K8s bring up, back to local."

# Bringup Cilium.
$gssh $INSTANCE --command "cd cilium/google_dev && ./bringup-cilium.sh"

