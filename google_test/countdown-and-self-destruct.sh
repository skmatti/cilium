#!/bin/bash

# This is triggered at startup of a testing VM by presubmit-unit.sh.
#
# This does nothing until 1 day after the creation of the testing VM, at which
# time this will trigger self-destruction so that we don't permenantly leak
# resources.

sleep 1d
NAME=$(curl -X GET http://metadata.google.internal/computeMetadata/v1/instance/name -H 'Metadata-Flavor: Google')
ZONE=$(curl -X GET http://metadata.google.internal/computeMetadata/v1/instance/zone -H 'Metadata-Flavor: Google')
gcloud --quiet compute instances delete $NAME --zone $ZONE
