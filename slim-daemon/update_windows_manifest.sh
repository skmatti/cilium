#!/bin/sh

# This script pulls the golden Windows manifest files from Google3.
# Run this script on your gLinux workstation to sync the base layers of Windows.
for winver in ${1:-ltsc2019 1909 2004 20H2}
do
  echo cloud/containers/windows/servercore.$winver.config.json

  # cat the files before copying them. This is an effort to warm up the CitC
  # client so that we don't get that the following error:
  #
  # cp: skipping file '/google/src/files/head/depot/google3/cloud/containers/windows/servercore.ltsc2019.config.json', as it was replaced while being copied
  #
  # This is likely because /google/src/files/head is an alias for a CL number
  # that's ever changing.
  # https://sourceware.org/legacy-ml/cygwin/2016-05/msg00194.html
  cat /google/src/files/head/depot/google3/cloud/containers/windows/servercore.$winver.config.json > /dev/null
  cat /google/src/files/head/depot/google3/cloud/containers/windows/servercore.$winver.manifest.json > /dev/null

  cp -f /google/src/files/head/depot/google3/cloud/containers/windows/servercore.$winver.config.json ./servercore.$winver.config.json
  cp -f /google/src/files/head/depot/google3/cloud/containers/windows/servercore.$winver.manifest.json ./servercore.$winver.manifest.json
done
