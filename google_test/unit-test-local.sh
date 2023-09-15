#!/bin/sh -ex

set +u

. /etc/profile.d/env.sh

make precheck
make postcheck
make integration-tests
make tests-privileged
