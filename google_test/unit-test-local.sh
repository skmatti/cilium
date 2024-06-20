#!/bin/sh -ex

set +u

. /etc/profile.d/env.sh

rm -rf "${HOST_TEST_REPORT_DIR:?Report directory location must be set}"
mkdir -p "${HOST_TEST_REPORT_DIR}"

# Install go-junit-report(https://github.com/jstemmer/go-junit-report) to generate
# junit report for CI/CD tool.
GOBIN=/usr/local/go/bin go install github.com/jstemmer/go-junit-report/v2@latest

run_tests_and_report() {
  test_target=$1
  output_file=$2

  tmp_output="$(mktemp -t ${test_target}.XXXXXXXXXX)"

  log_and_cleanup() {
    cat "${tmp_output}"
    rm -f "${tmp_output}"
  }
  trap log_and_cleanup EXIT

  # Run the tests
  GO_TEST_FLAGS=-v make "${test_target}" > "${tmp_output}" 2>&1
  retval=$?
  if [ "${retval}" = 0 ]; then
    go-junit-report -iocopy -set-exit-code -debug.print-events -in "${tmp_output}" -out "${output_file}"
    retval=$?
  fi
  return "${retval}"
}

run_tests_and_report integration-tests "${HOST_TEST_REPORT_DIR}/junit_integration_tests_result.xml"
integration_tests_status=$?
run_tests_and_report tests-privileged "${HOST_TEST_REPORT_DIR}/junit_privileged_tests_result.xml"
privileged_tests_status=$?

if [ "${integration_tests_status}" -ne 0 ] || [ "${privileged_tests_status}" -ne 0 ]; then
  exit 1
fi
