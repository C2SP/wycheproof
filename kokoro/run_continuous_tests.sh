#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

run_bazel_tests() {
  local -ar test_args=("$@")

  local bazel_exit_code=0
  bazel test --test_output=all "${test_args[@]}" || bazel_exit_code="$?"

  # Ignore test failures (exit code 3). For Wycheproof tests we only want to
  # ensure that tests execute properly. Test failures are generally indicative
  # of an issue with the library under test.
  #
  # See https://bazel.build/run/scripts#exit-codes
  if (( $bazel_exit_code != 0 && $bazel_exit_code != 3 )) ; then
    return "${bazel_exit_code}"
  fi
}

main() {
  if [[ -n "${KOKORO_ROOT}" ]] ; then
    # TODO(b/261682927): Uncomment once Kokoro configuration is updated.
    #cd git*/wycheproof

    use_bazel.sh "$(cat ./.bazelversion)"
  fi

  # Verify that all targets build successfully.
  bazel build ...

  # List all targets.
  bazel query ...

  # Verify that a subset of the test targets execute successfully.
  local test_targets=($(bazel query 'attr(name, "Test$", //...)'))
  run_bazel_tests "${test_targets[@]}"
}

main "$@"
