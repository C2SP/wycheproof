#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

if [[ -n "${KOKORO_ROOT}" ]] ; then
  # Change to the repository root.
  cd git*/wycheproof

  use_bazel.sh "$(cat .bazelversion)"
fi

# TODO(ckl): Distinguish between test failures and execution failures.

# Run all tests to generate logs.
# We don't care about the test results, thus always return successfully.
bazel query "kind(test, :all)" \
  | grep AllTests \
  | grep -v Local \
  | xargs bazel test --test_output=all \
  || exit 0
