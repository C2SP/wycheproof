#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

if [[ -n "${KOKORO_ROOT}" ]] ; then
  use_bazel.sh "4.1.0"
fi

# Change to the repository root.
cd git*/wycheproof

# Verify that all targets build successfully.
bazel build ...

# Run all tests to generate logs.
# We don't care about the test results, thus always return successfully.
bazel query "kind(test, :all)" \
  | grep AllTests \
  | grep -v Local \
  | xargs bazel --host_javabase="${JAVA_HOME}" test --test_output=all \
  || exit 0
