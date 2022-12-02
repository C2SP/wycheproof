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

echo "which java: $(which java)"
echo "java --version: $(java --version)"

# Verify that all targets build successfully.
bazel build ...
