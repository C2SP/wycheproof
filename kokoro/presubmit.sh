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
