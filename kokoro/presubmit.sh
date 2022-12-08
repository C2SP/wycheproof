#!/bin/bash

# TODO(b/261682927): Delete once Kokoro configuration is updated.

# Fail on any error.
set -e

# Display commands to stderr.
set -x

if [[ -n "${KOKORO_ROOT}" ]] ; then
  cd git*/wycheproof
fi

./kokoro/run_continuous_tests.sh
