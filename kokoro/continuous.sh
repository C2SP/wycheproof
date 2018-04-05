#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

# Change to repo root
cd git*/wycheproof

# Building should work.
bazel build ... || exit 1

# Run all tests to generate logs.
# We don't care about the test results, thus always return successfully.
bazel query "kind(test, :all)" | grep AllTests | grep -v Local | xargs bazel \
    --host_javabase="$JAVA_HOME" test --test_output=all || exit 0

