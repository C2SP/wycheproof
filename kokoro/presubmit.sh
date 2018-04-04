#!/bin/bash

# Fail on any error.
set -e

# Display commands to stderr.
set -x

# Change to repo root
cd git*/wycheproof

# Building should work.
bazel build ... || exit 1
