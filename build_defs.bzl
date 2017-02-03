bouncycastle_versions = range(49, 57)

# These targets run all tests.
def bouncycastle_all_tests(srcs, deps, size, test_class):
  """BouncyCastle version-specific tests."""

  # Generates BouncyCastleAllTests_1_56, ..., BouncyCastleAllTests_1_49
  for version in bouncycastle_versions:
    native.java_test(
        name = "BouncyCastleAllTests_1_%s" % version,
        srcs = srcs,
        deps = deps + [
            "@bouncycastle_1_%s//jar" % version,
        ],
        size = size,
        test_class = test_class,
    )

  # Latest stable.
  # We can't use native.alias, because aliased tests are not run.
  # So, we simply duplicate the test.
  native.java_test(
      name = "BouncyCastleAllTests",
      srcs = srcs,
      deps = deps + ["@bouncycastle_1_%s//jar" % max(bouncycastle_versions)],
      size = size,
      test_class = test_class,
  )

# These targets exclude slow tests.
def bouncycastle_tests(srcs, deps, size, test_class):
  """BouncyCastle version-specific tests."""

  # Generates BouncyCastleTest_1_56, ..., BouncyCastleTest_1_49
  for version in bouncycastle_versions:
    native.java_test(
        name = "BouncyCastleTest_1_%s" % version,
        srcs = srcs,
        deps = deps + [
            "@bouncycastle_1_%s//jar" % version,
        ],
        size = size,
        test_class = test_class,
    )

  # Latest stable.
  # We can't use native.alias, because aliased tests are not run.
  # So, we simply duplicate the test.
  native.java_test(
      name = "BouncyCastleTest",
      srcs = srcs,
      deps = deps + ["@bouncycastle_1_%s//jar" % max(bouncycastle_versions)],
      size = size,
      test_class = test_class,
  )

spongycastle_versions = range(50, 55)

# These targets run all tests.
def spongycastle_all_tests(srcs, deps, size, test_class):
  """SpongyCastle version-specific tests."""

  # Generates SpongyCastleAllTests_1_54, ..., SpongyCastleAllTests_1_50
  for version in spongycastle_versions:
    native.java_test(
        name = "SpongyCastleAllTests_1_%s" % version,
        srcs = srcs,
        deps = deps + [
            "@spongycastle_core_1_%s//jar" % version,
            "@spongycastle_prov_1_%s//jar" % version,
        ],
        size = size,
        test_class = test_class,
    )

  # Latest stable.
  # We can't use native.alias, because aliased tests are not run.
  # So, we simply duplicate the test.
  native.java_test(
      name = "SpongyCastleAllTests",
      srcs = srcs,
      deps = deps + [
          "@spongycastle_core_1_%s//jar" % max(spongycastle_versions),
          "@spongycastle_prov_1_%s//jar" % max(spongycastle_versions),
      ],
      size = size,
      test_class = test_class,
  )

# These targets exclude slow tests.
def spongycastle_tests(srcs, deps, size, test_class):
  """SpongyCastle version-specific tests."""

  # Generates SpongyCastleTest_1_54, ..., SpongyCastleTest_1_50
  for version in spongycastle_versions:
    native.java_test(
        name = "SpongyCastleTest_1_%s" % version,
        srcs = srcs,
        deps = deps + [
            "@spongycastle_core_1_%s//jar" % version,
            "@spongycastle_prov_1_%s//jar" % version,
        ],
        size = size,
        test_class = test_class,
    )

  # Latest stable.
  # We can't use native.alias, because aliased tests are not run.
  # So, we simply duplicate the test.
  native.java_test(
      name = "SpongyCastleTest",
      srcs = srcs,
      deps = deps + [
          "@spongycastle_core_1_%s//jar" % max(spongycastle_versions),
          "@spongycastle_prov_1_%s//jar" % max(spongycastle_versions),
      ],
      size = size,
      test_class = test_class,
  )
