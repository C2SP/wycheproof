"""Add test targets for providers such as Bouncy Castle or Spongy Castle.

"""

def add_tests(name, versions, provider_dep, srcs, deps, size, test_class):
  """Provider version-specific tests."""

  for version in versions:
    native.java_test(
        name = name + "_" + version,
        srcs = srcs,
        deps = deps + [
            provider_dep + "_" + version
        ],
        size = size,
        test_class = test_class,
    )

  # Latest stable.
  # We can't use native.alias, because aliased tests are not run.
  # So, we simply duplicate the test.
  native.java_test(
      name = name,
      srcs = srcs,
      deps = deps + [
          provider_dep + "_" + versions[-1]
      ],
      size = size,
      test_class = test_class,
  )

# Bouncy Castle targets

bouncycastle_versions = ["1_%d" % i for i in range(49, 60)]
bouncycastle_dep = "@bouncycastle"

# These targets run all tests.
def bouncycastle_all_tests(srcs, deps, size, test_class):
  """BouncyCastle version-specific tests."""

  add_tests("BouncyCastleAllTests", bouncycastle_versions, bouncycastle_dep, srcs, deps, size, test_class)

# These targets exclude @SlowTest
def bouncycastle_tests(srcs, deps, size, test_class):
  """BouncyCastle version-specific tests."""

  add_tests("BouncyCastleTest", bouncycastle_versions, bouncycastle_dep, srcs, deps, size, test_class)

# Spongy Castle targets
spongycastle_versions = ["1_50", "1_51", "1_52", "1_53", "1_54", "1_56", "1_58"]
spongycastle_dep = "@spongycastle_prov"

# These targets run all tests.
def spongycastle_all_tests(srcs, deps, size, test_class):
  """SpongyCastle version-specific tests."""

  add_tests("SpongyCastleAllTests", spongycastle_versions, spongycastle_dep, srcs, deps, size, test_class)


# These targets exclude slow tests.
def spongycastle_tests(srcs, deps, size, test_class):
  """SpongyCastle version-specific tests."""

  add_tests("SpongyCastleTest", spongycastle_versions, spongycastle_dep, srcs, deps, size, test_class)

# Conscrypt targets
conscrypt_versions = ["1_0_1"]
conscrypt_dep = "@conscrypt"

# These targets run all tests.
def conscrypt_all_tests(srcs, deps, size, test_class):
  """Conscrypt version-specific tests."""

  add_tests("ConscryptAllTests", conscrypt_versions, conscrypt_dep, srcs, deps, size, test_class)

# These targets exclude @SlowTest
def conscrypt_tests(srcs, deps, size, test_class):
  """Conscrypt version-specific tests."""

  add_tests("ConscryptTest", conscrypt_versions, conscrypt_dep, srcs, deps, size, test_class)
