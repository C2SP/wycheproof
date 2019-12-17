"""Add test targets for providers such as Bouncy Castle or Spongy Castle.

"""

def add_tests(name, versions, provider_dep, srcs, deps, size, test_class, data):
    """Provider version-specific tests."""

    for version in versions:
        native.java_test(
            name = name + "_" + version,
            srcs = srcs,
            deps = deps + [
                provider_dep + "_" + version,
            ],
            size = size,
            test_class = test_class,
            data = data,
        )

    # Latest stable.
    # We can't use native.alias, because aliased tests are not run.
    # So, we simply duplicate the test.
    native.java_test(
        name = name,
        srcs = srcs,
        deps = deps + [
            provider_dep + "_" + versions[-1],
        ],
        size = size,
        test_class = test_class,
        data = data,
    )

# Bouncy Castle targets

bouncycastle_versions = ["1_%d" % i for i in range(49, 60)]
bouncycastle_dep = "@bouncycastle"

# These targets run all tests.
def bouncycastle_all_tests(srcs, deps, size, test_class, data):
    """BouncyCastle version-specific tests."""

    add_tests("BouncyCastleAllTests", bouncycastle_versions, bouncycastle_dep, srcs, deps, size, test_class, data)

# These targets exclude @SlowTest
def bouncycastle_tests(srcs, deps, size, test_class, data):
    """BouncyCastle version-specific tests."""

    add_tests("BouncyCastleTest", bouncycastle_versions, bouncycastle_dep, srcs, deps, size, test_class, data)

# Spongy Castle targets
spongycastle_versions = ["1_50", "1_51", "1_52", "1_53", "1_54", "1_56", "1_58"]
spongycastle_dep = "@spongycastle_prov"

# These targets run all tests.
def spongycastle_all_tests(srcs, deps, size, test_class, data):
    """SpongyCastle version-specific tests."""

    add_tests("SpongyCastleAllTests", spongycastle_versions, spongycastle_dep, srcs, deps, size, test_class, data)

# These targets exclude slow tests.
def spongycastle_tests(srcs, deps, size, test_class, data):
    """SpongyCastle version-specific tests."""

    add_tests("SpongyCastleTest", spongycastle_versions, spongycastle_dep, srcs, deps, size, test_class, data)

# Conscrypt targets
conscrypt_versions = ["1_0_1"]
conscrypt_dep = "@conscrypt"

# These targets run all tests.
def conscrypt_all_tests(srcs, deps, size, test_class, data):
    """Conscrypt version-specific tests."""

    add_tests("ConscryptAllTests", conscrypt_versions, conscrypt_dep, srcs, deps, size, test_class, data)

# These targets exclude @SlowTest
def conscrypt_tests(srcs, deps, size, test_class, data):
    """Conscrypt version-specific tests."""

    add_tests("ConscryptTest", conscrypt_versions, conscrypt_dep, srcs, deps, size, test_class, data)

# Amazon Corretto Crypto Provider targets
accp_versions = ["1_1_0", "1_1_1", "1_2_0"]
accp_dep = "@amazon_corretto_crypto_provider"

# These targets run all tests.
def accp_all_tests(srcs, deps, size, test_class, data):
    """Amazon Corretto Crypto Provider version-specific tests."""

    add_tests("AccpAllTests", accp_versions, accp_dep, srcs, deps, size, test_class, data)

# These targets exclue @SlowTest
def accp_tests(srcs, deps, size, test_class, data):
    """Amazon Corretto Crypto Provider version-specific tests."""

    add_tests("AccpTest", accp_versions, accp_dep, srcs, deps, size, test_class, data)
