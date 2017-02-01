# Wycheproof tests

java_library(
    name = "utils",
    srcs = [
        "java/com/google/security/wycheproof/EcUtil.java",
        "java/com/google/security/wycheproof/RandomUtil.java",
        "java/com/google/security/wycheproof/TestUtil.java",
    ],
)

common_deps = [
    ":utils",
]

test_srcs = glob(["java/com/google/security/wycheproof/testcases/*.java"]) + ["java/com/google/security/wycheproof/WycheproofRunner.java"]

# These targets run all tests.

load(":build_defs.bzl", "bouncycastle_all_tests", "spongycastle_all_tests")

# Generates BouncyCastleAllTests_1_xx target for all available versions,
# plus a BouncyCastleAllTests alias for latest stable.
#
# To test latest stable:
# $ bazel test BouncyCastleAllTests
#
# To test other versions, e.g., v1.52:
# $ bazel test BouncyCastleAllTests_1_52
#
# To test all known versions (warning, will take a long time):
# $ bazel test BouncyCastleAllTest_*
bouncycastle_all_tests(
    # This test takes a long time, because key generation for DSA and DH generate new parameters.
    size = "large",
    srcs = ["java/com/google/security/wycheproof/BouncyCastleAllTests.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.BouncyCastleAllTests",
    deps = common_deps,
)

java_test(
    name = "BouncyCastleAllTestsLocal",
    # this target requires specifing a shell variable, thus won't work with the wildcard target patterns.
    # with tags=["manual"] it'll be excluded from said patterns.
    tags = ["manual"],
    size = "large",
    srcs = ["java/com/google/security/wycheproof/BouncyCastleAllTests.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.BouncyCastleAllTests",
    deps = common_deps + ["@local//:bouncycastle_jar"],
)

# Generates SpongyCastleAllTests_1_xx target for all available versions,
# plus a SpongyCastleAllTests alias for latest stable.
#
# To test latest stable:
# $ bazel test SpongyCastleAllTests
#
# To test other versions, e.g., v1.52.0.0:
# $ bazel test SpongyCastleAllTests_1_52
#
# To test all known versions (warning, will take a long time):
# $ bazel test SpongyCastleAllTests_*
spongycastle_all_tests(
    # This test takes a long time, because key generation for DSA and DH generate new parameters.
    size = "large",
    srcs = ["java/com/google/security/wycheproof/SpongyCastleAllTests.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.SpongyCastleAllTests",
    deps = common_deps,
)

# These targets exclude slow tests.

load(":build_defs.bzl", "bouncycastle_tests", "spongycastle_tests")

# Generates BouncyCastleTest_1_xx target for all available versions,
# plus a BouncyCastleTest alias for latest stable.
#
# To test latest stable:
# $ bazel test BouncyCastleTest
#
# To test other versions, e.g., v1.52:
# $ bazel test BouncyCastleTest_1_52
#
# To test all known versions:
# $ bazel test BouncyCastleTest_*
bouncycastle_tests(
    size = "large",
    srcs = ["java/com/google/security/wycheproof/BouncyCastleTest.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.BouncyCastleTest",
    deps = common_deps,
)

java_test(
    name = "BouncyCastleTestLocal",
    # this target requires specifing a shell variable, thus won't work with the wildcard target patterns.
    # with tags=["manual"] it'll be excluded from said patterns.
    tags = ["manual"],
    size = "large",
    srcs = ["java/com/google/security/wycheproof/BouncyCastleTest.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.BouncyCastleTest",
    deps = common_deps + ["@local//:bouncycastle_jar"],
)

# Generates SpongyCastleTest_1_xx target for all available versions,
# plus a SpongyCastleTest alias for latest stable.
#
# To test latest stable:
# $ bazel test SpongyCastleTest
#
# To test other versions, e.g., v1.52.0.0:
# $ bazel test SpongyCastleTest_1_52
#
# To test all known versions:
# $ bazel test SpongyCastleTest_*
spongycastle_tests(
    size = "large",
    srcs = ["java/com/google/security/wycheproof/SpongyCastleTest.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.SpongyCastleTest",
    deps = common_deps,
)

# OpenJDK tests
java_test(
    name = "OpenJDKTest",
    size = "large",
    srcs = ["java/com/google/security/wycheproof/OpenJDKTest.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.OpenJDKTest",
    deps = common_deps,
)

java_test(
    name = "OpenJDKAllTests",
    size = "large",
    srcs = ["java/com/google/security/wycheproof/OpenJDKAllTests.java"] + test_srcs,
    test_class = "com.google.security.wycheproof.OpenJDKAllTests",
    deps = common_deps,
)

# Platform-independent tests
java_test(
    name = "ProviderIndependentTest",
    size = "small",
    srcs = ["java/com/google/security/wycheproof/ProviderIndependentTest.java"] + test_srcs,
    deps = common_deps,
)
