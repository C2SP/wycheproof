load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Javascript

## Last update: 2019-10-18, to latest release.
http_archive(
    name = "io_bazel_rules_closure",
    sha256 = "7d206c2383811f378a5ef03f4aacbcf5f47fd8650f6abbc3fa89f3a27dd8b176",
    strip_prefix = "rules_closure-0.10.0",
    urls = [
        "https://github.com/bazelbuild/rules_closure/archive/0.10.0.tar.gz",
    ],
)

load(
    "@io_bazel_rules_closure//closure:repositories.bzl",
    "rules_closure_dependencies",
    "rules_closure_toolchains",
)

rules_closure_dependencies()

rules_closure_toolchains()

## Google End-to-end
http_archive(
    name = "google_e2e",
    strip_prefix = "end-to-end-a77a8cbd13157139437219a8c87a7e133457c2e7",
    sha256 = "1c0d3678a649c75254e035985a209b9e292befdec733af0a4ad3842acef271eb",
    url = "https://github.com/google/end-to-end/archive/a77a8cbd13157139437219a8c87a7e133457c2e7.zip",
    build_file = "//:third_party/e2e.BUILD.bazel"
)

# Java

load("@bazel_tools//tools/build_defs/repo:java.bzl", "java_import_external")

java_import_external(
    name = "com_google_code_gson",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "b7134929f7cc7c04021ec1cc27ef63ab907e410cf0588e397b8851181eb91092",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/google/code/gson/gson/2.8.2/gson-2.8.2.jar",
        "https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/gson-2.8.2.jar",
    ],
)

java_import_external(
    name = "junit",
    licenses = ["reciprocal"],  # Eclipse Public License 1.0
    jar_sha256 = "59721f0805e223d84b90677887d9ff567dc534d7c502ca903c0c2b17f05c116a",
    jar_urls = [
        "https://repo1.maven.org/maven2/junit/junit/4.12/junit-4.12.jar",
        "https://maven.ibiblio.org/maven2/junit/junit/4.12/junit-4.12.jar",
    ],
    deps = ["@org_hamcrest_core"],
)

java_import_external(
    name = "org_hamcrest_core",
    licenses = ["notice"],  # New BSD License
    jar_sha256 = "66fdef91e9739348df7a096aa384a5685f4e875584cce89386a7a47251c4d8e9",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar",
        "https://maven.ibiblio.org/maven2/org/hamcrest/hamcrest-core/1.3/hamcrest-core-1.3.jar",
    ],
)

java_import_external(
    name = "conscrypt_1_0_1",
    licenses = ["notice"],  # Apache 2
    jar_sha256 = "eb3ea7f7b955bc501ba03e1defd5132501539147d6576cc6c3be1d73c68eda08",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/conscrypt/conscrypt-openjdk-uber/1.0.1/conscrypt-openjdk-uber-1.0.1.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_46",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "a1952237d941ef0b6122ba27b0b58de602de91c714ba3ddd4eef30ba3f5a0a67",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.46/bcprov-jdk15on-1.46.jar",
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.46/bcprov-jdk15on-1.46.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_47",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "7fb12d09f041c294f08a0a51a2808438092273b51628eecaf2e0d0030b7556f5",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.47/bcprov-jdk15on-1.47.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.47/bcprov-jdk15on-1.47.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_48",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "804b7e2e3b9ac771dfd3b43de16666ac6008f8600f48f28ddc94e39a114e2288",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.48/bcprov-jdk15on-1.48.jar",
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.48/bcprov-jdk15on-1.48.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_49",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "96b4b8d46e38e5a08b5ee6eec23c5951d95bdac35c08f935e999bbbe6b15ba9d",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.49/bcprov-jdk15on-1.49.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.49/bcprov-jdk15on-1.49.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_50",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "115b14a02b91fb03cb1866d6b311d33cd5518a9d8524dd63a14f19571e420404",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.50/bcprov-jdk15on-1.50.jar",
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.50/bcprov-jdk15on-1.50.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_51",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "8748f0ec73895f7f18c1a9c13cf754fddddf0451cf472463ef02f93c3e7a7de7",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.51/bcprov-jdk15on-1.51.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.51/bcprov-jdk15on-1.51.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_52",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "0dc4d181e4d347893c2ddbd2e6cd5d7287fc651c03648fa64b2341c7366b1773",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.52/bcprov-jdk15on-1.52.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.52/bcprov-jdk15on-1.52.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_53",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "84c45d3d5552ab29381a55a419fbd093e1bd63032fb803f34816ae69fbbef2e5",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.53/bcprov-jdk15on-1.53.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.53/bcprov-jdk15on-1.53.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_54",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "d0ae14598f9c528d2ab7bb8ed00e785a5440f692712cd362d69328aba25efb57",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.54/bcprov-jdk15on-1.54.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.54/bcprov-jdk15on-1.54.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_55",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "c08450a176b55c7ef4847111550eb247e5912ad450c8c225fa2f7cab74ce608b",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.55/bcprov-jdk15on-1.55.jar",
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.55/bcprov-jdk15on-1.55.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_56",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "963e1ee14f808ffb99897d848ddcdb28fa91ddda867eb18d303e82728f878349",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.56/bcprov-jdk15on-1.56.jar",
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.56/bcprov-jdk15on-1.56.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_57",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "4c7fb5f7fb043fedc4b7e7af88871050f61af8dea7aaade87f8ebd60e509cd89",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.57/bcprov-jdk15on-1.57.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.57/bcprov-jdk15on-1.57.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_58",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "eb61ab61065ed96f9f2d5cde94d326233c09fdec9333c1185f2fa65ee88a4236",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.58/bcprov-jdk15on-1.58.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.58/bcprov-jdk15on-1.58.jar",
    ],
)

java_import_external(
    name = "bouncycastle_1_59",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "1c31e44e331d25e46d293b3e8ee2d07028a67db011e74cb2443285aed1d59c85",
    jar_urls = [
        "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.59/bcprov-jdk15on-1.59.jar",
        "https://maven.ibiblio.org/maven2/org/bouncycastle/bcprov-jdk15on/1.59/bcprov-jdk15on-1.59.jar",
    ],
)

java_import_external(
    name = "spongycastle_core_1_50",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "2fa2d95bd8908ac43c89f935e03e3be4173c388d177d96f24994efc7300ae2c8",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.50.0.0/core-1.50.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.50.0.0/core-1.50.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_50",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "b28c1da209762270e9f8b4ed1b6e37243fa722a9e4e3f3c0d0a5595dfabea18b",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.50.0.0/prov-1.50.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.50.0.0/prov-1.50.0.0.jar",
    ],
    deps = ["@spongycastle_core_1_50"],
)

java_import_external(
    name = "spongycastle_core_1_51",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "8d6240b974b0aca4d3da9c7dd44d42339d8a374358aca5fc98e50a995764511f",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.51.0.0/core-1.51.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.51.0.0/core-1.51.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_51",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "b8c3fec3a59aac1aa04ccf4dad7179351e54ef7672f53f508151b614c131398a",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.51.0.0/prov-1.51.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.51.0.0/prov-1.51.0.0.jar",
    ],
    deps = ["@spongycastle_core_1_51"],
)

java_import_external(
    name = "spongycastle_core_1_52",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "07a401edbe26e1028e2324754557b741cc57306008df7b71a9e12ec32d65be8f",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.52.0.0/core-1.52.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.52.0.0/core-1.52.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_52",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "becbb70797b0103517693d2a97ce93174cc4d1f732897ed965a24e32dd99503e",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.52.0.0/prov-1.52.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.52.0.0/prov-1.52.0.0.jar",
    ],
    deps = ["@spongycastle_core_1_52"],
)

java_import_external(
    name = "spongycastle_core_1_53",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "9b6b7ac856b91bcda2ede694eccd26cefb0bf0b09b89f13cda05b5da5ff68c6b",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.53.0.0/core-1.53.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.53.0.0/core-1.53.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_53",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "029f26cd6b67c06ffa05702d426d472c141789001bcb15b7262ed86c868e5643",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.53.0.0/prov-1.53.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.53.0.0/prov-1.53.0.0.jar",
    ],
    deps = ["@spongycastle_core_1_53"],
)

java_import_external(
    name = "spongycastle_core_1_54",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "1e7fa4b19ccccd1011364ab838d0b4702470c178bbbdd94c5c90b2d4d749ea1e",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.54.0.0/core-1.54.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.54.0.0/core-1.54.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_54",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "cf89c550fda86c0f26858c3d851ac1d2ce49cd78dd144cd86f307b7ea3e6afd7",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.54.0.0/prov-1.54.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.54.0.0/prov-1.54.0.0.jar",
    ],
    deps = ["@spongycastle_core_1_54"],
)

java_import_external(
    name = "spongycastle_core_1_56",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "5e791b0eaa9e0c4594231b44f616a52adddb7dccedeb0ad9ad74887e19499a23",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.56.0.0/core-1.56.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.56.0.0/core-1.56.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_56",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "3626ec5734619743a3b111d85a5bc5df4c5609e035f22cd3d090cbbe6e88d131",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.56.0.0/prov-1.56.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.56.0.0/prov-1.56.0.0.jar",
    ],
    deps = ["@spongycastle_core_1_56"],
)

java_import_external(
    name = "spongycastle_core_1_58",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "199617dd5698c5a9312b898c0a4cec7ce9dd8649d07f65d91629f58229d72728",
    jar_urls = [
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/core/1.58.0.0/core-1.58.0.0.jar",
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/core/1.58.0.0/core-1.58.0.0.jar",
    ],
)

java_import_external(
    name = "spongycastle_prov_1_58",
    # Bouncy Castle Licence
    # https://www.bouncycastle.org/licence.html
    licenses = ["notice"], # MIT license
    jar_sha256 = "092fd09e7006b0814980513b013d4c2b3ffd24a49a635ab4b2d204bb51af1727",
    jar_urls = [
        "https://repo1.maven.org/maven2/com/madgag/spongycastle/prov/1.58.0.0/prov-1.58.0.0.jar",
        "https://maven.ibiblio.org/maven2/com/madgag/spongycastle/prov/1.58.0.0/prov-1.58.0.0.jar",
    ],
    deps = [
        "@spongycastle_core_1_58",
        "@junit",
    ],
)

java_import_external(
    name = "amazon_corretto_crypto_provider_1_1_0",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "8fab9866f88c05b917184ed2fc977409eab8ab48c2dddbefa80364998b913bd3",
    jar_urls = [
        "https://repo1.maven.org/maven2/software/amazon/cryptools/AmazonCorrettoCryptoProvider/1.1.0/AmazonCorrettoCryptoProvider-1.1.0-linux-x86_64.jar",
        ],
)

java_import_external(
    name = "amazon_corretto_crypto_provider_1_1_1",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "187c45b54ae8dc968239125aad503543d6cd8963bf35a02a0ae7f30d2101af11",
    jar_urls = [
        "https://repo1.maven.org/maven2/software/amazon/cryptools/AmazonCorrettoCryptoProvider/1.1.1/AmazonCorrettoCryptoProvider-1.1.1-linux-x86_64.jar",
        ],
)

java_import_external(
    name = "amazon_corretto_crypto_provider_1_2_0",
    licenses = ["notice"],  # Apache 2.0
    jar_sha256 = "dbeece4e113d58d03e9450763032ba8326c0580f6c143a26519ed6b86fb2880e",
    jar_urls = [
        "https://repo1.maven.org/maven2/software/amazon/cryptools/AmazonCorrettoCryptoProvider/1.2.0/AmazonCorrettoCryptoProvider-1.2.0-linux-x86_64.jar",
        ],
)

load("//tools:local_repository_defs.bzl", "local_jars")

local_jars(name = "local")
