# for javascript
http_archive(
   name = "io_bazel_rules_closure",
   sha256 = "e9e2538b1f7f27de73fa2914b7d2cb1ce2ac01d1abe8390cfe51fb2558ef8b27",
   strip_prefix = "rules_closure-4c559574447f90751f05155faba4f3344668f666",
   urls = [
       "http://mirror.bazel.build/github.com/bazelbuild/rules_closure/archive/4c559574447f90751f05155faba4f3344668f666.tar.gz",
       "https://github.com/bazelbuild/rules_closure/archive/4c559574447f90751f05155faba4f3344668f666.tar.gz",  # 2017-06-21
   ],
)

load("@io_bazel_rules_closure//closure:defs.bzl", "closure_repositories")

closure_repositories()

# Google End-to-end
new_http_archive(
    name = "e2e",
    strip_prefix = "end-to-end-a77a8cbd13157139437219a8c87a7e133457c2e7",
    sha256 = "1c0d3678a649c75254e035985a209b9e292befdec733af0a4ad3842acef271eb",
    url = "https://github.com/google/end-to-end/archive/a77a8cbd13157139437219a8c87a7e133457c2e7.zip",
    build_file = "//:E2E.BUILD"
)

# Google GSON
new_http_archive(
    name = "gson",
    strip_prefix = "gson-gson-parent-2.8.1",
    sha256 = "5b64446a14ee5b29ab62f1bc0341631c20073e141b724afc410aa66dff6d7f2e",
    url = "https://github.com/google/gson/archive/gson-parent-2.8.1.tar.gz",
    build_file = "//:Gson.BUILD"
)

maven_jar(
    name = "bouncycastle_1_46",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.46",
)

maven_jar(
    name = "bouncycastle_1_47",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.47",
)

maven_jar(
    name = "bouncycastle_1_48",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.48",
)

maven_jar(
    name = "bouncycastle_1_49",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.49",
)

maven_jar(
    name = "bouncycastle_1_50",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.50",
)

maven_jar(
    name = "bouncycastle_1_51",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.51",
)

maven_jar(
    name = "bouncycastle_1_52",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.52",
)

maven_jar(
    name = "bouncycastle_1_53",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.53",
)

maven_jar(
    name = "bouncycastle_1_54",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.54",
)

maven_jar(
    name = "bouncycastle_1_55",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.55",
)

maven_jar(
    name = "bouncycastle_1_56",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.56",
)

maven_jar(
    name = "bouncycastle_1_57",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.57",
)

maven_jar(
    name = "bouncycastle_1_58",
    artifact = "org.bouncycastle:bcprov-jdk15on:1.58",
)

maven_jar(
    name = "spongycastle_core_1_50",
    artifact = "com.madgag.spongycastle:core:1.50.0.0",
)

maven_jar(
    name = "spongycastle_prov_1_50",
    artifact = "com.madgag.spongycastle:prov:1.50.0.0",
)

maven_jar(
    name = "spongycastle_core_1_51",
    artifact = "com.madgag.spongycastle:core:1.51.0.0",
)

maven_jar(
    name = "spongycastle_prov_1_51",
    artifact = "com.madgag.spongycastle:prov:1.51.0.0",
)

maven_jar(
    name = "spongycastle_core_1_52",
    artifact = "com.madgag.spongycastle:core:1.52.0.0",
)

maven_jar(
    name = "spongycastle_prov_1_52",
    artifact = "com.madgag.spongycastle:prov:1.52.0.0",
)

maven_jar(
    name = "spongycastle_core_1_53",
    artifact = "com.madgag.spongycastle:core:1.53.0.0",
)

maven_jar(
    name = "spongycastle_prov_1_53",
    artifact = "com.madgag.spongycastle:prov:1.53.0.0",
)

maven_jar(
    name = "spongycastle_core_1_54",
    artifact = "com.madgag.spongycastle:core:1.54.0.0",
)

maven_jar(
    name = "spongycastle_prov_1_54",
    artifact = "com.madgag.spongycastle:prov:1.54.0.0",
)

load(":local_repository_defs.bzl", "local_jars")

local_jars(name = "local")
