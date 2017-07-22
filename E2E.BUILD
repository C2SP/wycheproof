load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_test")
load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_library")
load("@io_bazel_rules_closure//closure:defs.bzl", "closure_js_deps")

closure_js_library(
    name = "E2E",
    visibility = ["//visibility:public"],
    srcs = glob(
        ["src/**/*.js"],
        exclude = [
            "src/**/*test.js",
            "src/**/*tester.js",
            "src/**/*testdata.js",
            "src/**/testing/*.js",
            "src/**/testing.js"],
    )
)