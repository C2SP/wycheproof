"""Add test targets for using a local jar.

"""

_bouncycastle_jar_rule = """
java_import(
    name = "bouncycastle_jar",
    jars = ["bouncycastle.jar"],
    visibility = ["//visibility:public"],
 )
"""

_accp_jar_rule = """
java_import(
    name = "accp_jar",
    jars = ["accp.jar"],
    visibility = ["//visibility:public"],
 )
"""

# TODO(ekasper): implement environment invalidation once supported by bazel,
# see https://bazel.build/designs/2016/10/18/repository-invalidation.html
# Meanwhile, users have to call 'bazel clean' explicitly when the
# environment changes.
def _local_jars_impl(repository_ctx):
    contents = ""
    if "WYCHEPROOF_BOUNCYCASTLE_JAR" in repository_ctx.os.environ:
        repository_ctx.symlink(
            repository_ctx.os.environ["WYCHEPROOF_BOUNCYCASTLE_JAR"],
            "bouncycastle.jar",
        )
        contents += _bouncycastle_jar_rule

    if "WYCHEPROOF_ACCP_JAR" in repository_ctx.os.environ:
        repository_ctx.symlink(
            repository_ctx.os.environ["WYCHEPROOF_ACCP_JAR"],
            "accp.jar",
        )
        contents += _accp_jar_rule

    repository_ctx.file("BUILD", contents)

local_jars = repository_rule(
    implementation = _local_jars_impl,
    local = True,
)
