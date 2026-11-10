load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "passt_test",
    size = "medium",
    srcs = ["passt_test.go"],
    data = [
        "//:release",
    ],
    deps = [
        "//pkg/test/testutil",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
