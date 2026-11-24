load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "donation",
    srcs = [
        "donation.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//runsc/specutils",
    ],
)

go_test(
    name = "donation_test",
    size = "small",
    srcs = ["donation_test.go"],
    embed = [":donation"],
    deps = [
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
