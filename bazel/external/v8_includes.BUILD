load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "wee8_lib_includes_lib",
    hdrs = [
        "include/v8-version.h",
        "include/v8-config.h",
    ],
    copts = ["-Wno-error=error"],
    includes = [
        "include",
        "include/cppgc",
        "src",
        "third_party",
        "third_party/wasm-api",
    ],
    visibility = ["//visibility:public"],
)

