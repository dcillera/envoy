load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "proxy_wasm_cpp_host_includes_lib",
    hdrs = [
        "include/proxy-wasm/v8.h",
    ],
    copts = ["-Wno-error=error"],
    includes = [
        "include",
        "include/proxy-wasm",
    ],
    visibility = ["//visibility:public"],
)

