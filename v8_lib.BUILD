load("@rules_cc//cc:defs.bzl", "cc_library")

licenses(["notice"])  # Apache 2

# V8 library built in proxy-wasm-cpp-host
cc_library(
    name = "libv8-pwch-lib",
    srcs = [
        "libv8_lib.so",
    ],
    linkstatic = False,
    visibility = ["//visibility:public"],
)

