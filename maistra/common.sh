#!/bin/bash

set -e
set -o pipefail
set -x

export CC=clang CXX=clang++

ARCH=$(uname -p)
if [ "${ARCH}" = "ppc64le" ]; then
  ARCH="ppc"
fi
export ARCH

COMMON_FLAGS="\
    --config=${ARCH} \
    --define crypto=system \
    --linkopt=-l:libwee8.so \
    --linkopt=-l:libv8_lib.so \
    --copt=-DV8_ENABLE_WEBASSEMBLY=1 \
    --linkopt=-v \
"

if [ -n "${CI}" ]; then
  COMMON_FLAGS+=" --config=ci-config " 

  # Throttle resources to work for our CI environemt
  LOCAL_CPU_RESOURCES="${LOCAL_CPU_RESOURCES:-6}"
  LOCAL_RAM_RESOURCES="${LOCAL_RAM_RESOURCES:-12288}"
  LOCAL_JOBS="${LOCAL_JOBS:-3}"

  COMMON_FLAGS+=" --local_cpu_resources=${LOCAL_CPU_RESOURCES} "
  COMMON_FLAGS+=" --local_ram_resources=${LOCAL_RAM_RESOURCES} "
  COMMON_FLAGS+=" --jobs=${LOCAL_JOBS} "
fi

if [ -n "${BAZEL_REMOTE_CACHE}" ]; then
  COMMON_FLAGS+=" --remote_cache=${BAZEL_REMOTE_CACHE} "
elif [ -n "${BAZEL_DISK_CACHE}" ]; then
  COMMON_FLAGS+=" --disk_cache=${BAZEL_DISK_CACHE} "
fi

if [ -n "${BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER}" ]; then
  COMMON_FLAGS+=" --experimental_remote_downloader=${BAZEL_EXPERIMENTAL_REMOTE_DOWNLOADER}"
fi
