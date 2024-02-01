#!/bin/bash

set -e
set -o pipefail
set -x

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "$DIR/common.sh"

export BUILD_SCM_REVISION="Maistra PR #${PULL_NUMBER:-undefined}"
export BUILD_SCM_STATUS="SHA=${PULL_PULL_SHA:-undefined}"

#   --override_repository=com_github_google_jwt_verify=/work/jwt_verify_lib \
# Build
time bazel --output_base=/bazel-cache/BASE build \
  --disk_cache=/bazel-cache \
  ${COMMON_FLAGS} \
  --@envoy//bazel:http3=False \
  //source/exe:envoy-static

echo "Build succeeded. Binary generated:"
bazel-bin/source/exe/envoy-static --version

# By default, `bazel test` command performs simultaneous
# build and test activity.
# The following build step helps reduce resources usage
# by compiling tests first.
# Build tests
#  --cxxopt -g \
#   --copt -g \
#   -c dbg \
time bazel --output_base=/bazel-cache/BASE build \
  --disk_cache=/bazel-cache \
  ${COMMON_FLAGS} \
  --cxxopt -g \
  --copt -g \
  -c dbg \
  --@envoy//bazel:http3=False \
  --build_tests_only \
   --test_keep_going \
  -- \
  //test/extensions/transport_sockets/tls:ssl_socket_test  \
  //test/extensions/filters/listener/original_dst:original_dst_integration_test \
  //test/extensions/transport_sockets/tls/cert_validator:cert_validator_integration_test \
  //test/integration:sds_dynamic_integration_test \
  -//test/extensions/listener_managers/listener_manager:listener_manager_impl_quic_only_test
#  //test/extensions/transport_sockets/tls:ssl_socket_test  \
#   //test/extensions/filters/listener/original_dst:original_dst_integration_test \
#   //test/extensions/transport_sockets/tls/cert_validator:cert_validator_integration_test \
#   //test/integration:sds_dynamic_integration_test \
# //test/... \

# Run tests
time bazel --output_base=/bazel-cache/BASE test \
  --disk_cache=/bazel-cache \
  ${COMMON_FLAGS} \
   --cxxopt -g \
  --copt -g \
  -c dbg \
  --@envoy//bazel:http3=False \
  --build_tests_only \
  --nocache_test_results \
  --test_keep_going \
  -- \
  //test/extensions/transport_sockets/tls:ssl_socket_test  \
  //test/extensions/filters/listener/original_dst:original_dst_integration_test \
  //test/extensions/transport_sockets/tls/cert_validator:cert_validator_integration_test \
  //test/integration:sds_dynamic_integration_test \
  -//test/extensions/listener_managers/listener_manager:listener_manager_impl_quic_only_test
#  //test/extensions/transport_sockets/tls:ssl_socket_test  \
#   //test/extensions/filters/listener/original_dst:original_dst_integration_test \
#   //test/extensions/transport_sockets/tls/cert_validator:cert_validator_integration_test \
#   //test/integration:sds_dynamic_integration_test \
#   //test/... \
# --override_repository=com_github_google_jwt_verify=/work/jwt_verify_lib \