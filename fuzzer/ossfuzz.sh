#!/bin/bash -eu
#
# This project is dual-licensed under Apache 2.0 and MIT terms.
# See LICENSE-APACHE and LICENSE-MIT for details.
#
################################################################################
# Ensure SRC and WORK are set
test "${SRC}" != "" || exit 1
test "${WORK}" != "" || exit 1

# Build libultrahdr
build_dir=$WORK/build
rm -rf ${build_dir}
mkdir -p ${build_dir}
pushd ${build_dir}

cmake $SRC/libultrahdr -DUHDR_BUILD_FUZZERS=1 -DUHDR_MAX_DIMENSION=1280
make -j$(nproc) ultrahdr_dec_fuzzer ultrahdr_enc_fuzzer ultrahdr_legacy_fuzzer
cp ${build_dir}/ultrahdr_dec_fuzzer $OUT/
cp ${build_dir}/ultrahdr_enc_fuzzer $OUT/
cp ${build_dir}/ultrahdr_legacy_fuzzer $OUT/
popd
