#!/bin/bash -eu
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.
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
make -j$(nproc) ultrahdr_dec_fuzzer ultrahdr_enc_fuzzer ultrahdr_legacy_fuzzer ultrahdr_metadata_fuzzer ultrahdr_gainmapmath_fuzzer ultrahdr_editor_fuzzer

cp ${build_dir}/ultrahdr_dec_fuzzer $OUT/
cp ${build_dir}/ultrahdr_enc_fuzzer $OUT/
cp ${build_dir}/ultrahdr_legacy_fuzzer $OUT/
cp ${build_dir}/ultrahdr_metadata_fuzzer $OUT/
cp ${build_dir}/ultrahdr_gainmapmath_fuzzer $OUT/
cp ${build_dir}/ultrahdr_editor_fuzzer $OUT/

popd
