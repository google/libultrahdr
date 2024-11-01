#!/bin/bash -eu
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
