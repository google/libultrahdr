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

# Build static, instrumented libaom (av1 decode + encode) and install
# system-wide so libheif's FindAOM picks it up; runtime images ship no codec
# shared libraries, so the codecs must be compiled into the fuzz targets.
aom_build=$WORK/aom-build
rm -rf ${aom_build}
cmake -S $SRC/aom -B ${aom_build} -DCMAKE_BUILD_TYPE= \
    -DCMAKE_C_FLAGS="$CFLAGS" -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DBUILD_SHARED_LIBS=OFF -DENABLE_DOCS=OFF -DENABLE_EXAMPLES=OFF \
    -DENABLE_TESTS=OFF -DENABLE_TOOLS=OFF
cmake --build ${aom_build} -j$(nproc)
cmake --install ${aom_build}

# Build libultrahdr
build_dir=$WORK/build
rm -rf ${build_dir}
mkdir -p ${build_dir}
pushd ${build_dir}

cmake $SRC/libultrahdr -DUHDR_BUILD_FUZZERS=1 -DUHDR_MAX_DIMENSION=1280 -DUHDR_BUILD_DEPS=1 -DBUILD_SHARED_LIBS=OFF
make -j$(nproc) ultrahdr_dec_fuzzer ultrahdr_enc_fuzzer ultrahdr_legacy_fuzzer ultrahdr_container_fuzzer
cp ${build_dir}/ultrahdr_dec_fuzzer $OUT/
cp ${build_dir}/ultrahdr_enc_fuzzer $OUT/
cp ${build_dir}/ultrahdr_legacy_fuzzer $OUT/
cp ${build_dir}/ultrahdr_container_fuzzer $OUT/

# structured seed corpus + dictionary for the container fuzzer
python3 $SRC/libultrahdr/fuzzer/generate_container_seeds.py $OUT/ultrahdr_container_fuzzer_seed_corpus_dir
zip -r $OUT/ultrahdr_container_fuzzer_seed_corpus.zip $OUT/ultrahdr_container_fuzzer_seed_corpus_dir > /dev/null
cp $SRC/libultrahdr/fuzzer/ultrahdr_container_fuzzer.dict $OUT/
popd
