#!/bin/bash -eu
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.
#
################################################################################
# Ensure SRC, WORK and OUT are set
test "${SRC}" != "" || exit 1
test "${WORK}" != "" || exit 1
test "${OUT}" != "" || exit 1

build_dir="$WORK/build"
rm -rf "$build_dir"
max_dimension=1280
jobs=$(nproc)

aom_prefix=""
if [[ -d "$SRC/aom" ]]; then
  aom_build_dir="$build_dir/aom-build"
  aom_prefix="$build_dir/aom-install"
  # Use C implementations so MemorySanitizer can instrument the decoder.
  # Bound coded frame dimensions as well as the container dimensions.
  cmake -S "$SRC/aom" -B "$aom_build_dir" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$aom_prefix" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBUILD_SHARED_LIBS=OFF -DAOM_TARGET_CPU=generic -DCONFIG_PIC=1 \
    -DCONFIG_AV1_DECODER=1 -DCONFIG_AV1_ENCODER=0 -DCONFIG_SIZE_LIMIT=1 \
    -DDECODE_WIDTH_LIMIT="$max_dimension" -DDECODE_HEIGHT_LIMIT="$max_dimension" \
    -DENABLE_APPS=OFF -DENABLE_DOCS=OFF -DENABLE_EXAMPLES=OFF -DENABLE_TESTS=OFF -DENABLE_TOOLS=OFF
  cmake --build "$aom_build_dir" --parallel "$jobs"
  cmake --install "$aom_build_dir"
else
  echo "AVIF gain-map fuzz coverage requires libaom source at $SRC/aom. Skipping its seed corpus." >&2
fi

cmake -S "$SRC/libultrahdr" -B "$build_dir" \
  -DUHDR_BUILD_FUZZERS=1 -DUHDR_MAX_DIMENSION="$max_dimension" -DUHDR_BUILD_DEPS=1 \
  -DBUILD_SHARED_LIBS=OFF -DUHDR_FUZZ_AOM_PREFIX:PATH="$aom_prefix"
cmake --build "$build_dir" --parallel "$jobs" \
  --target ultrahdr_dec_fuzzer ultrahdr_enc_fuzzer ultrahdr_legacy_fuzzer
cp "$build_dir"/ultrahdr_{dec,enc,legacy}_fuzzer "$OUT/"

seed_corpus="$OUT/ultrahdr_dec_fuzzer_seed_corpus.zip"
rm -f "$seed_corpus"
if [[ -n "$aom_prefix" ]]; then
  # The synthetic seed contains a 16x16 checkerboard primary and an 8x8 gain map.
  # Its 24-byte harness trailer selects PQ output with editing effects disabled.
  zip -j -X "$seed_corpus" "$SRC/libultrahdr/fuzzer/avif_gain_map.seed"
fi
