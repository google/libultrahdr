Building fuzzers for libultrahdr
================================

### Requirements

- Refer [Requirements](../README.md#Requirements)

- Additionally compilers are required to support options *-fsanitize=fuzzer, -fsanitize=fuzzer-no-link*.
  For instance, clang 12 (or later)

### Building Commands

    mkdir {build_directory}
    cd {build_directory}
    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1
    make

This will generate the following files under *{build_directory}*:

**libultrahdr.a**<br> Instrumented ultrahdr library

**ultrahdr_enc_fuzzer**<br> ultrahdr encoder fuzzer

**ultrahdr_dec_fuzzer**<br> ultrahdr decoder fuzzer

Additionally, while building fuzzers, user can enable sanitizers by providing desired
sanitizer option(s) through UHDR_SANITIZE_OPTIONS.

To enable ASan,

    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address
    make

To enable MSan,

    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=memory
    make

To enable TSan,

    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=thread
    make

To enable UBSan,

    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=undefined
    make

UBSan can be grouped with ASan, MSan or TSan.

For example, to enable ASan and UBSan,

    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address,undefined
    make

### Running

To run the fuzzer(s), first create a corpus directory that holds the initial
"seed" sample inputs. For decoder fuzzer, ultrahdr jpeg images can be used and
for encoder fuzzer, sample yuv files can be used.

Then run the fuzzers on the corpus directory.

    mkdir CORPUS_DIR
    cp seeds/* CORPUS_DIR
    ./ultrahdr_dec_fuzzer CORPUS_DIR
    ./ultrahdr_enc_fuzzer CORPUS_DIR
