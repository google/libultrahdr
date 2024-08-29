## Building fuzzers for libultrahdr

### Requirements

- Refer [Requirements](./building.md#Requirements)

- Additionally compilers are required to support options `-fsanitize=fuzzer, -fsanitize=fuzzer-no-link`.
  For instance, `clang 12` (or later)

### Building Commands

```sh
cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1
ninja
```

This will generate the following files under `build_directory`:

**ultrahdr_enc_fuzzer** - ultrahdr encoder fuzzer <br>
**ultrahdr_dec_fuzzer** - ultrahdr decoder fuzzer <br>

Additionally, while building fuzzers, user can enable sanitizers by providing desired
sanitizer option(s) through `UHDR_SANITIZE_OPTIONS`.

To enable ASan,

```sh
cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address
ninja
```

To enable MSan,

```sh
cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=memory
ninja
```
To enable TSan,

```sh
cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=thread
ninja
```

To enable UBSan,

```sh
cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=undefined
ninja
```

UBSan can be grouped with ASan, MSan or TSan.

For example, to enable ASan and UBSan,

```sh
cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address,undefined
ninja
```

### Running

To run the fuzzer(s), first create a corpus directory that holds the initial
"seed" sample inputs. For decoder fuzzer, ultrahdr jpeg images can be used and
for encoder fuzzer, sample yuv files can be used.

Then run the fuzzers on the corpus directory.

```sh
mkdir CORPUS_DIR
cp seeds/* CORPUS_DIR
./ultrahdr_dec_fuzzer CORPUS_DIR
./ultrahdr_enc_fuzzer CORPUS_DIR
```
