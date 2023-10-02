# Fuzzer for ultrahdr decoder and encoder

This describes steps to build ultrahdr_dec_fuzzer and ultrahdr_enc_fuzzer.

## Linux x86/x64

###  Requirements
- cmake (3.5 or above)
- make
- clang (12.0 or above)
  needs to support -fsanitize=fuzzer, -fsanitize=fuzzer-no-link

### Steps to build
Create a directory inside libultrahdr and change directory
```
 $ cd libultrahdr
 $ mkdir build
 $ cd build
```
Build fuzzer with required sanitizers
Note: Using clang and setting -DENABLE_FUZZERS=ON is mandatory to enable fuzzers.
```
 $ cmake .. -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
   -DCMAKE_BUILD_TYPE=Debug -DENABLE_FUZZERS=ON -DSANITIZE=address,\
   signed-integer-overflow,unsigned-integer-overflow
 $ make
 ```

### Steps to run
Create a directory CORPUS_DIR and copy some elementary ultrahdr files
(for ultrahdr_dec_fuzzer) or yuv files (for ultrahdr_enc_fuzzer) to that directory

To run the fuzzers
```
$ ./ultrahdr_dec_fuzzer CORPUS_DIR
$ ./ultrahdr_enc_fuzzer CORPUS_DIR
```

## Android

### Steps to build
Build the fuzzers
```
  $ mm -j$(nproc) ultrahdr_dec_fuzzer
  $ mm -j$(nproc) ultrahdr_enc_fuzzer
```

### Steps to run
Create a directory CORPUS_DIR and copy some elementary ultrahdr files
(for ultrahdr_dec_fuzzer) or yuv files (for ultrahdr_enc_fuzzer) to that folder
Push this directory to device

To run ultrahdr_dec_fuzzer on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ultrahdr_dec_fuzzer/ultrahdr_dec_fuzzer CORPUS_DIR
```

To run ultrahdr_enc_fuzzer on device
```
  $ adb sync data
  $ adb shell /data/fuzz/arm64/ultrahdr_enc_fuzzer/ultrahdr_enc_fuzzer CORPUS_DIR
```

To run ultrahdr_dec_fuzzer on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/ultrahdr_dec_fuzzer/ultrahdr_dec_fuzzer CORPUS_DIR
```

To run ultrahdr_enc_fuzzer on host
```
  $ $ANDROID_HOST_OUT/fuzz/x86_64/ultrahdr_enc_fuzzer/ultrahdr_enc_fuzzer CORPUS_DIR
```
