# Background

libultrahdr is an image compression library that uses gain map technology
to store and distribute HDR images. Conceptually on the encoding side, the
library accepts SDR and HDR rendition of an image and from these a Gain Map
(quotient between the two renditions) is computed. The library then uses
backward compatible means to store the base image (SDR), gain map image and
some associated metadata. Legacy readers that do not support handling the
gain map image and/or metadata, will display the base image. Readers that
support the format combine the base image with the gain map and render a
high dynamic range image on compatible displays.

For additional information about libultrahdr, see android hdr-image-format
[guide](https://developer.android.com/guide/topics/media/platform/hdr-image-format).


## Building libultrahdr

### Requirements

- [CMake](http://www.cmake.org) v3.13 or later
- C++ compiler, supporting at least C++17.
- libultrahdr uses jpeg compression format to store sdr image and gainmap quotient.
  So, libjpeg or any other jpeg codec that is ABI and API compatible with libjpeg.

The library offers a way to skip installing libjpeg by passing `UHDR_BUILD_DEPS=1`
at the time of configure. That is, `cmake -DUHDR_BUILD_DEPS=1` will clone jpeg codec
from [link](https://github.com/libjpeg-turbo/libjpeg-turbo.git) and include it in
the build process. This is however not recommended.

If jpeg is included in the build process then to build jpeg with simd extensions,
- C compiler
- [NASM](http://www.nasm.us) or [Yasm](http://yasm.tortall.net) are needed.
  * If using NASM, 2.13 or later is required.
  * If using Yasm, 1.2.0 or later is required.

### Build Procedure

To build libultrahdr, examples, unit tests:

### Un*x (including Linux, Mac)

    mkdir build_directory
    cd build_directory
    cmake -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
    make
    ctest
    make install

This will generate the following files under `build_directory`:

**libuhdr.so or libuhdr.dylib**<br> ultrahdr shared library

**libuhdr.pc**<br> ultrahdr pkg-config file

**ultrahdr_app**<br> Statically linked sample application demonstrating ultrahdr API usage

**ultrahdr_unit_test**<br> Unit tests

`make install` will install libuhdr.so, ultrahdr_api.h, libuhdr.pc for system-wide usage and
`make uninstall` will remove the same.

### MinGW

NOTE: This assumes that you are building on a Windows machine using the MSYS
environment.

    mkdir build_directory
    cd build_directory
    cmake -G "MSYS Makefiles" -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

    mkdir build_directory
    cd build_directory
    cmake -G "MinGW Makefiles" -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

This will generate the following files under `build_directory`:

**libuhdr.dll**<br> ultrahdr shared library

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests

### Visual C++ (IDE)

    mkdir build_directory
    cd build_directory
    cmake -G "Visual Studio 16 2019" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./ --config=Release
    ctest -C Release

This will generate the following files under `build_directory/Release`:

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests

### Visual C++ (Command line)

    mkdir build_directory
    cd build_directory
    cmake -G "NMake Makefiles" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

This will generate the following files under `build_directory`:

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests


NOTE: To not build unit tests, skip passing `-DUHDR_BUILD_TESTS=1`

### Building Benchmark

To build benchmarks, pass `-DUHDR_BUILD_BENCHMARK=1` to cmake configure command and build.

This will additionally generate,

**ultrahdr_bm**<br> Benchmark tests


### Building Fuzzers

Refer to [README.md](fuzzer/README.md) for complete instructions.

## Using libultrahdr

A detailed description of libultrahdr encode and decode api is included in [ultrahdr_api.h](ultrahdr_api.h)
and for sample usage refer [demo app](examples/ultrahdr_app.cpp).

libultrahdr includes two classes of APIs, one to compress and the other to decompress HDR images:

### Encoding api outline:

| Scenario  | Hdr intent raw | Sdr intent raw | Sdr intent compressed | Gain map compressed | Quality |   Exif   | Use Case |
|:---------:| :----------: | :----------: | :---------------------: | :-------------------: | :-------: | :---------: | :-------- |
| API - 0 | P010 |    No   |  No  |  No  | Optional| Optional | Used if, only hdr raw intent is present. [^1] |
| API - 1 | P010 | YUV420  |  No  |  No  | Optional| Optional | Used if, hdr raw and sdr raw intents are present.[^2] |
| API - 2 | P010 | YUV420  | Yes  |  No  |    No   |    No    | Used if, hdr raw, sdr raw and sdr compressed intents are present.[^3] |
| API - 3 | P010 |    No   | Yes  |  No  |    No   |    No    | Used if, hdr raw and sdr compressed intents are present.[^4] |
| API - 4 |  No  |    No   | Yes  | Yes  |    No   |    No    | Used if, sdr compressed, gain map compressed and GainMap Metadata are present.[^5] |

[^1]: Tonemap hdr to sdr. Compute gain map from hdr and sdr. Compress sdr and gainmap at quality configured. Add exif if provided. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^2]: Compute gain map from hdr and sdr. Compress sdr and gainmap at quality configured. Add exif if provided. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^3]: Compute gain map from hdr and raw sdr. Compress gainmap. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^4]: Decode compressed sdr input. Compute gain map from hdr and decoded sdr. Compress gainmap. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
[^5]: Combine sdr compressed, gainmap in multi picture format with gainmap metadata.

### Decoding api outline:

Configure display device characteristics (display transfer characteristics, max display boost) for optimal usage.

| Input  | Usage |
| ------------- | ------------- |
| max_display_boost  | (optional, >= 1.0) the maximum available boost supported by a display. |
| supported color transfer format pairs  | <table><thead><tr><th>color transfer</th><th>Color format </th></tr></thead><tbody><tr><td>SDR</td><td>32bppRGBA8888</td></tr><tr><td>HDR_LINEAR</td><td>64bppRGBAHalfFloat</td></tr><tr><td>HDR_PQ</td><td>32bppRGBA1010102 PQ</td></tr><tr><td>HDR_HLG</td><td>32bppRGBA1010102 HLG</td></tr></tbody></table> |
