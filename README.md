Background
==========

libultrahdr is an image compression library that uses gain map technology
to store and distribute HDR images. Conceptually on the encoding side, the
library accepts SDR and HDR rendition of an image and from these a Gain Map
(quotient between the two renditions) is computed. The library then uses
backward compatible means to store the base image (SDR), gain map image and
some associated metadata. Legacy readers that do not support parsing the
gain map image and/or metadata, will display the base image. Readers that
support the format combine the base image with the gain map and render a
high dynamic range image on compatible displays.

More information about libultrahdr can be found at
<https://developer.android.com/guide/topics/media/platform/hdr-image-format>.


Building libultrahdr
======================

libultrahdr compresses base image and gain map image in to jpeg format.
For this libjpeg-turbo is used. This is cloned from
<https://github.com/libjpeg-turbo/libjpeg-turbo.git> and included in the
build process.

Requirements
--------------

- [CMake](http://www.cmake.org) v3.13 or later

- [NASM](http://www.nasm.us) or [Yasm](http://yasm.tortall.net)
  (If libjpeg-turbo needs to be built with SIMD extensions)
  * If using NASM, 2.13 or later is required.
  * If using Yasm, 1.2.0 or later is required.
  * If building on macOS, NASM or Yasm can be obtained from
    [MacPorts](http://www.macports.org/) or [Homebrew](http://brew.sh/).

- Compilers with support for C++17

Should work with GCC v7 (or later) and Clang 5 (or later) on Linux and Mac Platforms.

Should work with Microsoft Visual C++ 2019 (or later) on Windows Platforms.

Build Procedure
---------------

To build libultrahdr, examples, unit tests:

### Un*x (including Linux, Mac)

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "Unix Makefiles"  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
    make
    ctest

This will generate the following files under *{build_directory}*:

**libultrahdr.a**<br> Static link library for the ultrahdr API

**ultrahdr_app**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test**<br> Unit tests

### Visual C++ (IDE)

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "Visual Studio 16 2019" -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./ --config=Release
    ctest -C Release

This will generate the following files under *{build_directory/Release}*:

**ultrahdr.lib**<br> Static link library for the ultrahdr API

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests

### Visual C++ (Command line)

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "NMake Makefiles" -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

This will generate the following files under *{build_directory}*:

**ultrahdr.lib**<br> Static link library for the ultrahdr API

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests

### MinGW

NOTE: This assumes that you are building on a Windows machine using the MSYS
environment.

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "MSYS Makefiles" -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "MinGW Makefiles" -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

This will generate the following files under *{build_directory}*:

**libultrahdr.a**<br> Static link library for the ultrahdr API

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests


NOTE: To not build unit tests, skip passing -DUHDR_BUILD_TESTS=1

### Building Benchmark

To build benchmarks, pass -DUHDR_BUILD_BENCHMARK=1 to cmake configure command and build.

This will additionally generate,

**ultrahdr_bm**<br> Benchmark tests


### Building Fuzzers

Refer to [README.md](fuzzer/README.md) for complete instructions.

Using libultrahdr
===================

libultrahdr includes two classes of APIs, one to compress and the other to
decompress HDR images:

List of encode APIs:
| Input  | HDR YUV | SDR YUV | JPEG | Encoded gainmap | Quality (0 ~ 100) | EXIF | Use case |
| ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- |
| API-0  | P010  | No | No | No | Required | Optional | Experimental only. |
| API-1  | P010  | YUV_420 | No | No | Required | Optional | Raw SDR input. Primary image will be encoded from the raw SDR input in the library. |
| API-2  | P010  | YUV_420 | Yes | No | No | No | Both JPEG and raw SDR inputs. Gainmap will be calculated from raw HDR and raw SDR inputs, the JPEG input will be preserved (including metadata) as the primary image. |
| API-3  | P010  | No | Yes | No | No | No | SDR JPEG input. Gainmap will be calculated from raw HDR and the decoding result of the JPEG input, the JPEG input will be preserved (including metadata) as the primary image.  |
| API-4  | No  | No | Yes | Yes | No | No | SDR JPEG and gainmap inputs. The library will only generate the Ultra HDR related metadata and write everything into the Ultra HDR format, all other metadata from the JPEG input will be preserved. |

List of decode API:
| Input  | Usage |
| ------------- | ------------- |
| compressed_jpegr_image  | The input data. Pointer to JPEG/R stream. |
| dest  | The output data. Destination that decoded data to be written. |
| max_display_boost  | (optional, >= 1.0) the maximum available boost supported by a display. |
| exif  | (optional, default to NULL) Destination that exif data to be written. |
| recovery_map  | (optional, default to NULL) Destination that decoded recovery map data to be written. |
| output_format  | <table><thead><tr><th>Value</th><th>Color format to be written</th></tr></thead><tbody><tr><td>SDR</td><td>RGBA_8888</td></tr><tr><td>HDR_LINEAR</td><td>(default) RGBA_F16 linear</td></tr><tr><td>HDR_PQ</td><td>RGBA_1010102 PQ</td></tr><tr><td>HDR_HLG</td><td>RGBA_1010102 HLG</td></tr></tbody></table> |
| metadata  | (optional, default to NULL) Destination of metadata (recovery map version, min/max content boost). |

For more info:
- Refer to [jpegr.h](lib/include/ultrahdr/jpegr.h) for detailed description of various encode and decode api.
- Refer to [ultrahdr_app.cpp](examples/ultrahdr_app.cpp) for examples of its usage.
