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

libultrahdr compresses an hdr and sdr rendition of an image in to jpeg format
using gain map technology and vice versa. For this libjpeg is used. If libjpeg
library is not present then cmake configuration will fail. This can be resolved
by installing libjpeg using package manager and then configuring or passing
UHDR_BUILD_DEPS=1 at the time of configure. cmake -DUHDR_BUILD_DEPS=1 will
clone jpeg from <https://github.com/libjpeg-turbo/libjpeg-turbo.git> and
include it in the build process.

Requirements
--------------

- [CMake](http://www.cmake.org) v3.13 or later

- Compiler with support for C++17

- libjpeg package or

- [NASM](http://www.nasm.us) or [Yasm](http://yasm.tortall.net)
  (If libjpeg-turbo needs to be built with SIMD extensions)
  * If using NASM, 2.13 or later is required.
  * If using Yasm, 1.2.0 or later is required.
  * If building on macOS, NASM or Yasm can be obtained from
    [MacPorts](http://www.macports.org/) or [Homebrew](http://brew.sh/).

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
    make install 

This will generate the following files under *{build_directory}*:

**libuhdr.so or libuhdr.dylib**<br> ultrahdr shared library

**libuhdr.pc**<br> ultrahdr pkg-config file

**ultrahdr_app**<br> Statically linked sample application demonstrating ultrahdr API

**ultrahdr_unit_test**<br> Unit tests

make install will install libuhdr.so, ultrahdr_api.h, libuhdr.pc for system-wide usage.
make uninstall will remove the same.

Note: You may need to run ldconfig after make install. Also, as of now, install and uninstall
targets are supported only for Un*x platforms

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

**libuhdr.dll**<br> ultrahdr shared library

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests

### Visual C++ (IDE)

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "Visual Studio 16 2019" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./ --config=Release
    ctest -C Release

This will generate the following files under *{build_directory/Release}*:

**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test.exe**<br> Unit tests

### Visual C++ (Command line)

    mkdir {build_directory}
    cd {build_directory}
    cmake -G "NMake Makefiles" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
    cmake --build ./
    ctest

This will generate the following files under *{build_directory}*:

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

A detailed description of libultrahdr encode and decode api is included in [ultrahdr_api.h](ultrahdr_api.h)
and for sample usage refer [ultrahdr_app.cpp](examples/ultrahdr_app.cpp)

