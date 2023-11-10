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
    cmake --build ./ --config=Release
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

### Building Fuzzers

Refer to [README.md](fuzzer/README.md) for complete instructions.

Using libultrahdr
===================

libultrahdr includes two classes of APIs, one to compress and the other to
decompress HDR images:

- Refer to [jpegr.h](lib/jpegr.h) for detailed description of various encode and decode api.
- Refer to [ultrahdr_app.cpp](examples/ultrahdr_app.cpp) for examples of its usage.
