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
For this libjpeg is used. This is cloned from
<https://github.com/libjpeg-turbo/libjpeg-turbo.git> and included in the
build process.

### Requirements

- [CMake](http://www.cmake.org) v3.5 or later

- [NASM](http://www.nasm.us) or [Yasm](http://yasm.tortall.net)
  (If libjpeg-turbo is building on x86 or x86-64 with SIMD extensions)
  * If using NASM, 2.13 or later is required.
  * If using Yasm, 1.2.0 or later is required.
  * If building on macOS, NASM or Yasm can be obtained from
    [MacPorts](http://www.macports.org/) or [Homebrew](http://brew.sh/).

Tested with GCC v11.4 and Clang 14.0.0 on Linux and Mac Platforms.

### Building Commands

To build libultrahdr and sample application:

    mkdir {build_directory}
    cd {build_directory}
    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
    make

To build unit tests:

    mkdir {build_directory}
    cd {build_directory}
    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_TESTS=1
    make
    ctest

This will generate the following files under *{build_directory}*:

**libultrahdr.a**<br> Static link library for the ultrahdr API

**ultrahdr_app**<br> Sample application demonstrating ultrahdr API

**ultrahdr_unit_test**<br> Unit tests

Using libultrahdr
===================

libultrahdr includes two classes of APIs, one to compress and the other to
decompress HDR images:

- Refer to [jpegr.h](include/ultrahdr/jpegr.h) for detailed description of various encode and decode api.
- Refer to [ultrahdr_app.cpp](tests/ultrahdr_app.cpp) for examples of its usage.
