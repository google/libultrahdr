## libultrahdr CMake Build Instructions

[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_linux.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_linux.yml?query=event%3Apush)
[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_mac.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_mac.yml?query=event%3Apush)
[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_win.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_win.yml?query=event%3Apush)
[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_android.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_android.yml?query=event%3Apush)
[![Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libultrahdr.svg)](https://introspector.oss-fuzz.com/project-profile?project=libultrahdr)

### Requirements

- [CMake](http://www.cmake.org) v3.15 or later
- C++ compiler, supporting at least C++17.
- libultrahdr uses JPEG compression format to store SDR images and gainmap quotients.
  So, libjpeg or any other JPEG codec that is ABI and API compatible with libjpeg is required for JPEG support.
- libultrahdr supports ISO 21496-1 gain map encoding and decoding in HEIF and AVIF containers via [libheif](https://github.com/strukturag/libheif).

The library offers a way to skip installing dependencies manually by passing `UHDR_BUILD_DEPS=1`
at configure time. That is, `cmake -DUHDR_BUILD_DEPS=1` will clone [libjpeg-turbo](https://github.com/libjpeg-turbo/libjpeg-turbo.git)
and [libheif](https://github.com/strukturag/libheif.git) (with the ISO 21496-1 gain map patch applied) and build them statically.

If jpeg is included in the build process then,
- C compiler
- For building x86/x86_64 SIMD optimizations, [NASM](http://www.nasm.us) or
 [Yasm](http://yasm.tortall.net).
  * If using NASM, 2.13 or later is required.
  * If using Yasm, 1.2.0 or later is required.

### CMake Options

There are a few options that can be passed to CMake to modify how the code
is built.<br>
To set these options and parameters, use `-D<Parameter_name>=<value>`.

All CMake options are passed at configure time, i.e., by running
`cmake -DOPTION_ONE=1 -DOPTION_TWO=0 ...` <br>
before running `cmake --build ...`<br>

For example, to build unit tests in a new subdirectory called 'build', run:

```sh
cmake -G "Unix Makefiles" -S. -Bbuild -DUHDR_BUILD_TESTS=1 ../
```
and then build with:

```sh
cmake --build build
```

Following is a list of available options:

| CMake Option | Default Value | Notes |
|:-------------|:--------------|:-----|
| `CMAKE_BUILD_TYPE` | Release | See CMake documentation [here](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html). |
| `BUILD_SHARED_LIBS` | ON | See CMake documentation [here](https://cmake.org/cmake/help/latest/variable/BUILD_SHARED_LIBS.html). <ul><li> If `BUILD_SHARED_LIBS` is **OFF**, in the linking phase, static versions of dependencies are chosen. However, the executable targets are not purely static because the system libraries used are still dynamic. </li></ul> |
| `UHDR_BUILD_EXAMPLES` | ON | Build sample application. This application demonstrates how to use [ultrahdr_api.h](../ultrahdr_api.h). |
| `UHDR_BUILD_TESTS` | OFF | Build Unit Tests. Mostly for Devs. During development, different modules of libuhdr library are validated using GoogleTest framework. Developers after making changes to library are expected to run these tests to ensure every thing is functional. |
| `UHDR_BUILD_BENCHMARK` | OFF | Build Benchmark Tests. These are for profiling libuhdr encode/decode API. Resources used by benchmark tests are shared [here](https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.1.zip). These are downloaded and extracted automatically during the build process for later benchmarking. |
| `UHDR_BUILD_FUZZERS` | OFF | Build Fuzz Test Applications. Mostly for Devs. <ul><li> Fuzz applications are built by instrumenting the entire software suite. This includes dependency libraries. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
| `UHDR_BUILD_DEPS` | OFF | Clone and Build project dependencies (libjpeg-turbo, libheif with ISO 21496-1 patch, googletest, benchmark) and not use pre-installed packages. |
| `UHDR_BUILD_JAVA` | OFF | Build JNI wrapper, Java front-end classes and Java sample application. |
| `UHDR_ENABLE_LOGS` | OFF | Build with verbose logging. |
| `UHDR_ENABLE_INSTALL` | ON | Enable install and uninstall targets for libuhdr package. <ul><li> For system wide installation it is best if dependencies are acquired from OS package manager instead of building from source. This is to avoid conflicts with software that is using a different version of the said dependency and also links to libuhdr. So if `UHDR_BUILD_DEPS` is **ON** then `UHDR_ENABLE_INSTALL` is forced to **OFF** internally. |
| `UHDR_ENABLE_INTRINSICS` | ON | Build with SIMD acceleration. Sections of libuhdr are accelerated for Arm Neon architectures and these are enabled. <ul><li> For x86/x86_64 architectures currently no SIMD acceleration is present. Consequently this option has no effect. </li><li> This parameter has no effect on SIMD configuration settings of dependencies. </li></ul> |
| `UHDR_ENABLE_GLES` | OFF | Build with GPU acceleration. |
| `UHDR_ENABLE_WERROR` | OFF | Enable -Werror when building. |
| `UHDR_ENABLE_SMPTE2094_50` | OFF | Build with SMPTE 2094-50 dynamic metadata support. |
| `UHDR_ENABLE_HEIF` | ON | Build with HEIF and AVIF container support via `libheif`. <ul><li> If `UHDR_BUILD_DEPS` is **OFF**, CMake looks for a system `libheif` that provides ISO 21496-1 gain map APIs. If system `libheif` lacks the gain map APIs or is missing, HEIF support is gracefully disabled with a warning. </li><li> If `UHDR_BUILD_DEPS` is **ON**, CMake automatically clones bundled `libheif` with the ISO 21496-1 patch and builds it statically. </li></ul> |
| `UHDR_MAX_DIMENSION` | 8192 | Maximum dimension supported by the library. The library defaults to handling images upto resolution 8192x8192. For different resolution needs use this option. For example, `-DUHDR_MAX_DIMENSION=4096`. |
| `UHDR_WRITE_XMP` | OFF | Enable writing gainmap metadata in XMP packet. <ul><li> Current implementation of XMP format supports writing only single channel gainmap metadata. To support encoding multi channel gainmap metadata, XMP format encoding is disabled by default. If enabled, metadata of all channels of gainmap image is merged into one and signalled. </li></ul> |
| `UHDR_WRITE_ISO` | ON | Enable writing gainmap metadata in ISO 21496-1 format. |
| `UHDR_SANITIZE_OPTIONS` | OFF | Build library with sanitize options. Values set to this parameter are passed to directly to compilation option `-fsanitize`. For example, `-DUHDR_SANITIZE_OPTIONS=address,undefined` adds `-fsanitize=address,undefined` to the list of compilation options. CMake configuration errors are raised if the compiler does not support these flags. This is useful during fuzz testing. <ul><li> As `-fsanitize` is an instrumentation option, dependencies are also built from source instead of using pre-builts. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
| `UHDR_BUILD_PACKAGING` | OFF | Build distribution packages using CPack. |
| | | |

### Generator

The CMake generator preferred is ninja. Consequently, ninja is added to the list of prerequisite packages. This need not be the case. If the platform is equipped with a different generator, it can be tried and ninja installation can be skipped.

### Build Steps

Check out the source code:

```sh
git clone https://github.com/google/libultrahdr.git
cd libultrahdr
mkdir build_directory
cd build_directory
```

### Linux Platform

Install the prerequisite packages before building:

```sh
sudo apt install cmake pkg-config libjpeg-dev ninja-build
```

Compile and Test:

```sh
cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
ninja
ctest
```

This will generate the following files under `build_directory`:

**libuhdr.so.{version}** - Shared library for the libuhdr API <br>
**libuhdr.so** - Symlink to shared library <br>
**libuhdr.a** - Static link library for the libuhdr API <br>
**libuhdr.pc** - libuhdr pkg-config file <br>
**ultrahdr_app** - sample application <br>
**ultrahdr_unit_test** - unit tests <br>

Installation:

```sh
sudo ninja install
```

This installs the headers, pkg-config, and shared libraries. By default the headers are put in `/usr/local/include/`, libraries in `/usr/local/lib/` and pkg-config file in `/usr/local/lib/pkgconfig/`. You may need to add path `/usr/local/lib/` to `LD_LIBRARY_PATH` if binaries linking with ultrahdr library are unable to load it at run time. e.g. `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/`.

### Enabling HEIF and AVIF Gain Map Encoding and Decoding

libultrahdr supports encoding and decoding ISO 21496-1 gain map images in HEIF (`.heic`) and AVIF (`.avif`) container formats via `libheif`.

#### 1. Building with Bundled Dependencies (Recommended)

To ensure full HEIF and AVIF gain map support out-of-the-box on any machine, build with `-DUHDR_BUILD_DEPS=1`:

```sh
cmake -G Ninja -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
ninja
```

This automatically downloads bundled `libheif` source and applies the ISO 21496-1 gain map patch ([PR #1503](https://github.com/strukturag/libheif/pull/1503)).

#### 2. Building with System libheif

If you have a system-installed `libheif` that provides ISO 21496-1 gain map APIs:

```sh
cmake -G Ninja -DUHDR_BUILD_TESTS=1 ../
ninja
```

CMake will automatically discover system `libheif` and dynamically link against `libheif::heif`. If the system `libheif` is missing or lacks the gain map APIs, CMake gracefully disables `UHDR_ENABLE_HEIF` with a warning, allowing the rest of the build to succeed.

#### 3. Runtime Codec Plugins for HEIF/AVIF Full-Pixel Encoding and Decoding

`libheif` uses modular codec plugins at runtime for compression and decompression:
- **HEVC Decode**: `libde265` (`libheif-plugin-libde265` on Debian/Ubuntu)
- **HEVC Encode**: `x265` (`libheif-plugin-x265` on Debian/Ubuntu)
- **AV1 Decode**: `dav1d` (`libheif-plugin-dav1d` on Debian/Ubuntu)
- **AV1 Encode**: `aom` / `svt-av1` (`libheif-plugin-aomenc` / `libheif-plugin-svtenc` on Debian/Ubuntu)

On Debian/Ubuntu, install the required codec plugins:
```sh
sudo apt install libheif-plugin-libde265 libheif-plugin-x265 libheif-plugin-dav1d libheif-plugin-aomenc
```
If plugins are located in a custom directory, set the `LIBHEIF_PLUGIN_DIRECTORY` environment variable to point to the plugin folder (e.g. `export LIBHEIF_PLUGIN_DIRECTORY=/usr/lib/x86_64-linux-gnu/libheif/plugins`).

### macOS Platform

Install the prerequisite packages before building:

```sh
brew install cmake pkg-config jpeg ninja
```

Compile and Test:

```sh
cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
ninja
ctest
```

#### Cross-compiling for Intel on Apple Silicon

From the libultrahdr source directory, build a thin x86_64 binary on an Apple
Silicon Mac:

```sh
cmake -G Ninja -S . -B build-x86_64 \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0 \
  -DUHDR_BUILD_DEPS=1 \
  -DUHDR_BUILD_TESTS=1
cmake --build build-x86_64
```

`UHDR_BUILD_DEPS=1` builds libjpeg-turbo and test dependencies for the
requested architecture. When using installed dependencies instead, they must
contain an x86_64 slice. Only one value in `CMAKE_OSX_ARCHITECTURES` is
supported per build; universal arm64+x86_64 builds are not supported. Running
the x86_64 tests on Apple Silicon requires Rosetta 2.

This will generate the following files under `build_directory`:

**libuhdr.{version}.dylib** - Shared library for the libuhdr API <br>
**libuhdr.dylib** - Symlink to shared library <br>
**libuhdr.a** - Static link library for the libuhdr API <br>
**libuhdr.pc** - libuhdr pkg-config file <br>
**ultrahdr_app** - sample application <br>
**ultrahdr_unit_test** - unit tests <br>

Installation:

```sh
sudo ninja install
```

This installs the headers, pkg-config, and shared libraries. By default the headers are put in `/usr/local/include/`, libraries in `/usr/local/lib/` and pkg-config file in `/usr/local/lib/pkgconfig/`. You may need to add path `/usr/local/lib/` to `DYLD_FALLBACK_LIBRARY_PATH` if binaries are unable to load uhdr library e.g. `export DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH:/usr/local/lib/`.

Uninstallation:

```sh
sudo ninja uninstall
```

### Windows Platform - MSYS2 Env

Install the prerequisite packages before building:

```sh
pacman -S mingw-w64-ucrt-x86_64-libjpeg-turbo mingw-w64-ucrt-x86_64-ninja
```

Compile and Test:

```sh
cmake -G Ninja -DUHDR_BUILD_TESTS=1 ../
ninja
ctest
```

This will generate the following files under `build_directory`:

**libuhdr.dll** - Shared library for the libuhdr API <br>
**libuhdr.dll.a** - Import library for the libuhdr API <br>
**libuhdr.a** - Static link library for the libuhdr API <br>
**libuhdr.pc** - libuhdr pkg-config file <br>
**ultrahdr_app** - sample application <br>
**ultrahdr_unit_test** - unit tests <br>

### Windows Platform - MSVC Env

Install the prerequisite packages before building:

```sh
git clone https://github.com/libjpeg-turbo/libjpeg-turbo.git
cd libjpeg-turbo
cmake -G "Visual Studio 16 2019" -DCMAKE_INSTALL_PREFIX=/c/msvcinstalls/ -S. -Bbuild
cmake --build ./build --config=Release --target install
```

#### IDE

Compile and Test:

```sh
cmake -G "Visual Studio 16 2019" -DCMAKE_PREFIX_PATH=/c/msvcinstalls/ -DCMAKE_INSTALL_PREFIX=/c/msvcinstalls/ ../
cmake --build ./ --config=Release
ctest -C Release
```

#### Command Line

Compile and Test:

```sh
cmake -G "NMake Makefiles" -DCMAKE_PREFIX_PATH=/c/msvcinstalls/ -DCMAKE_INSTALL_PREFIX=/c/msvcinstalls/ ../
cmake --build ./
ctest
```

This will generate the following files under `build_directory`:

**uhdr.dll** - Shared library for the libuhdr API <br>
**uhdr.lib** - Import library for the libuhdr API <br>
**ultrahdr_app** - sample application <br>

### Cross-Compilation - Build System Linux

#### Target - Linux Platform - Armv7 Arch

Install the prerequisite packages before building:

```sh
sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
```

Compile:

```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/arm-linux-gnueabihf.cmake -DUHDR_BUILD_DEPS=1 ../
ninja
```

#### Target - Linux Platform - Armv8 Arch

Install the prerequisite packages before building:

```sh
sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
```

Compile:

```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/aarch64-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
ninja
```

#### Target - Linux Platform - RISC-V Arch (64 bit)

Install the prerequisite packages before building:

```sh
sudo apt install gcc-riscv64-linux-gnu g++-riscv64-linux-gnu
```

Compile:

```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/riscv64-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
ninja
```

This will generate the following files under `build_directory`:

**libuhdr.so.{version}** - Shared library for the libuhdr API <br>
**libuhdr.so** - Symlink to shared library <br>
**libuhdr.a** - Static link library for the libuhdr API <br>
**ultrahdr_app** - sample application <br>
**ultrahdr_unit_test** - unit tests <br>

#### Target - Linux Platform - RISC-V Arch (32 bit)

Install the prerequisite packages before building:

```sh
# Download from https://github.com/riscv-collab/riscv-gnu-toolchain/releases
sudo ln -s {your_dir}/riscv/bin/riscv32-unknown-linux-gnu-g++ /usr/bin/riscv32-linux-gnu-g++
sudo ln -s {your_dir}/riscv/bin/riscv32-unknown-linux-gnu-gcc /usr/bin/riscv32-linux-gnu-gcc
```

Compile:

```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/riscv32-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
ninja
```

This will generate the following files under `build_directory`:

**libuhdr.so.{version}** - Shared library for the libuhdr API <br>
**libuhdr.so** - Symlink to shared library <br>
**libuhdr.a** - Static link library for the libuhdr API <br>
**ultrahdr_app** - sample application <br>
**ultrahdr_unit_test** - unit tests <br>

#### Target - Linux Platform - LOONG Arch (64 bit)

Install the prerequisite packages before building:

```sh
sudo apt install gcc-loongarch64-linux-gnu g++-loongarch64-linux-gnu
```

Compile:

```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/loong64-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
ninja
```

#### Target - Android Platform

Install the prerequisite packages before building:

```sh
wget https://dl.google.com/android/repository/android-ndk-r26d-linux.zip
unzip android-ndk-r26d-linux.zip
```

Choose target architecture with -DANDROID_ABI={armeabi-v7a, arm64-v8a, x86, x86_64}

Compile:
```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/android.cmake -DUHDR_ANDROID_NDK_PATH=/opt/android-ndk-r26d/ -DUHDR_BUILD_DEPS=1 -DANDROID_ABI="Selected Architecture" -DANDROID_PLATFORM=android-23 ../
ninja
```

This will generate the following files under `build_directory`:

**libuhdr.so** - Shared library for the libuhdr API <br>
**libuhdr.a** - Static link library for the libuhdr API <br>
**ultrahdr_app** - sample application <br>
**ultrahdr_unit_test** - unit tests <br>

#### Target - Wasm

Install the prerequisite packages before building: Follow the instructions given [here](https://emscripten.org/docs/getting_started/downloads.html#installation-instructions-using-the-emsdk-recommended).

Compile:
```sh
emcmake cmake -G Ninja ../
ninja
```

This will generate the following files under `build_directory`:

**ultrahdr_app.wasm** - wasm module <br>
**ultrahdr_app.js** - sample application <br>

## Building Fuzzers

Refer to [fuzzers.md](fuzzers.md) for complete instructions.
