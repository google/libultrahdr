#
# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#

cmake_minimum_required(VERSION 3.15)

# CMP0091: MSVC runtime library flags are selected by an abstraction.
# New in CMake 3.15. https://cmake.org/cmake/help/latest/policy/CMP0091.html
if(POLICY CMP0091)
  cmake_policy(SET CMP0091 OLD)
endif()

set(UHDR_MAJOR_VERSION 1)
set(UHDR_MINOR_VERSION 4)
set(UHDR_PATCH_VERSION 0)
project(libuhdr
        VERSION ${UHDR_MAJOR_VERSION}.${UHDR_MINOR_VERSION}.${UHDR_PATCH_VERSION}
        LANGUAGES C CXX
        DESCRIPTION "Library for encoding and decoding ultrahdr images")

###########################################################
# Detect system
###########################################################
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Android")
elseif(WIN32)
elseif(APPLE)
else()
  message(FATAL_ERROR "Platform ${CMAKE_SYSTEM_NAME} not recognized")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "amd64")
  else()
    set(ARCH "i386")
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686.*|i386.*|x86.*")
  set(ARCH "i386")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*|arm64.*|ARM64.*)")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "aarch64")
  else()
    set(ARCH "arm")
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm.*|ARM.*)")
  set(ARCH "arm")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv64")
  set(ARCH "riscv64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv32")
  set(ARCH "riscv32")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^loongarch64")
  set(ARCH "loong64")
else()
  message(FATAL_ERROR "Architecture: ${CMAKE_SYSTEM_PROCESSOR} not recognized")
endif()

# Cross compiling on macOS. The cross compiling architecture should override
# auto-detected system architecture settings.
if(CMAKE_OSX_ARCHITECTURES)
  if(APPLE)
    if(CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
      set(ARCH "aarch64")
    elseif(CMAKE_OSX_ARCHITECTURES STREQUAL "x86_64")
      set(ARCH "x86_64")
    elseif(CMAKE_OSX_ARCHITECTURES STREQUAL "i386")
      set(ARCH "x86")
    else()
      message(FATAL_ERROR "Architecture ${CMAKE_OSX_ARCHITECTURES} is not "
                          "supported. Only one architecture (arm64, x86_64 "
                          "or i386) could be specified at build time.")
    endif()
  else()
    message(WARNING "ignoring setting CMAKE_OSX_ARCHITECTURES:= ${CMAKE_OSX_ARCHITECTURES}")
  endif()
endif()

###########################################################
# Directories
###########################################################
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
set(JAVA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/java)
set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set(BENCHMARK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/benchmark)
set(FUZZERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fuzzer)
set(EXAMPLES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/examples)
set(EXPORT_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
  message(WARNING "Selected in-source build. Preferably, create a build/ directory and build from there.")
endif()

###########################################################
# Options
###########################################################
get_cmake_property(IS_MULTI GENERATOR_IS_MULTI_CONFIG)
if(NOT IS_MULTI)
  if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type chosen, selecting Release")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "The type of build: Debug Release MinSizeRel RelWithDebInfo." FORCE)
  endif()
endif()

if(EMSCRIPTEN)
  # platform does not support dynamic linking?
  message(STATUS "For wasm targets, selecting static only builds")
  option(BUILD_SHARED_LIBS "Build shared libraries" FALSE)
elseif(NOT DEFINED BUILD_SHARED_LIBS)
  message(STATUS "No target type chosen, selecting Shared")
  option(BUILD_SHARED_LIBS "Build shared libraries" TRUE)
endif()

function(option_if_not_defined name description default)
  if(NOT DEFINED ${name})
    option(${name} ${description} ${default})
  endif()
endfunction()

option_if_not_defined(UHDR_BUILD_EXAMPLES "Build sample application " TRUE)
option_if_not_defined(UHDR_BUILD_TESTS "Build unit tests " FALSE)
option_if_not_defined(UHDR_BUILD_BENCHMARK "Build benchmark tests " FALSE)
option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzz test applications " FALSE)
option_if_not_defined(UHDR_BUILD_DEPS "Build deps and not use pre-installed packages " FALSE)
option_if_not_defined(UHDR_BUILD_JAVA "Build JNI wrapper and Java front-end classes " FALSE)
option_if_not_defined(UHDR_BUILD_PACKAGING "Build distribution packages using CPack " FALSE)

option_if_not_defined(UHDR_ENABLE_LOGS "Build with verbose logging " FALSE)
option_if_not_defined(UHDR_ENABLE_INSTALL "Enable install and uninstall targets for libuhdr package " TRUE)
option_if_not_defined(UHDR_ENABLE_INTRINSICS "Build with SIMD acceleration " TRUE)
option_if_not_defined(UHDR_ENABLE_GLES "Build with GPU acceleration " FALSE)
option_if_not_defined(UHDR_ENABLE_WERROR "Build with -Werror" FALSE)

# These options effect only encoding process.
# Decoding continues to support both iso and xmp irrespective of this configuration.
# Also, if both packets are present iso is prioritized over xmp.
option_if_not_defined(UHDR_WRITE_XMP "Write gainmap metadata in XMP packet" FALSE)
option_if_not_defined(UHDR_WRITE_ISO "Write gainmap metadata in ISO 21496_1 packet" TRUE)

# pre-requisites
if(UHDR_BUILD_TESTS AND EMSCRIPTEN)
  message(FATAL_ERROR "Building tests not supported for wasm targets")
endif()

if(UHDR_BUILD_BENCHMARK AND WIN32)
  message(FATAL_ERROR "Building benchmarks not supported in Windows")
endif()

if(UHDR_BUILD_BENCHMARK AND EMSCRIPTEN)
  message(FATAL_ERROR "Building benchmarks not supported for wasm targets")
endif()

# side effects
if(CMAKE_CROSSCOMPILING AND UHDR_ENABLE_INSTALL)
  set(UHDR_ENABLE_INSTALL FALSE) # disable install and uninstall targets during cross compilation.
  message(STATUS "Install and uninstall targets - Disabled")
endif()

if(UHDR_BUILD_FUZZERS AND NOT UHDR_BUILD_DEPS)
  set(UHDR_BUILD_DEPS TRUE) # For fuzz testing its best to build all dependencies from source.
                            # This is to instrument dependency libs as well.
  message(STATUS "Building dependencies from source - Enabled")
endif()

if(DEFINED UHDR_SANITIZE_OPTIONS AND NOT UHDR_BUILD_DEPS)
  set(UHDR_BUILD_DEPS TRUE) # If sanitize options are enabled, its best to build all dependencies from source.
                            # This is to instrument dependency libs as well.
  message(STATUS "Building dependencies from source - Enabled")
endif()

if(UHDR_BUILD_DEPS AND UHDR_ENABLE_INSTALL)
  set(UHDR_ENABLE_INSTALL FALSE) # If dependencies are not chosen from installed packages but are built
                                 # from source, its best to disallow system wide installation of
                                 # uhdr to avoid possible abi/api conflicts.
  message(STATUS "Install and uninstall targets - Disabled")
endif()

###########################################################
# Compile flags
###########################################################
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(BUILD_SHARED_LIBS)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  set(CMAKE_CXX_VISIBILITY_PRESET hidden)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
  set(UHDR_ENABLE_STATIC_LINKING OFF)
  add_compile_options(-DUHDR_BUILDING_SHARED_LIBRARY)
else()
  if(WIN32)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
  else()
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
  endif()
  if(APPLE)
    message(STATUS "Apple does not support statically linking an entire executable, disabling '-static' option")
    set(UHDR_ENABLE_STATIC_LINKING OFF)
  elseif(DEFINED UHDR_SANITIZE_OPTIONS OR UHDR_BUILD_FUZZERS)
    message(STATUS "Possible that sanitizer libraries are only DSO's, disabling '-static' option")
    set(UHDR_ENABLE_STATIC_LINKING OFF)
  elseif(MSVC)
    message(STATUS "Disabling '-static' option in MSVC platforms")
    set(UHDR_ENABLE_STATIC_LINKING OFF)
  else()
    set(UHDR_ENABLE_STATIC_LINKING ON)
  endif()
endif()
if(UHDR_ENABLE_LOGS)
  add_compile_options(-DLOG_NDEBUG)
endif()
if(UHDR_ENABLE_INTRINSICS)
  add_compile_options(-DUHDR_ENABLE_INTRINSICS)
endif()
if(UHDR_WRITE_XMP)
  add_compile_options(-DUHDR_WRITE_XMP)
endif()
if(UHDR_WRITE_ISO)
  add_compile_options(-DUHDR_WRITE_ISO)
endif()

include(CheckCXXCompilerFlag)
function(CheckCompilerOption opt res)
  set(CMAKE_REQUIRED_FLAGS ${opt})
  check_cxx_compiler_flag(${opt} ${res})
  unset(CMAKE_REQUIRED_FLAGS)
  if(NOT ${res})
    message(FATAL_ERROR "Unsupported compiler option(s) ${opt}")
  endif()
endfunction(CheckCompilerOption)

if(DEFINED UHDR_SANITIZE_OPTIONS)
  CheckCompilerOption("-fsanitize=${UHDR_SANITIZE_OPTIONS}" SUPPORTS_SAN_OPTIONS)
  add_compile_options(-fsanitize=${UHDR_SANITIZE_OPTIONS})
  add_link_options(-fsanitize=${UHDR_SANITIZE_OPTIONS})
endif()

if(UHDR_BUILD_FUZZERS)
  CheckCompilerOption("-fsanitize=fuzzer-no-link" fuzz)
  add_compile_options(-fsanitize=fuzzer-no-link)
endif()

set(UHDR_WERROR_FLAGS "")
if(MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  # Disable specific warnings
  # TODO: None of these should be disabled, but for now, for a warning-free msvc build these are
  # added. fix the warnings and remove these filters
  add_compile_options(/wd4244) # conversion from 'type1' to 'type2', possible loss of data
  add_compile_options(/wd4267) # conversion from 'size_t' to 'type' possible loss of data
  add_compile_options(/wd4305) # truncation from 'double' to 'float'
  add_compile_options(/wd4838) # conversion from 'type1' to 'type2' requires a narrowing conversion
  add_compile_options(/wd26812) # Prefer enum class over enum
elseif(EMSCRIPTEN)
  if(NOT UHDR_BUILD_DEPS)
    include(CheckCSourceCompiles)
    set(CMAKE_REQUIRED_FLAGS "--use-port=libjpeg")
    set(CMAKE_REQUIRED_LINK_OPTIONS "--use-port=libjpeg")
    check_c_source_compiles([=[
       #include <stdio.h>
       #include <jpeglib.h>
       int main(void) {
         struct jpeg_compress_struct cinfo;
         struct jpeg_error_mgr jerr;
         cinfo.err=jpeg_std_error(&jerr);
         jpeg_create_compress(&cinfo);
         jpeg_destroy_compress(&cinfo);
         return 0;
       }
     ]=] HAVE_JPEG)
    if(NOT HAVE_JPEG)
      message(FATAL_ERROR "Could NOT compile with --use-port=libjpeg, resolve this \
                           or try 'cmake -DUHDR_BUILD_DEPS=1'")
    endif()
  endif()
else()
  add_compile_options(-ffunction-sections)
  add_compile_options(-fdata-sections)
  add_compile_options(-fomit-frame-pointer)
  add_compile_options(-ffp-contract=fast)
  if(ARCH STREQUAL "i386")
    add_compile_options(-m32)
    add_compile_options(-march=i386)
    add_compile_options(-mtune=generic)
  elseif(ARCH STREQUAL "amd64")
    add_compile_options(-m64)
    add_compile_options(-march=x86-64)
    add_compile_options(-mtune=generic)
  elseif(ARCH STREQUAL "arm")
    add_compile_options(-march=armv7-a)
    add_compile_options(-marm)
    if(NOT ANDROID_ABI)
      add_compile_options(-mfloat-abi=hard)
    endif()
    add_compile_options(-mfpu=neon-vfpv3)
    add_compile_options(-fno-lax-vector-conversions)
  elseif(ARCH STREQUAL "aarch64")
    add_compile_options(-march=armv8-a)
    add_compile_options(-fno-lax-vector-conversions)
  elseif(ARCH STREQUAL "riscv64")
    add_compile_options(-march=rv64gc)
    add_compile_options(-mabi=lp64d)
  elseif(ARCH STREQUAL "riscv32")
    add_compile_options(-march=rv32gc)
    add_compile_options(-mabi=ilp32d)
  elseif(ARCH STREQUAL "loong64")
    add_compile_options(-march=loongarch64)
    add_compile_options(-mabi=lp64d)
  endif()

  if(UHDR_ENABLE_WERROR)
    CheckCompilerOption("-Werror" SUPPORTS_WERROR)
    set(UHDR_WERROR_FLAGS "-Werror")
  endif()
endif()

###########################################################
# Utils
###########################################################
# copied from https://github.com/google/shaderc/blob/main/cmake/utils.cmake
macro(get_transitive_static_libs target out_list)
  if(TARGET ${target})
    get_target_property(target_type ${target} TYPE)
    if(target_type STREQUAL "STATIC_LIBRARY")
      list(INSERT ${out_list} 0 ${target})
      get_target_property(libs ${target} LINK_LIBRARIES)
      if(libs)
        foreach(lib ${libs})
          get_transitive_static_libs(${lib} ${out_list})
        endforeach()
      endif()
    endif()
  endif()
endmacro()

# combine a list of static libraries in to a single library
function(combine_static_libs target output_target)
  set(all_libs_list "")
  get_transitive_static_libs(${target} all_libs_list)
  foreach(lib IN LISTS all_libs_list)
    target_sources(${output_target} PRIVATE $<TARGET_OBJECTS:${lib}>)
  endforeach()
endfunction()

###########################################################
# Dependencies
###########################################################
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
  if (UHDR_ENABLE_LOGS)
    find_library(log-lib log QUIET)
    if(NOT log-lib)
      message(FATAL_ERROR "Could NOT find log library, retry after installing \
                           log library at sysroot or try 'cmake -DUHDR_ENABLE_LOGS=0'")
    else()
      message(STATUS "Found log-lib: ${log-lib}")
    endif()
  endif()
endif()

# Threads
set(CMAKE_THREAD_PREFER_PTHREAD ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

include(ExternalProject)

get_directory_property(UHDR_COMPILE_FLAGS COMPILE_OPTIONS)
string (REPLACE ";" " " UHDR_COMPILE_FLAGS_STR "${UHDR_COMPILE_FLAGS}")
set(UHDR_CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${UHDR_COMPILE_FLAGS_STR}")
set(UHDR_CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${UHDR_COMPILE_FLAGS_STR}")
set(UHDR_CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_C_FLAGS=${UHDR_CMAKE_C_FLAGS})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_C_FLAGS_DEBUG=${CMAKE_C_FLAGS_DEBUG})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_C_FLAGS_RELEASE=${CMAKE_C_FLAGS_RELEASE})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_C_FLAGS_MINSIZEREL=${CMAKE_C_FLAGS_MINSIZEREL})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_C_FLAGS_RELWITHDEBINFO=${CMAKE_C_FLAGS_RELWITHDEBINFO})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_CXX_FLAGS=${UHDR_CMAKE_CXX_FLAGS})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_CXX_FLAGS_MINSIZEREL=${CMAKE_CXX_FLAGS_MINSIZEREL})
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO})
if(BUILD_SHARED_LIBS)
  list(APPEND UHDR_CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
endif()
if(MSVC AND UHDR_BUILD_TESTS)
  list(APPEND UHDR_CMAKE_ARGS "-Dgtest_force_shared_crt=ON")
endif()
if(DEFINED CMAKE_TOOLCHAIN_FILE)
  list(APPEND UHDR_CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE})
endif()
if(DEFINED ANDROID_PLATFORM)
  list(APPEND UHDR_CMAKE_ARGS -DANDROID_PLATFORM=${ANDROID_PLATFORM})
endif()
if(DEFINED ANDROID_ABI)
  list(APPEND UHDR_CMAKE_ARGS -DANDROID_ABI=${ANDROID_ABI})
endif()
if(DEFINED UHDR_ANDROID_NDK_PATH)
  list(APPEND UHDR_CMAKE_ARGS -DUHDR_ANDROID_NDK_PATH=${UHDR_ANDROID_NDK_PATH})
endif()

# opengl es libraries
if(UHDR_ENABLE_GLES)
  find_package(EGL QUIET)
  if(EGL_FOUND)
    message(STATUS "Found EGL: ${EGL_LIBRARIES}")
    find_package(OpenGLES3 QUIET)
    if(OpenGLES3_FOUND)
      message(STATUS "Found GLESv3: ${OPENGLES3_LIBRARIES} (API version \"${OpenGLES3_API_VERSION}\")")
    else()
      message(STATUS "Could NOT find GLESv3")
    endif()
  else()
    message(STATUS "Could NOT find EGL")
  endif()
  if(EGL_FOUND AND OpenGLES3_FOUND)
    add_compile_options(-DUHDR_ENABLE_GLES)
    string(FIND "${OPENGLES3_LIBRARIES}" "GLESv3" result)
    if(result GREATER -1)
      set(UHDR_GL_DEPS "-lEGL -lGLESv3")
    else()
      set(UHDR_GL_DEPS "-lEGL -lGLESv2")
    endif()
  else()
    set(UHDR_ENABLE_GLES FALSE)
  endif()
endif()

# libjpeg-turbo
if(NOT UHDR_BUILD_DEPS)
  find_package(JPEG QUIET)
  if(NOT JPEG_FOUND)
    message(FATAL_ERROR "Could NOT find JPEG (missing: JPEG_LIBRARIES JPEG_INCLUDE_DIRS),\
                         retry after installing JPEG library at sysroot or try 'cmake -DUHDR_BUILD_DEPS=1'")
  else()
    message(STATUS "Found JPEG: ${JPEG_LIBRARIES} (found version \"${JPEG_VERSION}\")")
  endif()
endif()

if(NOT JPEG_FOUND)
  set(JPEGTURBO_TARGET_NAME turbojpeg)
  set(JPEGTURBO_PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR}/${JPEGTURBO_TARGET_NAME})
  set(JPEGTURBO_SOURCE_DIR ${THIRD_PARTY_DIR}/${JPEGTURBO_TARGET_NAME})
  set(JPEGTURBO_BINARY_DIR ${JPEGTURBO_PREFIX_DIR}/src/${JPEGTURBO_TARGET_NAME}-build)
  set(JPEG_INCLUDE_DIRS ${JPEGTURBO_SOURCE_DIR}/src ${JPEGTURBO_BINARY_DIR})
  if(MSVC)
    set(JPEG_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}jpeg-static${CMAKE_STATIC_LIBRARY_SUFFIX})
  else()
    set(JPEG_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}jpeg${CMAKE_STATIC_LIBRARY_SUFFIX})
  endif()
  if(IS_MULTI)
    set(JPEG_LIB_PREFIX ${JPEGTURBO_BINARY_DIR}/$<CONFIG>/)
  else()
    set(JPEG_LIB_PREFIX ${JPEGTURBO_BINARY_DIR}/)
  endif()
  set(JPEG_LIBRARIES ${JPEG_LIB_PREFIX}${JPEG_LIB})
  if(EMSCRIPTEN)
    ExternalProject_Add(${JPEGTURBO_TARGET_NAME}
        GIT_REPOSITORY https://github.com/libjpeg-turbo/libjpeg-turbo.git
        GIT_TAG 3.1.0
        PREFIX ${JPEGTURBO_PREFIX_DIR}
        SOURCE_DIR ${JPEGTURBO_SOURCE_DIR}
        BINARY_DIR ${JPEGTURBO_BINARY_DIR}
        CONFIGURE_COMMAND emcmake cmake ${JPEGTURBO_SOURCE_DIR}
                          -DENABLE_SHARED=0 -DWITH_SIMD=0
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target jpeg-static
        BUILD_BYPRODUCTS ${JPEG_LIBRARIES}
        INSTALL_COMMAND ""
    )
  else()
    ExternalProject_Add(${JPEGTURBO_TARGET_NAME}
        GIT_REPOSITORY https://github.com/libjpeg-turbo/libjpeg-turbo.git
        GIT_TAG 3.1.0
        PREFIX ${JPEGTURBO_PREFIX_DIR}
        SOURCE_DIR ${JPEGTURBO_SOURCE_DIR}
        BINARY_DIR ${JPEGTURBO_BINARY_DIR}
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target jpeg-static
        CMAKE_ARGS ${UHDR_CMAKE_ARGS} -DENABLE_SHARED=0
        BUILD_BYPRODUCTS ${JPEG_LIBRARIES}
        INSTALL_COMMAND ""
    )
  endif()
endif()

if(UHDR_BUILD_JAVA)
  # build jni and java util classes
  find_package(Java REQUIRED)
  if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
    find_package(JNI QUIET)
    if(NOT JAVA_INCLUDE_PATH)
      message(FATAL_ERROR "Could NOT find JNI Component")
    else()
      message(STATUS "Found JNI Component")
    endif()
    set(UHDR_JNI_INCLUDE_PATH ${JAVA_INCLUDE_PATH})
  else()
    find_package(JNI REQUIRED)
    set(UHDR_JNI_INCLUDE_PATH ${JNI_INCLUDE_DIRS})
  endif()
endif()

if(UHDR_BUILD_TESTS)
  # gtest and gmock
  set(GTEST_TARGET_NAME googletest)
  set(GTEST_PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR}/${GTEST_TARGET_NAME})
  set(GTEST_SOURCE_DIR ${THIRD_PARTY_DIR}/${GTEST_TARGET_NAME})
  set(GTEST_BINARY_DIR ${GTEST_PREFIX_DIR}/src/${GTEST_TARGET_NAME}-build)
  set(GTEST_INCLUDE_DIRS
      ${GTEST_SOURCE_DIR}/googletest/include
      ${GTEST_SOURCE_DIR}/googlemock/include)
  set(GTEST_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}gtest${CMAKE_STATIC_LIBRARY_SUFFIX})
  set(GTEST_LIB_MAIN ${CMAKE_STATIC_LIBRARY_PREFIX}gtest_main${CMAKE_STATIC_LIBRARY_SUFFIX})
  if(IS_MULTI)
    set(GTEST_LIB_PREFIX ${GTEST_BINARY_DIR}/lib/$<CONFIG>/)
  else()
    set(GTEST_LIB_PREFIX ${GTEST_BINARY_DIR}/lib/)
  endif()
  set(GTEST_BOTH_LIBRARIES ${GTEST_LIB_PREFIX}${GTEST_LIB} ${GTEST_LIB_PREFIX}${GTEST_LIB_MAIN})
  ExternalProject_Add(${GTEST_TARGET_NAME}
      GIT_REPOSITORY https://github.com/google/googletest
      GIT_TAG v1.14.0
      PREFIX ${GTEST_PREFIX_DIR}
      SOURCE_DIR ${GTEST_SOURCE_DIR}
      BINARY_DIR ${GTEST_BINARY_DIR}
      CMAKE_ARGS ${UHDR_CMAKE_ARGS}
      BUILD_BYPRODUCTS ${GTEST_BOTH_LIBRARIES}
      INSTALL_COMMAND ""
  )
endif()

if(UHDR_BUILD_BENCHMARK)
  # benchmark
  set(BM_TARGET_NAME benchmark)
  set(BM_PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR}/${BM_TARGET_NAME})
  set(BM_SOURCE_DIR ${THIRD_PARTY_DIR}/${BM_TARGET_NAME})
  set(BM_BINARY_DIR ${BM_PREFIX_DIR}/src/${BM_TARGET_NAME}-build)
  set(BENCHMARK_INCLUDE_DIR ${BM_SOURCE_DIR}/include)
  set(BM_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}benchmark${CMAKE_STATIC_LIBRARY_SUFFIX})
  set(BM_LIB_MAIN ${CMAKE_STATIC_LIBRARY_PREFIX}benchmark_main${CMAKE_STATIC_LIBRARY_SUFFIX})
  if(IS_MULTI)
    set(BM_LIB_PREFIX ${BM_BINARY_DIR}/src/$<CONFIG>/)
  else()
    set(BM_LIB_PREFIX ${BM_BINARY_DIR}/src/)
  endif()
  set(BENCHMARK_LIBRARIES ${BM_LIB_PREFIX}${BM_LIB} ${BM_LIB_PREFIX}${BM_LIB_MAIN})
  ExternalProject_Add(${BM_TARGET_NAME}
      GIT_REPOSITORY https://github.com/google/benchmark.git
      GIT_TAG v1.8.3
      PREFIX ${BM_PREFIX_DIR}
      SOURCE_DIR ${BM_SOURCE_DIR}
      BINARY_DIR ${BM_BINARY_DIR}
      CMAKE_ARGS ${UHDR_CMAKE_ARGS}
                 -DBENCHMARK_ENABLE_TESTING=OFF
                 -DBENCHMARK_DOWNLOAD_DEPENDENCIES=OFF
      BUILD_BYPRODUCTS ${BENCHMARK_LIBRARIES}
      INSTALL_COMMAND ""
  )
endif()

set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
    ${JPEGTURBO_BINARY_DIR} ${GTEST_BINARY_DIR} ${BM_BINARY_DIR})

###########################################################
# File Lists
###########################################################
file(GLOB UHDR_CORE_SRCS_LIST "${SOURCE_DIR}/src/*.cpp")
if(UHDR_ENABLE_INTRINSICS)
  if(ARCH STREQUAL "arm" OR ARCH STREQUAL "aarch64")
    file(GLOB UHDR_CORE_NEON_SRCS_LIST "${SOURCE_DIR}/src/dsp/arm/*.cpp")
    list(APPEND UHDR_CORE_SRCS_LIST ${UHDR_CORE_NEON_SRCS_LIST})
  endif()
endif()
if(UHDR_ENABLE_GLES)
  file(GLOB UHDR_CORE_GLES_SRCS_LIST "${SOURCE_DIR}/src/gpu/*.cpp")
  list(APPEND UHDR_CORE_SRCS_LIST ${UHDR_CORE_GLES_SRCS_LIST})
endif()
if(UHDR_BUILD_JAVA)
  file(GLOB UHDR_JNI_SRCS_LIST "${JAVA_DIR}/jni/*.cpp")
  file(GLOB UHDR_JAVA_SRCS_LIST "${JAVA_DIR}/com/google/media/codecs/ultrahdr/*.java")
  file(GLOB UHDR_APP_SRC "${JAVA_DIR}/UltraHdrApp.java")
endif()
file(GLOB UHDR_TEST_SRCS_LIST "${TESTS_DIR}/*.cpp")
file(GLOB UHDR_BM_SRCS_LIST "${BENCHMARK_DIR}/*.cpp")
file(GLOB IMAGE_IO_SRCS_LIST "${THIRD_PARTY_DIR}/image_io/src/**/*.cc")

set(PRIVATE_INCLUDE_DIR ${SOURCE_DIR}/include/ ${JPEG_INCLUDE_DIRS})
set(PRIVATE_LINK_LIBS ${JPEG_LIBRARIES} Threads::Threads)
if(UHDR_ENABLE_GLES)
  list(APPEND PRIVATE_INCLUDE_DIR ${EGL_INCLUDE_DIRS} ${OPENGLES3_INCLUDE_DIRS})
  list(APPEND PRIVATE_LINK_LIBS ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
endif()

###########################################################
# Targets
###########################################################
set(IMAGEIO_TARGET_NAME image_io)
add_library(${IMAGEIO_TARGET_NAME} STATIC ${IMAGE_IO_SRCS_LIST})
target_include_directories(${IMAGEIO_TARGET_NAME} PRIVATE
  "${THIRD_PARTY_DIR}/image_io/includes"
  "${THIRD_PARTY_DIR}/image_io/src/modp_b64"
  "${THIRD_PARTY_DIR}/image_io/src/modp_b64/modp_b64")

set(UHDR_CORE_LIB_NAME core)
add_library(${UHDR_CORE_LIB_NAME} STATIC ${UHDR_CORE_SRCS_LIST})
target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
if(NOT JPEG_FOUND)
  add_dependencies(${UHDR_CORE_LIB_NAME} ${JPEGTURBO_TARGET_NAME})
endif()
if(NOT MSVC)
  target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE -Wall -Wextra -Wshadow)
endif()
if(DEFINED UHDR_MAX_DIMENSION)
  target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE -DUHDR_MAX_DIMENSION=${UHDR_MAX_DIMENSION})
endif()
target_include_directories(${UHDR_CORE_LIB_NAME} PRIVATE
  ${PRIVATE_INCLUDE_DIR}
  "${THIRD_PARTY_DIR}/image_io/includes/"
)
target_include_directories(${UHDR_CORE_LIB_NAME} PUBLIC ${EXPORT_INCLUDE_DIR})
if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
  target_link_libraries(${UHDR_CORE_LIB_NAME} PUBLIC ${log-lib})
endif()
target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${PRIVATE_LINK_LIBS} ${IMAGEIO_TARGET_NAME})

if(UHDR_BUILD_EXAMPLES)
  set(UHDR_SAMPLE_APP ultrahdr_app)
  add_executable(${UHDR_SAMPLE_APP} "${EXAMPLES_DIR}/ultrahdr_app.cpp")
  add_dependencies(${UHDR_SAMPLE_APP} ${UHDR_CORE_LIB_NAME})
  target_compile_options(${UHDR_SAMPLE_APP} PRIVATE ${UHDR_WERROR_FLAGS})
  if(UHDR_BUILD_FUZZERS)
    target_link_options(${UHDR_SAMPLE_APP} PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  if(UHDR_ENABLE_STATIC_LINKING)
    target_link_options(${UHDR_SAMPLE_APP} PRIVATE -static)
  endif()
  target_link_libraries(${UHDR_SAMPLE_APP} PRIVATE ${UHDR_CORE_LIB_NAME})
endif()

if(UHDR_BUILD_TESTS OR UHDR_BUILD_BENCHMARK)
  include(CTest)
  if(WIN32)
    file(COPY "${TESTS_DIR}/data/" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/data")
  else()
    execute_process(COMMAND "${CMAKE_COMMAND}" -E create_symlink
      "${TESTS_DIR}/data/" "${CMAKE_CURRENT_BINARY_DIR}/data"
      RESULT_VARIABLE result
      ERROR_VARIABLE errorinfo)
    string(FIND "${errorinfo}" "error" errorstatus)
    if(result GREATER 0 OR errorstatus GREATER -1)
      message(FATAL_ERROR "Creating sym link failed with info ${errorinfo}")
    endif()
  endif()
endif()

if(UHDR_BUILD_TESTS)
  add_executable(ultrahdr_unit_test ${UHDR_TEST_SRCS_LIST})
  add_dependencies(ultrahdr_unit_test ${GTEST_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
  target_compile_options(ultrahdr_unit_test PRIVATE ${UHDR_WERROR_FLAGS})
  target_include_directories(ultrahdr_unit_test PRIVATE
    ${PRIVATE_INCLUDE_DIR}
    ${GTEST_INCLUDE_DIRS}
  )
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_unit_test PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_unit_test ${UHDR_CORE_LIB_NAME} ${GTEST_BOTH_LIBRARIES})
  add_test(NAME UHDRUnitTests, COMMAND ultrahdr_unit_test)
endif()

if(UHDR_BUILD_BENCHMARK)
  add_executable(ultrahdr_bm ${UHDR_BM_SRCS_LIST})
  add_dependencies(ultrahdr_bm ${BM_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
  target_compile_options(ultrahdr_bm PRIVATE ${UHDR_WERROR_FLAGS})
  target_include_directories(ultrahdr_bm PRIVATE
    ${PRIVATE_INCLUDE_DIR}
    ${BENCHMARK_INCLUDE_DIR}
  )
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_bm PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_bm ${UHDR_CORE_LIB_NAME} ${BENCHMARK_LIBRARIES})

  set(RES_FILE "${TESTS_DIR}/data/UltrahdrBenchmarkTestRes-1.2.zip")
  set(RES_FILE_MD5SUM "14eac767ef7252051cc5658c4ad776d9")
  set(GET_RES_FILE TRUE)
  if(EXISTS ${RES_FILE})
    file(MD5 ${RES_FILE} CURR_MD5_SUM)
    if(CURR_MD5_SUM STREQUAL RES_FILE_MD5SUM)
      message("Zip File already exists: " ${RES_FILE})
      set(GET_RES_FILE FALSE)
    else()
      file(REMOVE "${RES_FILE}")
    endif()
  endif()

  if(GET_RES_FILE)
    message("-- Downloading benchmark test resources")
    set(RES_URL "https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.2.zip")
    file(DOWNLOAD ${RES_URL} ${RES_FILE} STATUS result EXPECTED_MD5 ${RES_FILE_MD5SUM})
    list(GET result 0 retval)
    if(retval)
      file(REMOVE "${RES_FILE}")
      list(GET result 0 errcode)
      list(GET result 1 info)
      message(FATAL_ERROR "Error downloading ${RES_URL}: ${info} (${errcode})")
    endif()
  endif()
  message("-- Extracting benchmark test resources")
  execute_process(COMMAND "${CMAKE_COMMAND}" -E tar xf "${RES_FILE}"
      WORKING_DIRECTORY "${TESTS_DIR}/data/"
      RESULT_VARIABLE result
      ERROR_VARIABLE errorinfo)
  string(FIND "${errorinfo}" "error" errorstatus)
  if(result GREATER 0 OR errorstatus GREATER -1)
    message(FATAL_ERROR "Extracting benchmark test resources failed with info ${errorinfo}")
  endif()
endif()

if(UHDR_BUILD_FUZZERS)
  add_executable(ultrahdr_enc_fuzzer ${FUZZERS_DIR}/ultrahdr_enc_fuzzer.cpp)
  add_dependencies(ultrahdr_enc_fuzzer ${UHDR_CORE_LIB_NAME})
  target_compile_options(ultrahdr_enc_fuzzer PRIVATE ${UHDR_WERROR_FLAGS})
  target_include_directories(ultrahdr_enc_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_enc_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_enc_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_enc_fuzzer ${UHDR_CORE_LIB_NAME})

  add_executable(ultrahdr_dec_fuzzer ${FUZZERS_DIR}/ultrahdr_dec_fuzzer.cpp)
  add_dependencies(ultrahdr_dec_fuzzer ${UHDR_CORE_LIB_NAME})
  target_compile_options(ultrahdr_dec_fuzzer PRIVATE ${UHDR_WERROR_FLAGS})
  target_include_directories(ultrahdr_dec_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_dec_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_dec_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_dec_fuzzer ${UHDR_CORE_LIB_NAME})

  add_executable(ultrahdr_legacy_fuzzer ${FUZZERS_DIR}/ultrahdr_legacy_fuzzer.cpp)
  add_dependencies(ultrahdr_legacy_fuzzer ${UHDR_CORE_LIB_NAME})
  target_compile_options(ultrahdr_legacy_fuzzer PRIVATE ${UHDR_WERROR_FLAGS})
  target_include_directories(ultrahdr_legacy_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_legacy_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_legacy_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_legacy_fuzzer ${UHDR_CORE_LIB_NAME})
endif()

set(UHDR_TARGET_NAME uhdr)
add_library(${UHDR_TARGET_NAME})
add_dependencies(${UHDR_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
target_compile_options(${UHDR_TARGET_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
  target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${log-lib})
endif()
target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${PRIVATE_LINK_LIBS})
set_target_properties(${UHDR_TARGET_NAME}
                      PROPERTIES PUBLIC_HEADER ultrahdr_api.h)
target_include_directories(${UHDR_TARGET_NAME} PUBLIC ${EXPORT_INCLUDE_DIR})
if(BUILD_SHARED_LIBS)
  # If target is STATIC no need to set VERSION and SOVERSION
  set_target_properties(${UHDR_TARGET_NAME}
                        PROPERTIES VERSION ${PROJECT_VERSION}
                        SOVERSION ${PROJECT_VERSION_MAJOR})
endif()
combine_static_libs(${UHDR_CORE_LIB_NAME} ${UHDR_TARGET_NAME})

# Build static library as well
if(BUILD_SHARED_LIBS)
  set(UHDR_TARGET_NAME_STATIC uhdr-static)
  add_library(${UHDR_TARGET_NAME_STATIC} STATIC)
  add_dependencies(${UHDR_TARGET_NAME_STATIC} ${UHDR_CORE_LIB_NAME})
  target_compile_options(${UHDR_TARGET_NAME_STATIC} PRIVATE ${UHDR_WERROR_FLAGS})
  if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
    target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${log-lib})
  endif()
  target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${PRIVATE_LINK_LIBS})
  target_include_directories(${UHDR_TARGET_NAME_STATIC} PUBLIC ${EXPORT_INCLUDE_DIR})
  combine_static_libs(${UHDR_CORE_LIB_NAME} ${UHDR_TARGET_NAME_STATIC})
  if(NOT MSVC)
    set_target_properties(${UHDR_TARGET_NAME_STATIC}
                          PROPERTIES OUTPUT_NAME ${UHDR_TARGET_NAME})
  endif()
endif()

if(UHDR_BUILD_JAVA)
  include(UseJava)

  set(UHDR_JNI_TARGET_NAME uhdrjni)
  add_library(${UHDR_JNI_TARGET_NAME} SHARED ${UHDR_JNI_SRCS_LIST})
  add_dependencies(${UHDR_JNI_TARGET_NAME} ${UHDR_TARGET_NAME})
  target_include_directories(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_JNI_INCLUDE_PATH} ${EXPORT_INCLUDE_DIR})
  target_compile_options(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
  target_link_libraries(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_TARGET_NAME})

  add_jar(uhdr-java SOURCES ${UHDR_JAVA_SRCS_LIST} ${UHDR_APP_SRC} ENTRY_POINT UltraHdrApp)
endif()

if(UHDR_ENABLE_INSTALL)
  if(NOT(MSVC OR XCODE))
    include(GNUInstallDirs)

    # pkg-config: libuhdr.pc
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/libuhdr.pc.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc" @ONLY NEWLINE_STYLE UNIX)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    install(TARGETS ${UHDR_TARGET_NAME} ${UHDR_TARGET_NAME_STATIC} ${UHDR_SAMPLE_APP}
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
    if(BUILD_SHARED_LIBS)
      if(APPLE)
        install(CODE "message(STATUS \"You may need to add path \"
                                     \"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/ \"
                                     \"to DYLD_FALLBACK_LIBRARY_PATH if binaries are unable to load uhdr library \n\"
                                     \"e.g. export DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH:${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/ \")")
      elseif(UNIX)
        install(CODE "message(STATUS \"You may need to add path \"
                                     \"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/ \"
                                     \"to LD_LIBRARY_PATH if binaries are unable to load uhdr library \n\"
                                     \"e.g. export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/ \")")
      endif()
    endif()

    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)
    add_custom_target(uninstall
      COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

    # packaging
    if(UHDR_BUILD_PACKAGING)
      include(cmake/package.cmake)
      include(CPack)
    endif()

  endif()
endif()
