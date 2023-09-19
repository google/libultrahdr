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

cmake_minimum_required(VERSION 3.5)

project(ULTRAHDR VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)

include(ExternalProject)

# Check the target architecture and set compiler flags accordingly
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    # 64-bit architecture
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -m64")
else()
    # 32-bit architecture
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -m32")
endif()

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

include("${SRC_DIR}/utils.cmake")
libultrahdr_add_compile_options()

ADD_SUBDIRECTORY("${SRC_DIR}/third_party/cmake/image_io")

ExternalProject_Add(libjpeg-turbo
    GIT_REPOSITORY https://github.com/libjpeg-turbo/libjpeg-turbo.git
    GIT_TAG main
    PREFIX ${SRC_DIR}/third_party/build/libjpeg-turbo
    SOURCE_DIR ${SRC_DIR}/third_party/libjpeg-turbo
    TMP_DIR ${SRC_DIR}/third_party/build/libjpeg-turbo/tmp
    INSTALL_COMMAND ""
)

ExternalProject_Add(googletest
    GIT_REPOSITORY https://android.googlesource.com/platform/external/googletest
    GIT_TAG main
    PREFIX ${SRC_DIR}/third_party/build/googletest
    SOURCE_DIR ${SRC_DIR}/third_party/googletest
    TMP_DIR ${SRC_DIR}/third_party/build/googletest/tmp
    INSTALL_COMMAND ""
)

add_library(ultrahdr STATIC
    "${SRC_DIR}/gainmapmath.cpp"
    "${SRC_DIR}/icc.cpp"
    "${SRC_DIR}/jpegr.cpp"
    "${SRC_DIR}/jpegrutils.cpp"
    "${SRC_DIR}/jpegencoderhelper.cpp"
    "${SRC_DIR}/jpegdecoderhelper.cpp"
    "${SRC_DIR}/multipictureformat.cpp"
)

set_target_properties(ultrahdr PROPERTIES COMPILE_FLAGS -std=c++17)

# Set include directories for the target
target_include_directories(ultrahdr PRIVATE
    "${SRC_DIR}/include"
    "${SRC_DIR}/third_party/libjpeg-turbo/"
    "${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build"
    "${SRC_DIR}/third_party/image_io/includes/"
)

target_link_libraries(ultrahdr PRIVATE
    ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build/libjpeg.a
    image_io
)

libultrahdr_add_executable(ultrahdr_unit_test
    ultrahdr
    SOURCES
        "${SRC_DIR}/tests/jpegr_test.cpp"
        "${SRC_DIR}/tests/gainmapmath_test.cpp"
        "${SRC_DIR}/tests/icchelper_test.cpp"
        "${SRC_DIR}/tests/jpegencoderhelper_test.cpp"
        "${SRC_DIR}/tests/jpegdecoderhelper_test.cpp"
        "${SRC_DIR}/tests/icchelper_test.cpp"
    INCLUDES
        "${SRC_DIR}/include"
        "${SRC_DIR}/third_party/googletest/googletest/include"
        "${SRC_DIR}/third_party/googletest/googlemock/include"
        "${SRC_DIR}/third_party/libjpeg-turbo/"
        "${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build"
)

libultrahdr_add_executable(ultrahdr_app
    ultrahdr
    SOURCES
        "${SRC_DIR}/tests/ultrahdr_app.cpp"
    INCLUDES
        "${SRC_DIR}/include"
        "${SRC_DIR}/third_party/libjpeg-turbo/"
        "${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build"
)

target_link_libraries(ultrahdr_unit_test
    ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgmock.a
    ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgtest.a
    ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgtest_main.a
)

libultrahdr_add_fuzzer(ultrahdr_enc_fuzzer ultrahdr
    SOURCES
        ${SRC_DIR}/fuzzer/ultrahdr_enc_fuzzer.cpp
    INCLUDES
        ${SRC_DIR}/include
        ${SRC_DIR}/third_party/libjpeg-turbo/
        ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build
)

libultrahdr_add_fuzzer(ultrahdr_dec_fuzzer ultrahdr
    SOURCES
        ${SRC_DIR}/fuzzer/ultrahdr_dec_fuzzer.cpp
    INCLUDES
        ${SRC_DIR}/include
        ${SRC_DIR}/third_party/libjpeg-turbo/
        ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build
)
