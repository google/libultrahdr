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

option(ENABLE_FUZZERS "Enables fuzzers" OFF)

# Add -fuzzer-no-link to sanitize argument if fuzzer build is enabled
if (${ENABLE_FUZZERS})
if(DEFINED SANITIZE)
    set(SANITIZE "${SANITIZE},fuzzer-no-link")
else()
    set(SANITIZE "fuzzer-no-link")
endif()
endif()
set(CMAKE_CXX_STANDARD 17)

include(ExternalProject)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

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
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target jpeg-static
    INSTALL_COMMAND ""
)

set(JPEG_INCLUDE_DIR
    ${SRC_DIR}/third_party/libjpeg-turbo/
    ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build)

set(JPEG_LIBRARIES ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build/libjpeg.a)

ExternalProject_Add(googletest
    GIT_REPOSITORY https://android.googlesource.com/platform/external/googletest
    GIT_TAG main
    PREFIX ${SRC_DIR}/third_party/build/googletest
    SOURCE_DIR ${SRC_DIR}/third_party/googletest
    TMP_DIR ${SRC_DIR}/third_party/build/googletest/tmp
    INSTALL_COMMAND ""
)

set(GTEST_INCLUDE_DIRS
    ${SRC_DIR}/third_party/googletest/googletest/include
    ${SRC_DIR}/third_party/googletest/googlemock/include)

set(GTEST_LIBRARIES
    ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgtest.a
    ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgtest_main.a)

add_library(ultrahdr STATIC
    "${SRC_DIR}/gainmapmath.cpp"
    "${SRC_DIR}/icc.cpp"
    "${SRC_DIR}/jpegr.cpp"
    "${SRC_DIR}/jpegrutils.cpp"
    "${SRC_DIR}/jpegencoderhelper.cpp"
    "${SRC_DIR}/jpegdecoderhelper.cpp"
    "${SRC_DIR}/multipictureformat.cpp"
)

target_include_directories(ultrahdr PRIVATE
    "${SRC_DIR}/include"
    ${JPEG_INCLUDE_DIR}
    "${SRC_DIR}/third_party/image_io/includes/"
)

target_link_libraries(ultrahdr PRIVATE
    ${JPEG_LIBRARIES}
    image_io
    Threads::Threads
)
add_dependencies(ultrahdr libjpeg-turbo)

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
        ${GTEST_INCLUDE_DIRS}
        ${JPEG_INCLUDE_DIR}
)
add_dependencies(ultrahdr_unit_test googletest libjpeg-turbo)

libultrahdr_add_executable(ultrahdr_app
    ultrahdr
    SOURCES
        "${SRC_DIR}/tests/ultrahdr_app.cpp"
    INCLUDES
        "${SRC_DIR}/include"
        ${JPEG_INCLUDE_DIR}
)
add_dependencies(ultrahdr_app googletest libjpeg-turbo)

target_link_libraries(ultrahdr_unit_test ${GTEST_LIBRARIES})

if (${ENABLE_FUZZERS})
libultrahdr_add_fuzzer(ultrahdr_enc_fuzzer ultrahdr
    SOURCES
        ${SRC_DIR}/fuzzer/ultrahdr_enc_fuzzer.cpp
    INCLUDES
        ${SRC_DIR}/include
        ${JPEG_INCLUDE_DIR}
)
add_dependencies(ultrahdr_enc_fuzzer libjpeg-turbo)


libultrahdr_add_fuzzer(ultrahdr_dec_fuzzer ultrahdr
    SOURCES
        ${SRC_DIR}/fuzzer/ultrahdr_dec_fuzzer.cpp
    INCLUDES
        ${SRC_DIR}/include
        ${JPEG_INCLUDE_DIR}
)
add_dependencies(ultrahdr_dec_fuzzer libjpeg-turbo)
endif()
