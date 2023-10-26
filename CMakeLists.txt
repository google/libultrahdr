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

project(ULTRAHDR)

if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, defaulting to release")
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

set(ULTRAHDR_VERSION_MAJOR 1)
set(ULTRAHDR_VERSION_MINOR 0)
set(ULTRAHDR_VERSION_PATCH 0)
set(ULTRAHDR_VERSION ${ULTRAHDR_VERSION_MAJOR}.${ULTRAHDR_VERSION_MINOR}.${ULTRAHDR_VERSION_PATCH})

option(ENABLE_FUZZERS "Enable building fuzzer apps" OFF)
# Add -fuzzer-no-link to sanitize argument if fuzzer build is enabled
if(${ENABLE_FUZZERS})
  message(STATUS "Building fuzzer applications enabled")
  if(DEFINED SANITIZE)
    set(SANITIZE "${SANITIZE},fuzzer-no-link")
  else()
    set(SANITIZE "fuzzer-no-link")
  endif()
else()
  message(STATUS "Building fuzzer applications disabled")
endif()

option(ENABLE_TESTS "Enable unit tests" OFF)
if(${ENABLE_TESTS})
  message(STATUS "Building unit tests enabled")
  include(CTest)
else()
  message(STATUS "Building unit tests disabled")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_THREAD_PREFER_PTHREAD ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

include("${SRC_DIR}/utils.cmake")

libultrahdr_add_compile_options()

ADD_SUBDIRECTORY("${SRC_DIR}/third_party/cmake/image_io")

include(ExternalProject)

function(fetch_libjpegturbo)
  ExternalProject_Add(libjpeg-turbo
      GIT_REPOSITORY https://github.com/libjpeg-turbo/libjpeg-turbo.git
      GIT_TAG 3.0.1
      PREFIX ${SRC_DIR}/third_party/build/libjpeg-turbo
      SOURCE_DIR ${SRC_DIR}/third_party/libjpeg-turbo
      TMP_DIR ${SRC_DIR}/third_party/build/libjpeg-turbo/tmp
      BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target jpeg-static
      CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      INSTALL_COMMAND ""
  )
  set(JPEG_INCLUDE_DIRS
      ${SRC_DIR}/third_party/libjpeg-turbo/
      ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build PARENT_SCOPE)
  set(JPEG_LIBRARIES
      ${SRC_DIR}/third_party/build/libjpeg-turbo/src/libjpeg-turbo-build/libjpeg.a PARENT_SCOPE)
endfunction()

function(fetch_googletest)
  ExternalProject_Add(googletest
      GIT_REPOSITORY https://github.com/google/googletest
      GIT_TAG v1.13.0
      PREFIX ${SRC_DIR}/third_party/build/googletest
      SOURCE_DIR ${SRC_DIR}/third_party/googletest
      TMP_DIR ${SRC_DIR}/third_party/build/googletest/tmp
      CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                 -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      INSTALL_COMMAND ""
  )
  set(GTEST_INCLUDE_DIRS
      ${SRC_DIR}/third_party/googletest/googletest/include
      ${SRC_DIR}/third_party/googletest/googlemock/include PARENT_SCOPE)
  set(GTEST_BOTH_LIBRARIES
      ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgtest.a
      ${SRC_DIR}/third_party/build/googletest/src/googletest-build/lib/libgtest_main.a PARENT_SCOPE)
endfunction()

fetch_libjpegturbo()

if(${ENABLE_TESTS})
  find_package(GTest)
  if(NOT GTest_FOUND)
    fetch_googletest()
  endif()
endif()

add_library(ultrahdr STATIC
  "${SRC_DIR}/gainmapmath.cpp"
  "${SRC_DIR}/icc.cpp"
  "${SRC_DIR}/jpegr.cpp"
  "${SRC_DIR}/jpegrutils.cpp"
  "${SRC_DIR}/jpegencoderhelper.cpp"
  "${SRC_DIR}/jpegdecoderhelper.cpp"
  "${SRC_DIR}/multipictureformat.cpp"
)
add_dependencies(ultrahdr libjpeg-turbo)

target_include_directories(ultrahdr PRIVATE
  ${JPEG_INCLUDE_DIRS}
  "${SRC_DIR}/include"
  "${SRC_DIR}/third_party/image_io/includes/"
)

target_link_libraries(ultrahdr PRIVATE
  ${JPEG_LIBRARIES}
  image_io
  Threads::Threads
)

libultrahdr_add_executable(ultrahdr_app
  ultrahdr
  SOURCES
    "${SRC_DIR}/tests/ultrahdr_app.cpp"
  INCLUDES
    ${JPEG_INCLUDE_DIRS}
    "${SRC_DIR}/include"
)
add_dependencies(ultrahdr_app libjpeg-turbo)

if (${ENABLE_FUZZERS})
  libultrahdr_add_fuzzer(ultrahdr_enc_fuzzer ultrahdr
    SOURCES
      ${SRC_DIR}/fuzzer/ultrahdr_enc_fuzzer.cpp
    INCLUDES
      ${JPEG_INCLUDE_DIRS}
      "${SRC_DIR}/include"
  )
  add_dependencies(ultrahdr_enc_fuzzer libjpeg-turbo)

  libultrahdr_add_fuzzer(ultrahdr_dec_fuzzer ultrahdr
    SOURCES
      ${SRC_DIR}/fuzzer/ultrahdr_dec_fuzzer.cpp
    INCLUDES
      ${JPEG_INCLUDE_DIRS}
      "${SRC_DIR}/include"
  )
  add_dependencies(ultrahdr_dec_fuzzer libjpeg-turbo)
endif()

if(${ENABLE_TESTS})
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
      ${JPEG_INCLUDE_DIRS}
      ${GTEST_INCLUDE_DIRS}
      "${SRC_DIR}/include"
  )
  if(GTest_FOUND)
    add_dependencies(ultrahdr_unit_test libjpeg-turbo)
  else()
    add_dependencies(ultrahdr_unit_test googletest libjpeg-turbo)
  endif()

  target_link_libraries(ultrahdr_unit_test ${GTEST_BOTH_LIBRARIES})

  execute_process(COMMAND cmake -E create_symlink
    "${SRC_DIR}/third_party/data/"
    "${CMAKE_CURRENT_BINARY_DIR}/data"
  )

  add_test(NAME UltraHdrUnitTests, COMMAND ultrahdr_unit_test)
endif()
