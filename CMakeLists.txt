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

cmake_minimum_required(VERSION 3.13)

project(UltraHdr C CXX)

###########################################################
# Detect system
###########################################################
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
elseif(WIN32)
elseif(APPLE)
else()
  message(FATAL_ERROR "Platform not supported")
endif()

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm" OR CMAKE_SYSTEM_PROCESSOR MATCHES "aarch")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "aarch64")
  else()
    set(ARCH "arm")
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^mips.*")
  message(FATAL_ERROR "Architecture not supported")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^ppc.*")
  message(FATAL_ERROR "Architecture not supported")
else()
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH "x86_64")
  else()
    set(ARCH "x86")
  endif()
endif()

###########################################################
# Directories
###########################################################
set(SOURCE_DIR ${CMAKE_SOURCE_DIR}/lib)
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)
set(TESTS_DIR ${CMAKE_SOURCE_DIR}/tests)
set(FUZZERS_DIR ${CMAKE_SOURCE_DIR}/fuzzer)
set(EXAMPLES_DIR ${CMAKE_SOURCE_DIR}/examples)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
  message(WARNING "Selected in-source build. Preferably, create a build/ directory and build from there.")
endif()

###########################################################
# Options
###########################################################
get_cmake_property(IS_MULTI GENERATOR_IS_MULTI_CONFIG)
if (NOT IS_MULTI)
  if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type chosen, selecting Release")
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "The type of build: Debug Release MinSizeRel RelWithDebInfo." FORCE)
  endif()
endif()

function(option_if_not_defined name description default)
  if(NOT DEFINED ${name})
    option(${name} ${description} ${default})
  endif()
endfunction()

option_if_not_defined(UHDR_BUILD_EXAMPLES "Build examples " TRUE)
option_if_not_defined(UHDR_BUILD_TESTS "Build unit tests " FALSE)
option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzzers " FALSE)
option_if_not_defined(UHDR_ENABLE_LOGS "Build with verbose logging " FALSE)

###########################################################
# Compile flags
###########################################################
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  if(DEFINED UHDR_SANITIZE_OPTIONS)
    message(FATAL_ERROR "Building with Sanitizer options not supported in MSVC path")
  endif()
  if(UHDR_BUILD_FUZZERS)
    message(FATAL_ERROR "Building fuzzers not supported in MSVC path")
  endif()
  add_compile_options($<$<CONFIG:>:/MT>
    $<$<CONFIG:Debug>:/MTd>
    $<$<CONFIG:MinSizeRel>:/MT>
    $<$<CONFIG:Release>:/MT>
    $<$<CONFIG:RelWithDebInfo>:/MT>)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  # Disable specific warnings
  # TODO: None of these should be disabled, but for now,for a warning-free msvc build these are
  # added. fix the warnings and remove these filters
  add_compile_options(/wd4244) # conversion from 'type1' to 'type2', possible loss of data
  add_compile_options(/wd4267) # conversion from 'size_t' to 'type' possible loss of data
  add_compile_options(/wd4305) # truncation from 'double' to 'float'
  add_compile_options(/wd4838) # conversion from 'type1' to 'type2' requires a narrowing conversion
else()
  add_compile_options(-ffunction-sections)
  add_compile_options(-fdata-sections)
  add_compile_options(-fomit-frame-pointer)
  if(ARCH STREQUAL "x86")
    add_compile_options(-m32)
    add_compile_options(-march=pentium4)
    add_compile_options(-mtune=generic)
  endif()
  if(ARCH STREQUAL "x86_64")
    add_compile_options(-m64)
    add_compile_options(-march=x86-64)
    add_compile_options(-mtune=generic)
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
endif()

if(UHDR_ENABLE_LOGS)
  add_compile_options(-DLOG_NDEBUG)
endif()

###########################################################
# Dependencies
###########################################################

# Threads
set(CMAKE_THREAD_PREFER_PTHREAD ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ImageIO
add_subdirectory("${THIRD_PARTY_DIR}/image_io")

include(ExternalProject)

get_directory_property(UHDR_COMPILE_FLAGS COMPILE_OPTIONS)
string (REPLACE ";" " " UHDR_COMPILE_FLAGS_STR "${UHDR_COMPILE_FLAGS}")
set(UHDR_CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${UHDR_COMPILE_FLAGS_STR}")
set(UHDR_CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${UHDR_COMPILE_FLAGS_STR}")

# libjpeg-turbo
ExternalProject_Add(libjpeg-turbo
    GIT_REPOSITORY https://github.com/libjpeg-turbo/libjpeg-turbo.git
    GIT_TAG 3.0.1
    PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libjpeg-turbo
    SOURCE_DIR ${THIRD_PARTY_DIR}/libjpeg-turbo
    BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target jpeg-static
    CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
               -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
               -DCMAKE_C_FLAGS=${UHDR_CMAKE_C_FLAGS}
    INSTALL_COMMAND ""
)
set(JPEG_INCLUDE_DIRS
    ${THIRD_PARTY_DIR}/libjpeg-turbo/
    ${CMAKE_CURRENT_BINARY_DIR}/libjpeg-turbo/src/libjpeg-turbo-build)

if(IS_MULTI)
  set(JPEG_LIBRARIES
      ${CMAKE_CURRENT_BINARY_DIR}/libjpeg-turbo/src/libjpeg-turbo-build/$<CONFIG>/jpeg-static.lib)
else()
  set(JPEG_LIBRARIES
      ${CMAKE_CURRENT_BINARY_DIR}/libjpeg-turbo/src/libjpeg-turbo-build/libjpeg.a)
endif()

if(UHDR_BUILD_TESTS)
  # gtest and gmock
  ExternalProject_Add(googletest
      GIT_REPOSITORY https://github.com/google/googletest
      GIT_TAG v1.14.0
      PREFIX ${CMAKE_CURRENT_BINARY_DIR}/googletest
      SOURCE_DIR ${THIRD_PARTY_DIR}/googletest
      CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                 -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                 -DCMAKE_C_FLAGS=${UHDR_CMAKE_C_FLAGS}
                 -DCMAKE_CXX_FLAGS=${UHDR_CMAKE_CXX_FLAGS}
      INSTALL_COMMAND ""
  )
  set(GTEST_INCLUDE_DIRS
      ${THIRD_PARTY_DIR}/googletest/googletest/include
      ${THIRD_PARTY_DIR}/googletest/googlemock/include)
  if(IS_MULTI)
    set(GTEST_BOTH_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/googletest/src/googletest-build/lib/$<CONFIG>/gtest.lib
        ${CMAKE_CURRENT_BINARY_DIR}/googletest/src/googletest-build/lib/$<CONFIG>/gtest_main.lib)
  else()
    set(GTEST_BOTH_LIBRARIES
        ${CMAKE_CURRENT_BINARY_DIR}/googletest/src/googletest-build/lib/libgtest.a
        ${CMAKE_CURRENT_BINARY_DIR}/googletest/src/googletest-build/lib/libgtest_main.a)
  endif()
endif()

set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/libjpeg-turbo/src/libjpeg-turbo-build
    ${CMAKE_CURRENT_BINARY_DIR}/googletest/src/googletest-build)

###########################################################
# File Lists
###########################################################
file(GLOB UHDR_LIB_LIST "${SOURCE_DIR}/*.cpp")
file(GLOB UHDR_TEST_LIST "${TESTS_DIR}/*.cpp")
set(COMMON_INCLUDE_LIST ${SOURCE_DIR} ${JPEG_INCLUDE_DIRS})
set(COMMON_LIBS_LIST ${JPEG_LIBRARIES} Threads::Threads)

###########################################################
# Targets
###########################################################
add_library(ultrahdr STATIC ${UHDR_LIB_LIST})
add_dependencies(ultrahdr libjpeg-turbo)
#target_compile_options(ultrahdr PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(ultrahdr PRIVATE
  ${COMMON_INCLUDE_LIST}
  "${THIRD_PARTY_DIR}/image_io/includes/"
)
target_link_libraries(ultrahdr PRIVATE ${COMMON_LIBS_LIST} image_io)

if(UHDR_BUILD_EXAMPLES)
  add_executable(ultrahdr_app "${EXAMPLES_DIR}/ultrahdr_app.cpp")
  add_dependencies(ultrahdr_app ultrahdr)
  target_include_directories(ultrahdr_app PRIVATE ${COMMON_INCLUDE_LIST})
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_app PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_app PRIVATE ultrahdr)
endif()

if(UHDR_BUILD_TESTS)
  include(CTest)
  add_executable(ultrahdr_unit_test ${UHDR_TEST_LIST})
  add_dependencies(ultrahdr_unit_test googletest ultrahdr)
  target_include_directories(ultrahdr_unit_test PRIVATE
    ${COMMON_INCLUDE_LIST}
    ${GTEST_INCLUDE_DIRS}
  )
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_unit_test PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_unit_test ultrahdr ${GTEST_BOTH_LIBRARIES})
  if(WIN32)
    file(COPY "${TESTS_DIR}/data/" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/data")
  else()
    execute_process(COMMAND cmake -E create_symlink
      "${TESTS_DIR}/data/"
      "${CMAKE_CURRENT_BINARY_DIR}/data"
    )
  endif()
  add_test(NAME UHDRUnitTests, COMMAND ultrahdr_unit_test)
endif()

if(UHDR_BUILD_FUZZERS)
  add_executable(ultrahdr_enc_fuzzer ${FUZZERS_DIR}/ultrahdr_enc_fuzzer.cpp)
  add_dependencies(ultrahdr_enc_fuzzer ultrahdr)
  target_include_directories(ultrahdr_enc_fuzzer PRIVATE ${COMMON_INCLUDE_LIST})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_enc_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_enc_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_enc_fuzzer ultrahdr)

  add_executable(ultrahdr_dec_fuzzer ${FUZZERS_DIR}/ultrahdr_dec_fuzzer.cpp)
  add_dependencies(ultrahdr_dec_fuzzer ultrahdr)
  target_include_directories(ultrahdr_dec_fuzzer PRIVATE ${COMMON_INCLUDE_LIST})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_dec_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_dec_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_dec_fuzzer ultrahdr)
endif()
