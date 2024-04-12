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

project(libuhdr VERSION 1.0 LANGUAGES C CXX
        DESCRIPTION "Library for encoding and decoding ultrahdr images")

###########################################################
# Detect system
###########################################################
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
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
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
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
option_if_not_defined(UHDR_BUILD_BENCHMARK "Build benchmark " FALSE)
option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzzers " FALSE)
option_if_not_defined(UHDR_BUILD_DEPS "Build deps and not use pre-installed packages " FALSE)
option_if_not_defined(UHDR_ENABLE_LOGS "Build with verbose logging " FALSE)
option_if_not_defined(UHDR_ENABLE_INSTALL "Add install target for ultrahdr package" TRUE)

if(UHDR_BUILD_BENCHMARK AND WIN32)
  message(FATAL_ERROR "Building benchmarks on current platform not supported")
endif()

# side effects
if(UHDR_BUILD_FUZZERS OR UHDR_BUILD_DEPS)
  set(UHDR_ENABLE_INSTALL FALSE) # during fuzz testing dont enable install/uninstall targets
  set(UHDR_BUILD_DEPS TRUE) # for fuzz testing its best to build all dependencies from source.
                            # This is to instrument dependencies libs as well
endif()

if(UHDR_ENABLE_INSTALL)
  set(UHDR_BUILD_FUZZERS FALSE) # dont instrument any code
  set(UHDR_BUILD_DEPS FALSE) # use pre-builts for portability
  set(UHDR_ENABLE_LOGS FALSE) # no verbose logs
endif()

if(EMSCRIPTEN)
  set(UHDR_BUILD_DEPS TRUE) # not using -s USE_LIBJPEG=1, building it ourself
  set(UHDR_ENABLE_INSTALL FALSE) # not providing install/uninstall targets in emscripten builds?
endif()

###########################################################
# Compile flags
###########################################################
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT EMSCRIPTEN)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
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

if(MSVC)
  if(DEFINED UHDR_SANITIZE_OPTIONS)
    message(FATAL_ERROR "Building with Sanitizer options not supported in MSVC path")
  endif()
  if(UHDR_BUILD_FUZZERS)
    message(FATAL_ERROR "Building fuzzers not supported in MSVC path")
  endif()
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
  if(UHDR_BUILD_TESTS)
    message(FATAL_ERROR "Building tests not supported in Web Assembly Path")
  endif()
  if(UHDR_BUILD_BENCHMARK)
    message(FATAL_ERROR "Building benchmark not supported in Web Assembly Path")
  endif()
  if(UHDR_BUILD_FUZZERS)
    message(FATAL_ERROR "Building fuzzers not supported in Web Assembly Path")
  endif()
  if(DEFINED UHDR_SANITIZE_OPTIONS)
    CheckCompilerOption("-fsanitize=${UHDR_SANITIZE_OPTIONS}" SUPPORTS_SAN_OPTIONS)
    add_compile_options(-fsanitize=${UHDR_SANITIZE_OPTIONS})
    add_link_options(-fsanitize=${UHDR_SANITIZE_OPTIONS})
  endif()
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
list(APPEND UHDR_CMAKE_ARGS -DCMAKE_POSITION_INDEPENDENT_CODE=ON)
if(MSVC AND UHDR_BUILD_TESTS)
  list(APPEND UHDR_CMAKE_ARGS "-Dgtest_force_shared_crt=ON")
endif()

# libjpeg-turbo
if(UHDR_ENABLE_INSTALL)
  find_package(JPEG REQUIRED)
else()
  if(NOT UHDR_BUILD_DEPS)
    find_package(JPEG)
  endif()
endif()

if(NOT JPEG_FOUND)
  set(JPEGTURBO_TARGET_NAME turbojpeg)
  set(JPEGTURBO_PREFIX_DIR ${CMAKE_CURRENT_BINARY_DIR}/${JPEGTURBO_TARGET_NAME})
  set(JPEGTURBO_SOURCE_DIR ${THIRD_PARTY_DIR}/${JPEGTURBO_TARGET_NAME})
  set(JPEGTURBO_BINARY_DIR ${JPEGTURBO_PREFIX_DIR}/src/${JPEGTURBO_TARGET_NAME}-build)
  set(JPEG_INCLUDE_DIRS ${JPEGTURBO_SOURCE_DIR} ${JPEGTURBO_BINARY_DIR})
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
        GIT_TAG 3.0.1
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
        GIT_TAG 3.0.1
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
file(GLOB UHDR_TEST_SRCS_LIST "${TESTS_DIR}/*.cpp")
file(GLOB UHDR_BM_SRCS_LIST "${BENCHMARK_DIR}/*.cpp")
file(GLOB IMAGE_IO_SRCS_LIST "${THIRD_PARTY_DIR}/image_io/src/**/*.cc")

set(PRIVATE_INCLUDE_DIR ${SOURCE_DIR}/include/ ${JPEG_INCLUDE_DIRS})
set(COMMON_LIBS_LIST ${JPEG_LIBRARIES} Threads::Threads)

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
if(NOT JPEG_FOUND)
  add_dependencies(${UHDR_CORE_LIB_NAME} ${JPEGTURBO_TARGET_NAME})
endif()
#target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE -Wall -Wextra -Wpedantic)
target_include_directories(${UHDR_CORE_LIB_NAME} PRIVATE
  ${PRIVATE_INCLUDE_DIR}
  "${THIRD_PARTY_DIR}/image_io/includes/"
)
target_include_directories(${UHDR_CORE_LIB_NAME} PUBLIC ${EXPORT_INCLUDE_DIR})
target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${COMMON_LIBS_LIST} ${IMAGEIO_TARGET_NAME})

if(UHDR_BUILD_EXAMPLES)
  add_executable(ultrahdr_app "${EXAMPLES_DIR}/ultrahdr_app.cpp")
  add_dependencies(ultrahdr_app ${UHDR_CORE_LIB_NAME})
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_app PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_app PRIVATE ${UHDR_CORE_LIB_NAME})
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
  target_include_directories(ultrahdr_bm PRIVATE
    ${PRIVATE_INCLUDE_DIR}
    ${BENCHMARK_INCLUDE_DIR}
  )
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_bm PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_bm ${UHDR_CORE_LIB_NAME} ${BENCHMARK_LIBRARIES})

  set(RES_FILE "${TESTS_DIR}/data/UltrahdrBenchmarkTestRes-1.0.zip")
  set(RES_FILE_MD5SUM "96651c5c07505c37aa017c57f480e6c1")
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
    set(RES_URL "https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.0.zip")
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
  target_include_directories(ultrahdr_enc_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_enc_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_enc_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_enc_fuzzer ${UHDR_CORE_LIB_NAME})

  add_executable(ultrahdr_dec_fuzzer ${FUZZERS_DIR}/ultrahdr_dec_fuzzer.cpp)
  add_dependencies(ultrahdr_dec_fuzzer ${UHDR_CORE_LIB_NAME})
  target_include_directories(ultrahdr_dec_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
  if(DEFINED ENV{LIB_FUZZING_ENGINE})
    target_link_options(ultrahdr_dec_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
  else()
    target_link_options(ultrahdr_dec_fuzzer PRIVATE -fsanitize=fuzzer)
  endif()
  target_link_libraries(ultrahdr_dec_fuzzer ${UHDR_CORE_LIB_NAME})
endif()

if(UHDR_ENABLE_INSTALL)
  set(UHDR_TARGET_NAME uhdr)
  add_library(${UHDR_TARGET_NAME} SHARED)
  add_dependencies(${UHDR_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
  target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${JPEG_LIBRARIES})
  set_target_properties(${UHDR_TARGET_NAME} PROPERTIES PUBLIC_HEADER ultrahdr_api.h)
  combine_static_libs(${UHDR_CORE_LIB_NAME} ${UHDR_TARGET_NAME})

  if(NOT(WIN32 OR XCODE))
    include(GNUInstallDirs)

    # pkg-config: libuhdr.pc
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/libuhdr.pc.template"
                   "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc" @ONLY NEWLINE_STYLE UNIX)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc"
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
    install(TARGETS ${UHDR_TARGET_NAME}
            DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

    add_custom_target(uninstall)
    add_custom_command(TARGET uninstall
      POST_BUILD
      COMMAND xargs rm -vf < install_manifest.txt)
  endif()
endif()
