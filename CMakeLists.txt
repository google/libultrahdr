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
set(BENCHMARK_DIR ${CMAKE_SOURCE_DIR}/benchmark)
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
option_if_not_defined(UHDR_BUILD_BENCHMARK "Build benchmark " FALSE)
option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzzers " FALSE)
option_if_not_defined(UHDR_ENABLE_LOGS "Build with verbose logging " FALSE)
option_if_not_defined(UHDR_BUILD_ALWAYS "Build all deps and not use pre-installed packages " FALSE)

if(UHDR_BUILD_BENCHMARK AND WIN32)
  message(FATAL_ERROR "Building benchmarks on current platform not supported")
endif()

if(UHDR_BUILD_FUZZERS)
  message(STATUS "Enforcing UHDR_BUILD_ALWAYS to TRUE")
  set(UHDR_BUILD_ALWAYS TRUE)
endif()

###########################################################
# Compile flags
###########################################################
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(MSVC)
  if(DEFINED UHDR_SANITIZE_OPTIONS)
    message(FATAL_ERROR "Building with Sanitizer options not supported in MSVC path")
  endif()
  if(UHDR_BUILD_FUZZERS)
    message(FATAL_ERROR "Building fuzzers not supported in MSVC path")
  endif()
  foreach(flag_var
          CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
          CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
          CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
          CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
    if(${flag_var} MATCHES "/MD")
      string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif()
    if (${flag_var} MATCHES "/MDd")
      string(REGEX REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
    endif()
  endforeach()
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  # Disable specific warnings
  # TODO: None of these should be disabled, but for now,for a warning-free msvc build these are
  # added. fix the warnings and remove these filters
  add_compile_options(/wd4244) # conversion from 'type1' to 'type2', possible loss of data
  add_compile_options(/wd4267) # conversion from 'size_t' to 'type' possible loss of data
  add_compile_options(/wd4305) # truncation from 'double' to 'float'
  add_compile_options(/wd4838) # conversion from 'type1' to 'type2' requires a narrowing conversion
  add_compile_options(/wd26812) # Prefer enum class over enum
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

include(ExternalProject)

get_directory_property(UHDR_COMPILE_FLAGS COMPILE_OPTIONS)
string (REPLACE ";" " " UHDR_COMPILE_FLAGS_STR "${UHDR_COMPILE_FLAGS}")
set(UHDR_CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${UHDR_COMPILE_FLAGS_STR}")
set(UHDR_CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${UHDR_COMPILE_FLAGS_STR}")

# libjpeg-turbo
if(NOT UHDR_BUILD_ALWAYS)
  find_package(JPEG)
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
  ExternalProject_Add(${JPEGTURBO_TARGET_NAME}
      GIT_REPOSITORY https://github.com/libjpeg-turbo/libjpeg-turbo.git
      GIT_TAG 3.0.1
      PREFIX ${JPEGTURBO_PREFIX_DIR}
      SOURCE_DIR ${JPEGTURBO_SOURCE_DIR}
      BINARY_DIR ${JPEGTURBO_BINARY_DIR}
      BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG> --target jpeg-static
      CMAKE_ARGS -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                 -DCMAKE_C_FLAGS=${UHDR_CMAKE_C_FLAGS}
                 -DCMAKE_C_FLAGS_DEBUG=${CMAKE_C_FLAGS_DEBUG}
                 -DCMAKE_C_FLAGS_RELEASE=${CMAKE_C_FLAGS_RELEASE}
                 -DCMAKE_C_FLAGS_MINSIZEREL=${CMAKE_C_FLAGS_MINSIZEREL}
                 -DCMAKE_C_FLAGS_RELWITHDEBINFO=${CMAKE_C_FLAGS_RELWITHDEBINFO}
                 -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                 -DENABLE_SHARED=0
      BUILD_BYPRODUCTS ${JPEG_LIBRARIES}
      INSTALL_COMMAND ""
  )
endif()

if(UHDR_BUILD_TESTS)
  # gtest and gmock
  if(NOT UHDR_BUILD_ALWAYS)
    find_package(GTest)
  endif()
  if (NOT GTest_FOUND)
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
        CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                   -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                   -DCMAKE_CXX_FLAGS=${UHDR_CMAKE_CXX_FLAGS}
                   -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                   -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                   -DCMAKE_CXX_FLAGS_MINSIZEREL=${CMAKE_CXX_FLAGS_MINSIZEREL}
                   -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                   -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        BUILD_BYPRODUCTS ${GTEST_BOTH_LIBRARIES}
        INSTALL_COMMAND ""
    )
  endif()
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
      CMAKE_ARGS -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                 -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                 -DCMAKE_CXX_FLAGS=${UHDR_CMAKE_CXX_FLAGS}
                 -DCMAKE_CXX_FLAGS_DEBUG=${CMAKE_CXX_FLAGS_DEBUG}
                 -DCMAKE_CXX_FLAGS_RELEASE=${CMAKE_CXX_FLAGS_RELEASE}
                 -DCMAKE_CXX_FLAGS_MINSIZEREL=${CMAKE_CXX_FLAGS_MINSIZEREL}
                 -DCMAKE_CXX_FLAGS_RELWITHDEBINFO=${CMAKE_CXX_FLAGS_RELWITHDEBINFO}
                 -DCMAKE_POSITION_INDEPENDENT_CODE=ON
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
file(GLOB UHDR_LIB_LIST "${SOURCE_DIR}/src/*.cpp")
file(GLOB UHDR_TEST_LIST "${TESTS_DIR}/*.cpp")
file(GLOB UHDR_BM_LIST "${BENCHMARK_DIR}/*.cpp")
file(GLOB IMAGE_IO_LIST "${THIRD_PARTY_DIR}/image_io/src/**/*.cc")

set(COMMON_INCLUDE_LIST ${CMAKE_SOURCE_DIR} ${SOURCE_DIR}/include/ ${JPEG_INCLUDE_DIRS})
set(COMMON_LIBS_LIST ${JPEG_LIBRARIES} Threads::Threads)

###########################################################
# Targets
###########################################################
add_library(image_io STATIC ${IMAGE_IO_LIST})
target_include_directories(image_io PRIVATE
  "${THIRD_PARTY_DIR}/image_io/includes"
  "${THIRD_PARTY_DIR}/image_io/src/modp_b64"
  "${THIRD_PARTY_DIR}/image_io/src/modp_b64/modp_b64")

add_library(ultrahdr STATIC ${UHDR_LIB_LIST})
if(NOT JPEG_FOUND)
  add_dependencies(ultrahdr ${JPEGTURBO_TARGET_NAME})
endif()
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
  add_executable(ultrahdr_unit_test ${UHDR_TEST_LIST})
  if(NOT GTest_FOUND)
    add_dependencies(ultrahdr_unit_test ${GTEST_TARGET_NAME} ultrahdr)
  else()
    add_dependencies(ultrahdr_unit_test ultrahdr)
  endif()
  target_include_directories(ultrahdr_unit_test PRIVATE
    ${COMMON_INCLUDE_LIST}
    ${GTEST_INCLUDE_DIRS}
  )
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_unit_test PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_unit_test ultrahdr ${GTEST_BOTH_LIBRARIES})
  add_test(NAME UHDRUnitTests, COMMAND ultrahdr_unit_test)
endif()

if(UHDR_BUILD_BENCHMARK)
  add_executable(ultrahdr_bm ${UHDR_BM_LIST})
  add_dependencies(ultrahdr_bm ${BM_TARGET_NAME} ultrahdr)
  target_include_directories(ultrahdr_bm PRIVATE
    ${COMMON_INCLUDE_LIST}
    ${BENCHMARK_INCLUDE_DIR}
  )
  if(UHDR_BUILD_FUZZERS)
    target_link_options(ultrahdr_bm PRIVATE -fsanitize=fuzzer-no-link)
  endif()
  target_link_libraries(ultrahdr_bm ultrahdr ${BENCHMARK_LIBRARIES})

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

###########################################################
# Utils
###########################################################
# combine a list of static libraries in to a single library
# hassle due to ExternalProject_Add(). Else we could get transitive libs for
# each target and rely on target_sources(${new_target} PRIVATE $<TARGET_OBJECTS:${lib}>)
# to combine libraries
function(combine_static_libs output_lib list_of_targets list_of_addl_libs)
  set(OUT_LIB ${CMAKE_STATIC_LIBRARY_PREFIX}${output_lib}${CMAKE_STATIC_LIBRARY_SUFFIX})
  if(IS_MULTI)
    set(OUTPUT_LIB_PATH ${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/${OUT_LIB})
    set(MOCK_FILE ${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/${output_lib}.dummy.cpp)
  else()
    set(OUTPUT_LIB_PATH ${CMAKE_CURRENT_BINARY_DIR}/${OUT_LIB})
    set(MOCK_FILE ${CMAKE_CURRENT_BINARY_DIR}/${output_lib}.dummy.cpp)
  endif()
  if(MSVC OR APPLE)
    if(MSVC)
      find_program(lib_tool lib)
    else()
      find_program(lib_tool libtool)
    endif()
    if(NOT lib_tool)
      message(WARNING "lib_tool not found! skipping combine archives")
      return()
    endif()
    foreach(tgt ${list_of_targets})
      get_target_property(target_type ${tgt} TYPE)
      if(target_type STREQUAL "STATIC_LIBRARY")
        list(APPEND list_of_static_libs $<TARGET_FILE:${tgt}>)
      endif()
    endforeach()
    foreach(lib ${list_of_addl_libs})
      list(FIND list_of_static_libs ${lib} res)
      if(res EQUAL -1)
        list(APPEND list_of_static_libs ${lib})
      endif()
    endforeach()

    # Create a dummy file for the combined library
    # Have it depend on all input targets so that the combined library is regenerated
    # if any of them changes.
    add_custom_command(OUTPUT ${MOCK_FILE}
      COMMAND echo // Auto Generated, for target ${output_lib} > ${MOCK_FILE}
      DEPENDS "${list_of_targets}" "${list_of_addl_libs}")

    add_library(${output_lib} STATIC ${MOCK_FILE})

    # Add a custom command to combine the archives after the static library is "built".
    if(MSVC)
      add_custom_command(TARGET ${output_lib}
        POST_BUILD
        COMMAND ${lib_tool} /NOLOGO /OUT:${OUTPUT_LIB_PATH} ${list_of_static_libs})
    else()
      add_custom_command(TARGET ${output_lib}
        POST_BUILD
        COMMAND ${lib_tool} -static -o ${OUTPUT_LIB_PATH} ${list_of_static_libs})
    endif()
  else()
    # Generate the MRI file for CMAKE_AR to consume.
    if(IS_MULTI)
      set(MRI_FILE ${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/${output_lib}.mri)
    else()
      set(MRI_FILE ${CMAKE_CURRENT_BINARY_DIR}/${output_lib}.mri)
    endif()
    set(MRI_CONTENT "CREATE ${OUTPUT_LIB_PATH}\n")
    foreach(tgt ${list_of_targets})
      get_target_property(target_type ${tgt} TYPE)
      if(target_type STREQUAL "STATIC_LIBRARY")
        string(APPEND MRI_CONTENT "ADDLIB $<TARGET_FILE:${tgt}>\n")
      endif()
    endforeach()
    foreach(lib ${list_of_addl_libs})
      string(FIND ${MRI_CONTENT} "ADDLIB ${lib}\n" res)
      if(res EQUAL -1)
        string(APPEND MRI_CONTENT "ADDLIB ${lib}\n")
      endif()
    endforeach()
    string(APPEND MRI_CONTENT "SAVE\n")
    string(APPEND MRI_CONTENT "END\n")
    file(GENERATE OUTPUT ${MRI_FILE} CONTENT ${MRI_CONTENT})

    # Create a dummy file for the combined library
    # Have it depend on all input targets so that the combined library is regenerated
    # if any of them changes.
    add_custom_command(OUTPUT ${MOCK_FILE}
      COMMAND echo // Auto Generated, for target ${output_lib} > ${MOCK_FILE}
      DEPENDS "${list_of_targets}" "${list_of_addl_libs}")

    add_library(${output_lib} STATIC ${MOCK_FILE})

    # Add a custom command to combine the archives after the static library is "built".
    add_custom_command(TARGET ${output_lib}
      POST_BUILD
      COMMAND ${CMAKE_AR} -M < ${MRI_FILE})
  endif()
endfunction()

if(UHDR_BUILD_ALWAYS)
  set(INPUT_TARGETS ultrahdr image_io ${JPEGTURBO_TARGET_NAME})
  set(ADDL_LIBS ${JPEG_LIBRARIES})
else()
  set(INPUT_TARGETS ultrahdr image_io)
  set(ADDL_LIBS "")
endif()

combine_static_libs(uhdr "${INPUT_TARGETS}" "${ADDL_LIBS}")
