#
# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.
#

if(UHDR_BUILD_CMAKE_TOOLCHAINS_ANDROID_CMAKE_)
  return()
endif()

set(UHDR_BUILD_CMAKE_TOOLCHAINS_ANDROID_CMAKE_ 1)

if(NOT ANDROID_PLATFORM)
  set(ANDROID_PLATFORM android-23)
endif()

# Choose target architecture with:
# -DANDROID_ABI={armeabi-v7a, arm64-v8a, x86, x86_64}
if(NOT ANDROID_ABI)
  set(ANDROID_ABI arm64-v8a)
endif()

# Toolchain files don't have access to cached variables:
# https://gitlab.kitware.com/cmake/cmake/issues/16170. Set an intermediate
# environment variable when loaded the first time.
if(UHDR_ANDROID_NDK_PATH)
  set(ENV{UHDR_ANDROID_NDK_PATH} "${UHDR_ANDROID_NDK_PATH}")
else()
  set(UHDR_ANDROID_NDK_PATH "$ENV{UHDR_ANDROID_NDK_PATH}")
endif()

if(NOT UHDR_ANDROID_NDK_PATH)
  message(FATAL_ERROR "UHDR_ANDROID_NDK_PATH not set.")
  return()
endif()

include("${UHDR_ANDROID_NDK_PATH}/build/cmake/android.toolchain.cmake")

set(CMAKE_SYSTEM_NAME "Android")


