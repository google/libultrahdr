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


