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

cmake_minimum_required(VERSION 3.4.1)

project(IMAGE_IO VERSION 1.0.0)

# Check the target architecture and set compiler flags accordingly
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
    # 64-bit architecture
    message("Building for 64-bit architecture")
    #set(CMAKE_ANDROID_ARCH_ABI x86_64)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -m64")
else()
    # 32-bit architecture
    message("Building for 32-bit architecture")
    #set(CMAKE_ANDROID_ARCH_ABI x86)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -m32")
endif()
#set(CMAKE_C_FLAGS "-Wall -Werror -Wextra -Wstrict-prototypes -Wmissing-prototypes -Waggregate-return -Wcast-align -Wnested-externs -Wshadow -Wundef -Wmissing-declarations -Winline ${CMAKE_C_FLAGS}")

set(IMAGE_IO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../image_io")

file(GLOB IMAGE_IO_SRC "${IMAGE_IO_DIR}/src/**/*.cc")

add_library(image_io STATIC
    ${IMAGE_IO_SRC}
)

set_target_properties(image_io PROPERTIES COMPILE_FLAGS -std=c++17)

# Set include directories for the target
target_include_directories(image_io PRIVATE
    "${IMAGE_IO_DIR}/includes"
    "${IMAGE_IO_DIR}/src/modp_b64"
    "${IMAGE_IO_DIR}/src/modp_b64/modp_b64"
)
