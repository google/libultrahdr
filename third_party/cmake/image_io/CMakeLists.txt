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

project(IMAGE_IO VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)

set(IMAGE_IO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../image_io")

file(GLOB IMAGE_IO_SRC "${IMAGE_IO_DIR}/src/**/*.cc")

add_library(image_io STATIC
    ${IMAGE_IO_SRC}
)

# Set include directories for the target
target_include_directories(image_io PRIVATE
    "${IMAGE_IO_DIR}/includes"
    "${IMAGE_IO_DIR}/src/modp_b64"
    "${IMAGE_IO_DIR}/src/modp_b64/modp_b64"
)
