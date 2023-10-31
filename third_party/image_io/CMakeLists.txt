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

project(ImageIO CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB IMAGE_IO_LIST "${SOURCE_DIR}/src/**/*.cc")

add_library(image_io STATIC ${IMAGE_IO_LIST})

target_include_directories(image_io PRIVATE
  "${SOURCE_DIR}/includes"
  "${SOURCE_DIR}/src/modp_b64"
  "${SOURCE_DIR}/src/modp_b64/modp_b64")
