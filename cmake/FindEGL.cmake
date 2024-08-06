#
# Copyright (C) 2024 The Android Open Source Project
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

#
# Finds the EGL library. This module defines:
#
#  EGL_FOUND            - True if EGL library is found, False otherwise
#  EGL_LIBRARIES        - EGL library
#  EGL_INCLUDE_DIRS     - Include dir
#

find_path(EGL_INCLUDE_DIRS EGL/egl.h)

find_library(EGL_LIBRARIES NAMES EGL libEGL)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(EGL DEFAULT_MSG EGL_INCLUDE_DIRS EGL_LIBRARIES)

mark_as_advanced(EGL_INCLUDE_DIRS EGL_LIBRARIES)
