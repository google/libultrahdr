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
# Finds the libde265 library. This module defines:
#
#  LIBDE265_FOUND            - True if libde265 is found, False otherwise
#  LIBDE265_LIBRARIES        - libde265 library
#  LIBDE265_INCLUDE_DIRS     - Include dir
#

find_path(LIBDE265_INCLUDE_DIRS libde265/de265.h)

find_library(LIBDE265_LIBRARIES NAMES libde265 de265)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBDE265 DEFAULT_MSG LIBDE265_INCLUDE_DIRS LIBDE265_LIBRARIES)

mark_as_advanced(LIBDE265_INCLUDE_DIRS LIBDE265_LIBRARIES)
