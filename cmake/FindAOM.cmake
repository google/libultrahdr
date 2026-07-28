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
# Finds the AOM Codec library. This module defines:
#
#  AOM_FOUND            - True if AOM Codec is found, False otherwise
#  AOM_LIBRARIES        - AOM Codec library
#  AOM_INCLUDE_DIRS     - Include dir
#

find_path(AOM_INCLUDE_DIRS aom/aom.h)

find_library(AOM_LIBRARIES NAMES aom)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(AOM DEFAULT_MSG AOM_INCLUDE_DIRS AOM_LIBRARIES)

mark_as_advanced(AOM_INCLUDE_DIRS AOM_LIBRARIES)
