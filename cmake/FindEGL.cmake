#
# Copyright (C) 2024 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.
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
