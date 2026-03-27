#
# Copyright (C) 2024 The Android Open Source Project
#
# This project is dual-licensed under Apache 2.0 and MIT terms.
# See LICENSE-APACHE and LICENSE-MIT for details.
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
