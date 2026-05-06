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
# Finds the OpenGLES3 library. This module defines:
#
#  OpenGLES3_FOUND            - True if OpenGLES 3 library is found, False otherwise
#  OPENGLES3_LIBRARIES        - OpenGLES3 library
#  OPENGLES3_INCLUDE_DIRS     - Include dir
#  OpenGLES3_API_VERSION      - OpenGLES3 Supported API version
#

find_path(OPENGLES3_INCLUDE_DIRS GLES3/gl3.h)

# Android has separate library for OpenGLES3 in the form GLESv3
# Many platforms support OpenGLES3 via OpenGLES2 lib. In this case, presence of GLES3/gl*.h will be indicative of GLES3 support
find_library(OPENGLES3_LIBRARIES NAMES GLESv3 GLESv2 libGLESv2)

if(OPENGLES3_INCLUDE_DIRS)
  if(EXISTS ${OPENGLES3_INCLUDE_DIRS}/GLES3/gl32.h)
    set(OpenGLES3_API_VERSION "3.2")
  elseif(EXISTS ${OPENGLES3_INCLUDE_DIRS}/GLES3/gl31.h)
    set(OpenGLES3_API_VERSION "3.1")
  else()
    set(OpenGLES3_API_VERSION "3.0")
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(OpenGLES3 OPENGLES3_INCLUDE_DIRS OPENGLES3_LIBRARIES)

mark_as_advanced(OPENGLES3_INCLUDE_DIRS OPENGLES3_LIBRARIES)
