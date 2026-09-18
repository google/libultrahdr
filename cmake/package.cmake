#
# Copyright (C) 2024 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.
#

# common package configuration
set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "Google, Inc.")
set(CPACK_PACKAGE_CONTACT "Dichen Zhang <dichenzhang@google.com>")
set(CPACK_PACKAGE_VERSION_MAJOR ${UHDR_MAJOR_VERSION})
set(CPACK_PACKAGE_VERSION_MINOR ${UHDR_MINOR_VERSION})
set(CPACK_PACKAGE_VERSION_PATCH ${UHDR_PATCH_VERSION})
set(CPACK_PACKAGE_VERSION "${UHDR_MAJOR_VERSION}.${UHDR_MINOR_VERSION}.${UHDR_PATCH_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_SOURCE_DIR}/DESCRIPTION)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${CMAKE_PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/google/libultrahdr")
if("${CMAKE_SYSTEM_NAME}" STREQUAL "")
  message(FATAL_ERROR "Failed to determine CPACK_SYSTEM_NAME. Is CMAKE_SYSTEM_NAME set?" )
endif()
string(TOLOWER "${CMAKE_SYSTEM_NAME}" CPACK_SYSTEM_NAME)
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_SYSTEM_NAME}")
set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_SOURCE_DIR}/LICENSE)
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# platform specific configuration
if(APPLE)
  set(CPACK_GENERATOR "DragNDrop")
elseif(UNIX)
  if(EXISTS "/etc/debian_version")
    set(CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
    set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE ${CPACK_PACKAGE_HOMEPAGE_URL})
  elseif(EXISTS "/etc/redhat-release")
    set(CPACK_GENERATOR "RPM")
    set(CPACK_RPM_PACKAGE_RELEASE 1)
    set(CPACK_RPM_PACKAGE_LICENSE "Apache 2.0")
    set(CPACK_RPM_PACKAGE_URL ${CPACK_PACKAGE_HOMEPAGE_URL})
  else()
    set(CPACK_GENERATOR "TGZ")
  endif()
else()
  set(CPACK_GENERATOR "ZIP")
endif()
