# cmake/Findlibheif.cmake
#
# Finds the libheif library and provides the imported target libheif::heif.
#
# Imported Targets:
#   libheif::heif - Target representing the libheif library
#
# Result Variables:
#   libheif_FOUND             - True if libheif was found
#   LIBHEIF_HAS_GAIN_MAP      - True if libheif includes ISO 21496-1 gain map APIs
#   LIBHEIF_VERSION           - Version of libheif found

include(CheckCXXSymbolExists)
include(FindPackageHandleStandardArgs)

set(LIBHEIF_TARGET "")

# -----------------------------------------------------------------------------
# 1. Primary Method: Modern CMake CONFIG Mode (libheifConfig.cmake)
# -----------------------------------------------------------------------------
find_package(libheif CONFIG QUIET)
if(libheif_FOUND)
  if(TARGET libheif::heif)
    set(LIBHEIF_TARGET libheif::heif)
  elseif(TARGET heif)
    set(LIBHEIF_TARGET heif)
    if(NOT TARGET libheif::heif)
      add_library(libheif::heif ALIAS heif)
    endif()
  endif()
endif()

# -----------------------------------------------------------------------------
# 2. Secondary Fallback: pkg-config Mode
# -----------------------------------------------------------------------------
if(NOT LIBHEIF_TARGET)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(PC_LIBHEIF QUIET IMPORTED_TARGET libheif)
    if(PC_LIBHEIF_FOUND)
      if(NOT TARGET libheif::heif)
        add_library(libheif::heif ALIAS PkgConfig::PC_LIBHEIF)
      endif()
      set(LIBHEIF_TARGET libheif::heif)
      set(LIBHEIF_VERSION ${PC_LIBHEIF_VERSION})
    endif()
  endif()
endif()

# -----------------------------------------------------------------------------
# 3. Tertiary Fallback: Direct Path and Library Discovery
# -----------------------------------------------------------------------------
if(NOT LIBHEIF_TARGET)
  find_path(LIBHEIF_INCLUDE_DIR NAMES "libheif/heif.h")
  find_library(LIBHEIF_LIBRARY NAMES heif libheif)

  if(LIBHEIF_INCLUDE_DIR AND LIBHEIF_LIBRARY)
    if(NOT TARGET libheif::heif)
      add_library(libheif::heif UNKNOWN IMPORTED)
      set_target_properties(libheif::heif PROPERTIES
        IMPORTED_LOCATION "${LIBHEIF_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBHEIF_INCLUDE_DIR}"
      )
    endif()
    set(LIBHEIF_TARGET libheif::heif)
  endif()
endif()

# -----------------------------------------------------------------------------
# 4. Feature Verification: ISO 21496-1 Gain Map Support
# -----------------------------------------------------------------------------
if(LIBHEIF_TARGET)
  get_target_property(LIBHEIF_INCLUDES ${LIBHEIF_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
  get_target_property(LIBHEIF_DEFS ${LIBHEIF_TARGET} INTERFACE_COMPILE_DEFINITIONS)
  
  set(CMAKE_REQUIRED_INCLUDES "")
  if(LIBHEIF_INCLUDES)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBHEIF_INCLUDES})
  endif()
  if(LIBHEIF_INCLUDE_DIR)
    list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBHEIF_INCLUDE_DIR})
  endif()
  set(CMAKE_REQUIRED_LIBRARIES ${LIBHEIF_TARGET})
  if(LIBHEIF_DEFS)
    set(CMAKE_REQUIRED_DEFINITIONS "-D${LIBHEIF_DEFS}")
  endif()

  check_cxx_symbol_exists(
    heif_image_handle_get_gain_map_image_handle
    "libheif/heif.h"
    LIBHEIF_HAS_GAIN_MAP
  )
endif()

# -----------------------------------------------------------------------------
# Standard Package Handler
# -----------------------------------------------------------------------------
find_package_handle_standard_args(libheif
  REQUIRED_VARS LIBHEIF_TARGET
  VERSION_VAR LIBHEIF_VERSION
)
