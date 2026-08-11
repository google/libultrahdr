# cmake/Findlibheif.cmake
#
# Finds the libheif library and provides the imported target libheif::heif.
#
# Imported Targets:
#   libheif::heif - Target representing the libheif library
#
# Result Variables:
#   LIBHEIF_FOUND             - True if libheif was found
#   LIBHEIF_HAS_GAIN_MAP      - True if libheif includes ISO 21496-1 gain map APIs
#   LIBHEIF_VERSION           - Version of libheif found
#   LIBHEIF_INCLUDE_DIRS      - Include directories for libheif
#   LIBHEIF_LIBRARIES         - Libraries needed to link against libheif

include(CheckCXXSymbolExists)
include(FindPackageHandleStandardArgs)

set(LIBHEIF_TARGET "")

# -----------------------------------------------------------------------------
# 1. Primary Method: Modern CMake CONFIG Mode (libheifConfig.cmake)
# -----------------------------------------------------------------------------
find_package(libheif CONFIG QUIET)
if(libheif_FOUND OR LIBHEIF_FOUND)
  if(TARGET libheif::heif)
    set(LIBHEIF_TARGET libheif::heif)
  elseif(TARGET heif)
    set(LIBHEIF_TARGET heif)
    if(NOT TARGET libheif::heif)
      add_library(libheif::heif ALIAS heif)
    endif()
  endif()
  if(libheif_VERSION)
    set(LIBHEIF_VERSION ${libheif_VERSION})
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
      set(LIBHEIF_INCLUDE_DIRS ${PC_LIBHEIF_INCLUDE_DIRS})
      set(LIBHEIF_LIBRARIES ${PC_LIBHEIF_LIBRARIES})
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
        INTERFACE_LINK_LIBRARIES "${CMAKE_DL_LIBS}"
      )
    endif()
    set(LIBHEIF_TARGET libheif::heif)
    set(LIBHEIF_INCLUDE_DIRS "${LIBHEIF_INCLUDE_DIR}")
    set(LIBHEIF_LIBRARIES "${LIBHEIF_LIBRARY}")
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
  if(LIBHEIF_DEFS)
    set(CMAKE_REQUIRED_DEFINITIONS "-D${LIBHEIF_DEFS}")
  endif()

  # Perform a compile-only check to avoid linking transitive dependencies
  # (e.g. AOM::aom, x265) of static libheif targets in the try_compile sandbox.
  set(_saved_try_compile_target_type ${CMAKE_TRY_COMPILE_TARGET_TYPE})
  set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

  check_cxx_symbol_exists(
    heif_image_handle_get_gain_map_image_handle
    "libheif/heif.h"
    LIBHEIF_HAS_GAIN_MAP
  )

  set(CMAKE_TRY_COMPILE_TARGET_TYPE ${_saved_try_compile_target_type})
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_DEFINITIONS)
endif()

# -----------------------------------------------------------------------------
# Standard Package Handler
# -----------------------------------------------------------------------------
find_package_handle_standard_args(libheif
  REQUIRED_VARS LIBHEIF_TARGET
  VERSION_VAR LIBHEIF_VERSION
  FOUND_VAR LIBHEIF_FOUND
)
