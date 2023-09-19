include(CheckCXXCompilerFlag)
# cmake-format: off
# Adds a target for an executable
#
# Arguments:
# NAME: Name of the executatble
# LIB: Library that executable depends on
# SOURCES: Source files
#
# Optional Arguments:
# INCLUDES: Include paths
# LIBS: Additional libraries
# FUZZER: flag to specify if the target is a fuzzer binary
# cmake-format: on

# Adds compiler options for all targets
function(libultrahdr_add_compile_options)
  if(DEFINED SANITIZE)
    set(CMAKE_REQUIRED_FLAGS -fsanitize=${SANITIZE})
    check_cxx_compiler_flag(-fsanitize=${SANITIZE} COMPILER_HAS_SANITIZER)
    unset(CMAKE_REQUIRED_FLAGS)

    if(NOT COMPILER_HAS_SANITIZER)
      message(
        FATAL_ERROR "ERROR: Compiler doesn't support -fsanitize=${SANITIZE}")
      return()
    endif()
    add_compile_options(-fno-omit-frame-pointer -fsanitize=${SANITIZE})
  endif()

endfunction()

function(libultrahdr_add_executable NAME LIB)
  set(multi_value_args SOURCES INCLUDES LIBS)
  set(optional_args FUZZER)
  cmake_parse_arguments(ARG "${optional_args}" "${single_value_args}"
                        "${multi_value_args}" ${ARGN})

  # Check if compiler supports -fsanitize=fuzzer. If not, skip building fuzzer
  # binary
  if(ARG_FUZZER)
    set(CMAKE_REQUIRED_FLAGS -fsanitize=fuzzer-no-link)
    check_cxx_compiler_flag(-fsanitize=fuzzer-no-link
                          COMPILER_HAS_SANITIZE_FUZZER)
    unset(CMAKE_REQUIRED_FLAGS)
    if(NOT COMPILER_HAS_SANITIZE_FUZZER)
      message("Compiler doesn't support -fsanitize=fuzzer. Skipping ${NAME}")
      return()
    endif()
  endif()

  add_executable(${NAME} ${ARG_SOURCES})
  target_include_directories(${NAME} PRIVATE ${ARG_INCLUDES})
  add_dependencies(${NAME} ${LIB} ${ARG_LIBS})

  target_link_libraries(${NAME} ${LIB} ${ARG_LIBS})
  if(ARG_FUZZER)
    if(DEFINED ENV{LIB_FUZZING_ENGINE})
      set_target_properties(${NAME} PROPERTIES LINK_FLAGS
                                               $ENV{LIB_FUZZING_ENGINE})
    elseif(DEFINED SANITIZE)
      set_target_properties(${NAME} PROPERTIES LINK_FLAGS
                                               -fsanitize=fuzzer,${SANITIZE})
    else()
      set_target_properties(${NAME} PROPERTIES LINK_FLAGS -fsanitize=fuzzer)
    endif()
  else()
    if(DEFINED SANITIZE)
      set_target_properties(${NAME} PROPERTIES LINK_FLAGS
                                               -fsanitize=${SANITIZE})
    endif()
  endif()
endfunction()

# cmake-format: off
# Adds a target for a fuzzer binary
# Calls libultrahdr_add_executable with all arguments with FUZZER set to 1
# Arguments:
# Refer to libultrahdr_add_executable's arguments
# cmake-format: on

function(libultrahdr_add_fuzzer NAME LIB)
  libultrahdr_add_executable(${NAME} ${LIB} FUZZER 1 ${ARGV})
endfunction()
