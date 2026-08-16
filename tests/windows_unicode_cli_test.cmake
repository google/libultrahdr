# Copyright 2026 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

if(NOT DEFINED UHDR_APP OR NOT DEFINED TEST_INPUT OR NOT DEFINED TEST_OUTPUT_DIR)
  message(FATAL_ERROR "UHDR_APP, TEST_INPUT, and TEST_OUTPUT_DIR are required")
endif()

set(test_dir "${TEST_OUTPUT_DIR}/路径-🌈")
set(input_file "${test_dir}/输入图像.p010")
set(output_file "${test_dir}/输出图像.jpeg")

file(REMOVE_RECURSE "${TEST_OUTPUT_DIR}")
file(MAKE_DIRECTORY "${test_dir}")
configure_file("${TEST_INPUT}" "${input_file}" COPYONLY)

execute_process(
  COMMAND "${UHDR_APP}" -m 0 -p "${input_file}" -w 1280 -h 720 -a 0 -z "${output_file}"
  RESULT_VARIABLE encode_result
  ERROR_VARIABLE encode_error
)
if(NOT encode_result EQUAL 0)
  message(FATAL_ERROR "Unicode-path encode failed: ${encode_error}")
endif()
if(NOT EXISTS "${output_file}")
  message(FATAL_ERROR "Unicode-path encode did not create ${output_file}")
endif()

execute_process(
  COMMAND "${UHDR_APP}" -m 1 -j "${output_file}" -P
  RESULT_VARIABLE probe_result
  ERROR_VARIABLE probe_error
)
if(NOT probe_result EQUAL 0)
  message(FATAL_ERROR "Unicode-path probe failed: ${probe_error}")
endif()
