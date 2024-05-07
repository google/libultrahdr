/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ULTRAHDR_ULTRAHDR_H
#define ULTRAHDR_ULTRAHDR_H

#include <string>

namespace ultrahdr {

// The current JPEGR version that we encode to
static const char* const kGainMapVersion = "1.0";

// TODO (dichenzhang): rename these to "ULTRAHDR".
typedef enum {
  JPEGR_NO_ERROR = 0,
  JPEGR_UNKNOWN_ERROR = -1,

  JPEGR_IO_ERROR_BASE = -10000,
  ERROR_JPEGR_BAD_PTR = JPEGR_IO_ERROR_BASE - 1,
  ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT = JPEGR_IO_ERROR_BASE - 2,
  ERROR_JPEGR_INVALID_COLORGAMUT = JPEGR_IO_ERROR_BASE - 3,
  ERROR_JPEGR_INVALID_STRIDE = JPEGR_IO_ERROR_BASE - 4,
  ERROR_JPEGR_INVALID_TRANS_FUNC = JPEGR_IO_ERROR_BASE - 5,
  ERROR_JPEGR_RESOLUTION_MISMATCH = JPEGR_IO_ERROR_BASE - 6,
  ERROR_JPEGR_INVALID_QUALITY_FACTOR = JPEGR_IO_ERROR_BASE - 7,
  ERROR_JPEGR_INVALID_DISPLAY_BOOST = JPEGR_IO_ERROR_BASE - 8,
  ERROR_JPEGR_INVALID_OUTPUT_FORMAT = JPEGR_IO_ERROR_BASE - 9,
  ERROR_JPEGR_BAD_METADATA = JPEGR_IO_ERROR_BASE - 10,
  ERROR_JPEGR_INVALID_CROPPING_PARAMETERS = JPEGR_IO_ERROR_BASE - 11,

  JPEGR_RUNTIME_ERROR_BASE = -20000,
  ERROR_JPEGR_ENCODE_ERROR = JPEGR_RUNTIME_ERROR_BASE - 1,
  ERROR_JPEGR_DECODE_ERROR = JPEGR_RUNTIME_ERROR_BASE - 2,
  ERROR_JPEGR_GAIN_MAP_IMAGE_NOT_FOUND = JPEGR_RUNTIME_ERROR_BASE - 3,
  ERROR_JPEGR_BUFFER_TOO_SMALL = JPEGR_RUNTIME_ERROR_BASE - 4,
  ERROR_JPEGR_METADATA_ERROR = JPEGR_RUNTIME_ERROR_BASE - 5,
  ERROR_JPEGR_NO_IMAGES_FOUND = JPEGR_RUNTIME_ERROR_BASE - 6,
  ERROR_JPEGR_MULTIPLE_EXIFS_RECEIVED = JPEGR_RUNTIME_ERROR_BASE - 7,
  ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR = JPEGR_RUNTIME_ERROR_BASE - 8,

  ERROR_JPEGR_UNSUPPORTED_FEATURE = -30000,
} status_t;

// Color gamuts for image data
typedef enum {
  ULTRAHDR_COLORGAMUT_UNSPECIFIED = -1,
  ULTRAHDR_COLORGAMUT_BT709,
  ULTRAHDR_COLORGAMUT_P3,
  ULTRAHDR_COLORGAMUT_BT2100,
  ULTRAHDR_COLORGAMUT_MAX = ULTRAHDR_COLORGAMUT_BT2100,
} ultrahdr_color_gamut;

// Transfer functions for image data
// TODO: TF LINEAR is deprecated, remove this enum and the code surrounding it.
typedef enum {
  ULTRAHDR_TF_UNSPECIFIED = -1,
  ULTRAHDR_TF_LINEAR = 0,
  ULTRAHDR_TF_HLG = 1,
  ULTRAHDR_TF_PQ = 2,
  ULTRAHDR_TF_SRGB = 3,
  ULTRAHDR_TF_MAX = ULTRAHDR_TF_SRGB,
} ultrahdr_transfer_function;

// Target output formats for decoder
typedef enum {
  ULTRAHDR_OUTPUT_UNSPECIFIED = -1,
  ULTRAHDR_OUTPUT_SDR,         // SDR in RGBA_8888 color format
  ULTRAHDR_OUTPUT_HDR_LINEAR,  // HDR in F16 color format (linear)
  ULTRAHDR_OUTPUT_HDR_PQ,      // HDR in RGBA_1010102 color format (PQ transfer function)
  ULTRAHDR_OUTPUT_HDR_HLG,     // HDR in RGBA_1010102 color format (HLG transfer function)
  ULTRAHDR_OUTPUT_MAX = ULTRAHDR_OUTPUT_HDR_HLG,
} ultrahdr_output_format;

// Supported pixel format
typedef enum {
  ULTRAHDR_PIX_FMT_UNSPECIFIED = -1,
  ULTRAHDR_PIX_FMT_P010,
  ULTRAHDR_PIX_FMT_YUV420,
  ULTRAHDR_PIX_FMT_MONOCHROME,
  ULTRAHDR_PIX_FMT_RGBA8888,
  ULTRAHDR_PIX_FMT_RGBAF16,
  ULTRAHDR_PIX_FMT_RGBA1010102,
} ultrahdr_pixel_format;

/*
 * Holds information for gain map related metadata.
 *
 * Not: all values stored in linear. This differs from the metadata encoding in XMP, where
 * maxContentBoost (aka gainMapMax), minContentBoost (aka gainMapMin), hdrCapacityMin, and
 * hdrCapacityMax are stored in log2 space.
 */
struct ultrahdr_metadata_struct {
  // Ultra HDR format version
  std::string version;
  // Max Content Boost for the map
  float maxContentBoost;
  // Min Content Boost for the map
  float minContentBoost;
  // Gamma of the map data
  float gamma;
  // Offset for SDR data in map calculations
  float offsetSdr;
  // Offset for HDR data in map calculations
  float offsetHdr;
  // HDR capacity to apply the map at all
  float hdrCapacityMin;
  // HDR capacity to apply the map completely
  float hdrCapacityMax;
};
typedef struct ultrahdr_metadata_struct* ultrahdr_metadata_ptr;

}  // namespace ultrahdr

#endif  // ULTRAHDR_ULTRAHDR_H
