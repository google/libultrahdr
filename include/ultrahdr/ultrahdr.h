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

#ifndef ANDROID_ULTRAHDR_ULTRAHDR_H
#define ANDROID_ULTRAHDR_ULTRAHDR_H

namespace android::ultrahdr {
// Color gamuts for image data
typedef enum {
  ULTRAHDR_COLORGAMUT_UNSPECIFIED = -1,
  ULTRAHDR_COLORGAMUT_BT709,
  ULTRAHDR_COLORGAMUT_P3,
  ULTRAHDR_COLORGAMUT_BT2100,
  ULTRAHDR_COLORGAMUT_MAX = ULTRAHDR_COLORGAMUT_BT2100,
} ultrahdr_color_gamut;

// Transfer functions for image data
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
  ULTRAHDR_OUTPUT_SDR,          // SDR in RGBA_8888 color format
  ULTRAHDR_OUTPUT_HDR_LINEAR,   // HDR in F16 color format (linear)
  ULTRAHDR_OUTPUT_HDR_PQ,       // HDR in RGBA_1010102 color format (PQ transfer function)
  ULTRAHDR_OUTPUT_HDR_HLG,      // HDR in RGBA_1010102 color format (HLG transfer function)
  ULTRAHDR_OUTPUT_MAX = ULTRAHDR_OUTPUT_HDR_HLG,
} ultrahdr_output_format;

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

}  // namespace android::ultrahdr

#endif //ANDROID_ULTRAHDR_ULTRAHDR_H
