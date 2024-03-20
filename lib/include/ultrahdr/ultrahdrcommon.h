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

#ifndef ULTRAHDR_ULTRAHDRCOMMON_H
#define ULTRAHDR_ULTRAHDRCOMMON_H

//#define LOG_NDEBUG 0

#include <map>
#include <memory>
#include <vector>

#include "ultrahdr_api.h"

// ===============================================================================================
// Function Macros
// ===============================================================================================

#ifdef __ANDROID__
#include "log/log.h"
#else
#ifdef LOG_NDEBUG
#include <cstdio>

#define ALOGD(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)
#define ALOGE(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)
#define ALOGI(...)                \
  do {                            \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n");        \
  } while (0)
#define ALOGV(...)                \
  do {                            \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n");        \
  } while (0)
#define ALOGW(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)
#else
#define ALOGD(...) ((void)0)
#define ALOGE(...) ((void)0)
#define ALOGI(...) ((void)0)
#define ALOGV(...) ((void)0)
#define ALOGW(...) ((void)0)
#endif
#endif

#define ALIGNM(x, m) ((((x) + ((m)-1)) / (m)) * (m))

namespace ultrahdr {

// ===============================================================================================
// Structure Definitions
// ===============================================================================================

/**\brief uhdr memory block */
typedef struct uhdr_memory_block {
  uhdr_memory_block(size_t capacity);

  std::unique_ptr<uint8_t[]> m_buffer; /**< data */
  size_t m_capacity;                   /**< capacity */
} uhdr_memory_block_t;                 /**< alias for struct uhdr_memory_block */

/**\brief extended raw image descriptor */
typedef struct uhdr_raw_image_ext : uhdr_raw_image_t {
  uhdr_raw_image_ext(uhdr_img_fmt_t fmt, uhdr_color_gamut_t cg, uhdr_color_transfer_t ct,
                     uhdr_color_range_t range, unsigned w, unsigned h, unsigned align_stride_to);

 private:
  std::unique_ptr<ultrahdr::uhdr_memory_block> m_block;
} uhdr_raw_image_ext_t; /**< alias for struct uhdr_raw_image_ext */

/**\brief extended compressed image descriptor */
typedef struct uhdr_compressed_image_ext : uhdr_compressed_image_t {
  uhdr_compressed_image_ext(uhdr_color_gamut_t cg, uhdr_color_transfer_t ct,
                            uhdr_color_range_t range, unsigned sz);

 private:
  std::unique_ptr<ultrahdr::uhdr_memory_block> m_block;
} uhdr_compressed_image_ext_t; /**< alias for struct uhdr_compressed_image_ext */

}  // namespace ultrahdr

// ===============================================================================================
// Extensions of ultrahdr api definitions, so outside ultrahdr namespace
// ===============================================================================================

struct uhdr_codec_private {};

struct uhdr_encoder_private : uhdr_codec_private {
  // config data
  std::map<uhdr_img_label, std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t>> m_raw_images;
  std::map<uhdr_img_label, std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t>>
      m_compressed_images;
  std::map<uhdr_img_label, int> m_quality;
  std::vector<uint8_t> m_exif;
  uhdr_gainmap_metadata_t m_metadata;
  uhdr_codec_t m_output_format;

  // internal data
  bool m_sailed;
  std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t> m_compressed_output_buffer;
  uhdr_error_info_t m_encode_call_status;
};

struct uhdr_decoder_private : uhdr_codec_private {
  // config data
  std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t> m_uhdr_compressed_img;
  uhdr_img_fmt_t m_output_fmt;
  uhdr_color_transfer_t m_output_ct;
  float m_output_max_disp_boost;

  // internal data
  bool m_probed;
  bool m_sailed;
  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> m_decoded_img_buffer;
  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> m_gainmap_img_buffer;
  int m_img_wd, m_img_ht;
  int m_gainmap_wd, m_gainmap_ht;
  std::vector<uint8_t> m_exif;
  uhdr_mem_block_t m_exif_block;
  std::vector<uint8_t> m_icc;
  uhdr_mem_block_t m_icc_block;
  std::vector<uint8_t> m_base_xmp;
  std::vector<uint8_t> m_gainmap_xmp;
  uhdr_gainmap_metadata_t m_metadata;
  uhdr_error_info_t m_probe_call_status;
  uhdr_error_info_t m_decode_call_status;
};

#endif  // ULTRAHDR_ULTRAHDRCOMMON_H
