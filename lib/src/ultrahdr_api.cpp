/*
 * Copyright 2024 The Android Open Source Project
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

#include <cstdio>
#include <cstring>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"

static const uhdr_error_info_t g_no_error = {UHDR_CODEC_OK, 0, ""};

namespace ultrahdr {

uhdr_memory_block::uhdr_memory_block(size_t capacity) {
  m_buffer = std::make_unique<uint8_t[]>(capacity);
  m_capacity = capacity;
}

uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt, uhdr_color_gamut_t cg,
                                       uhdr_color_transfer_t ct, uhdr_color_range_t range,
                                       unsigned w, unsigned h, unsigned align_stride_to) {
  this->fmt = fmt;
  this->cg = cg;
  this->ct = ct;
  this->range = range;

  this->w = w;
  this->h = h;

  int aligned_width = ALIGNM(w, align_stride_to);

  int bpp = 1;
  if (fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    bpp = 2;
  } else if (fmt == UHDR_IMG_FMT_32bppRGBA8888 || fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
    bpp = 4;
  } else if (fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    bpp = 8;
  }

  size_t plane_1_sz = bpp * aligned_width * h;
  size_t plane_2_sz;
  size_t plane_3_sz;
  if (fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    plane_2_sz = (2 /* planes */ * ((aligned_width / 2) * (h / 2) * bpp));
    plane_3_sz = 0;
  } else if (fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    plane_2_sz = (((aligned_width / 2) * (h / 2) * bpp));
    plane_3_sz = (((aligned_width / 2) * (h / 2) * bpp));
  } else {
    plane_2_sz = 0;
    plane_3_sz = 0;
  }
  size_t total_size = plane_1_sz + plane_2_sz + plane_3_sz;
  this->m_block = std::make_unique<uhdr_memory_block_t>(total_size);

  uint8_t* data = this->m_block->m_buffer.get();
  this->planes[0] = data;
  this->stride[0] = aligned_width;
  if (fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    this->planes[1] = data + plane_1_sz;
    this->stride[1] = aligned_width;
    this->planes[2] = nullptr;
    this->stride[2] = 0;
  } else if (fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    this->planes[1] = data + plane_1_sz;
    this->stride[1] = aligned_width / 2;
    this->planes[2] = data + plane_1_sz + plane_2_sz;
    this->stride[2] = aligned_width / 2;
  } else {
    this->planes[1] = nullptr;
    this->stride[1] = 0;
    this->planes[2] = nullptr;
    this->stride[2] = 0;
  }
}

uhdr_compressed_image_ext::uhdr_compressed_image_ext(uhdr_color_gamut_t cg,
                                                     uhdr_color_transfer_t ct,
                                                     uhdr_color_range_t range, unsigned size) {
  this->m_block = std::make_unique<uhdr_memory_block_t>(size);
  this->data = this->m_block->m_buffer.get();
  this->capacity = size;
  this->data_sz = 0;
  this->cg = cg;
  this->ct = ct;
  this->range = range;
}

}  // namespace ultrahdr

ultrahdr::ultrahdr_pixel_format map_pix_fmt_to_internal_pix_fmt(uhdr_img_fmt_t fmt) {
  switch (fmt) {
    case UHDR_IMG_FMT_12bppYCbCr420:
      return ultrahdr::ULTRAHDR_PIX_FMT_YUV420;
    case UHDR_IMG_FMT_24bppYCbCrP010:
      return ultrahdr::ULTRAHDR_PIX_FMT_P010;
    case UHDR_IMG_FMT_32bppRGBA1010102:
      return ultrahdr::ULTRAHDR_PIX_FMT_RGBA1010102;
    case UHDR_IMG_FMT_32bppRGBA8888:
      return ultrahdr::ULTRAHDR_PIX_FMT_RGBA8888;
    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
      return ultrahdr::ULTRAHDR_PIX_FMT_RGBAF16;
    case UHDR_IMG_FMT_8bppYCbCr400:
      return ultrahdr::ULTRAHDR_PIX_FMT_MONOCHROME;
    default:
      return ultrahdr::ULTRAHDR_PIX_FMT_UNSPECIFIED;
  }
}

ultrahdr::ultrahdr_color_gamut map_cg_to_internal_cg(uhdr_color_gamut_t cg) {
  switch (cg) {
    case UHDR_CG_BT_2100:
      return ultrahdr::ULTRAHDR_COLORGAMUT_BT2100;
    case UHDR_CG_BT_709:
      return ultrahdr::ULTRAHDR_COLORGAMUT_BT709;
    case UHDR_CG_DISPLAY_P3:
      return ultrahdr::ULTRAHDR_COLORGAMUT_P3;
    default:
      return ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  }
}

uhdr_color_gamut_t map_internal_cg_to_cg(ultrahdr::ultrahdr_color_gamut cg) {
  switch (cg) {
    case ultrahdr::ULTRAHDR_COLORGAMUT_BT2100:
      return UHDR_CG_BT_2100;
    case ultrahdr::ULTRAHDR_COLORGAMUT_BT709:
      return UHDR_CG_BT_709;
    case ultrahdr::ULTRAHDR_COLORGAMUT_P3:
      return UHDR_CG_DISPLAY_P3;
    default:
      return UHDR_CG_UNSPECIFIED;
  }
}

ultrahdr::ultrahdr_transfer_function map_ct_to_internal_ct(uhdr_color_transfer_t ct) {
  switch (ct) {
    case UHDR_CT_HLG:
      return ultrahdr::ULTRAHDR_TF_HLG;
    case UHDR_CT_PQ:
      return ultrahdr::ULTRAHDR_TF_PQ;
    case UHDR_CT_LINEAR:
      return ultrahdr::ULTRAHDR_TF_LINEAR;
    case UHDR_CT_SRGB:
      return ultrahdr::ULTRAHDR_TF_SRGB;
    default:
      return ultrahdr::ULTRAHDR_TF_UNSPECIFIED;
  }
}

ultrahdr::ultrahdr_output_format map_ct_fmt_to_internal_output_fmt(uhdr_color_transfer_t ct,
                                                                   uhdr_img_fmt fmt) {
  if (ct == UHDR_CT_HLG && fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
    return ultrahdr::ULTRAHDR_OUTPUT_HDR_HLG;
  } else if (ct == UHDR_CT_PQ && fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
    return ultrahdr::ULTRAHDR_OUTPUT_HDR_PQ;
  } else if (ct == UHDR_CT_LINEAR && fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    return ultrahdr::ULTRAHDR_OUTPUT_HDR_LINEAR;
  } else if (ct == UHDR_CT_SRGB && fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    return ultrahdr::ULTRAHDR_OUTPUT_SDR;
  }
  return ultrahdr::ULTRAHDR_OUTPUT_UNSPECIFIED;
}

void map_internal_error_status_to_error_info(ultrahdr::status_t internal_status,
                                             uhdr_error_info_t& status) {
  if (internal_status == ultrahdr::JPEGR_NO_ERROR) {
    status = g_no_error;
  } else {
    status.has_detail = 1;
    if (internal_status == ultrahdr::ERROR_JPEGR_RESOLUTION_MISMATCH) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      snprintf(status.detail, sizeof status.detail,
               "dimensions of sdr intent and hdr intent do not match");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_ENCODE_ERROR) {
      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
      snprintf(status.detail, sizeof status.detail, "encountered unknown error during encoding");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_DECODE_ERROR) {
      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
      snprintf(status.detail, sizeof status.detail, "encountered unknown error during decoding");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_NO_IMAGES_FOUND) {
      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
      snprintf(status.detail, sizeof status.detail, "input uhdr image does not any valid images");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_GAIN_MAP_IMAGE_NOT_FOUND) {
      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
      snprintf(status.detail, sizeof status.detail,
               "input uhdr image does not contain gainmap image");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_BUFFER_TOO_SMALL) {
      status.error_code = UHDR_CODEC_MEM_ERROR;
      snprintf(status.detail, sizeof status.detail,
               "output buffer to store compressed data is too small");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_MULTIPLE_EXIFS_RECEIVED) {
      status.error_code = UHDR_CODEC_INVALID_OPERATION;
      snprintf(status.detail, sizeof status.detail,
               "received exif from uhdr_enc_set_exif_data() while the base image intent already "
               "contains exif, unsure which one to use");
    } else if (internal_status == ultrahdr::ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR) {
      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
      snprintf(status.detail, sizeof status.detail,
               "say base image wd to gain map image wd ratio is 'k1' and base image ht to gain map "
               "image ht ratio is 'k2'. Either k1 is fractional or k2 is fractional or k1 != k2. "
               "currently the library does not handle these scenarios");
    } else {
      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
      status.has_detail = 0;
    }
  }
}

uhdr_error_info_t uhdr_enc_validate_and_set_compressed_img(uhdr_codec_private_t* enc,
                                                           uhdr_compressed_image_t* img,
                                                           uhdr_img_label_t intent) {
  uhdr_error_info_t status = g_no_error;

  if (enc == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (img == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for compressed image handle");
  } else if (img->data == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received nullptr for compressed img->data field");
  } else if (img->capacity < img->data_sz) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "img->capacity %d is less than img->data_sz %d",
             img->capacity, img->data_sz);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_encode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  auto entry = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(img->cg, img->ct, img->range,
                                                                       img->data_sz);
  memcpy(entry->data, img->data, img->data_sz);
  entry->data_sz = img->data_sz;
  handle->m_compressed_images.insert_or_assign(intent, std::move(entry));

  return status;
}

uhdr_codec_private_t* uhdr_create_encoder(void) {
  uhdr_encoder_private* handle = new uhdr_encoder_private();

  if (handle != nullptr) {
    uhdr_reset_encoder(handle);
  }
  return handle;
}

void uhdr_release_encoder(uhdr_codec_private_t* enc) {
  if (enc != nullptr) {
    uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
    delete handle;
  }
}

uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_image_t* img,
                                         uhdr_img_label_t intent) {
  uhdr_error_info_t status = g_no_error;

  if (enc == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (img == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for raw image handle");
  } else if (intent != UHDR_HDR_IMG && intent != UHDR_SDR_IMG) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid intent %d, expects one of {UHDR_HDR_IMG, UHDR_SDR_IMG}", intent);
  } else if (img->fmt != UHDR_IMG_FMT_12bppYCbCr420 && img->fmt != UHDR_IMG_FMT_24bppYCbCrP010) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid input pixel format %d, expects one of {UHDR_IMG_FMT_12bppYCbCr420, "
             "UHDR_IMG_FMT_24bppYCbCrP010}",
             img->fmt);
  } else if (img->cg != UHDR_CG_BT_2100 && img->cg != UHDR_CG_DISPLAY_P3 &&
             img->cg != UHDR_CG_BT_709) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid input color gamut %d, expects one of {UHDR_CG_BT_2100, UHDR_CG_DISPLAY_P3, "
             "UHDR_CG_BT_709}",
             img->cg);
  } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420 && img->ct != UHDR_CT_SRGB) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid input color transfer for sdr intent image %d, expects UHDR_CT_SRGB", img->ct);
  } else if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010 &&
             (img->ct != UHDR_CT_HLG && img->ct != UHDR_CT_LINEAR && img->ct != UHDR_CT_PQ)) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid input color transfer for hdr intent image %d, expects one of {UHDR_CT_HLG, "
             "UHDR_CT_LINEAR, UHDR_CT_PQ}",
             img->ct);
  } else if (img->w % 2 != 0 || img->h % 2 != 0) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "image dimensions cannot be odd, received image dimensions %dx%d", img->w, img->h);
  } else if (img->w < ultrahdr::kMinWidth || img->h < ultrahdr::kMinHeight) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "image dimensions cannot be less than %dx%d, received image dimensions %dx%d",
             ultrahdr::kMinWidth, ultrahdr::kMinHeight, img->w, img->h);
  } else if (img->w > ultrahdr::kMaxWidth || img->h > ultrahdr::kMaxHeight) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "image dimensions cannot be larger than %dx%d, received image dimensions %dx%d",
             ultrahdr::kMaxWidth, ultrahdr::kMaxHeight, img->w, img->h);
  } else if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    if (img->planes[UHDR_PLANE_Y] == nullptr || img->planes[UHDR_PLANE_UV] == nullptr) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "received nullptr for data field(s), luma ptr %p, chroma_uv ptr %p",
               img->planes[UHDR_PLANE_Y], img->planes[UHDR_PLANE_UV]);
    } else if (img->stride[UHDR_PLANE_Y] < img->w) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "luma stride must not be smaller than width, stride=%d, width=%d",
               img->stride[UHDR_PLANE_Y], img->w);
    } else if (img->stride[UHDR_PLANE_UV] < img->w) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "chroma_uv stride must not be smaller than width, stride=%d, width=%d",
               img->stride[UHDR_PLANE_UV], img->w);
    }
  } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    if (img->planes[UHDR_PLANE_Y] == nullptr || img->planes[UHDR_PLANE_U] == nullptr ||
        img->planes[UHDR_PLANE_V] == nullptr) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "received nullptr for data field(s) luma ptr %p, chroma_u ptr %p, chroma_v ptr %p",
               img->planes[UHDR_PLANE_Y], img->planes[UHDR_PLANE_U], img->planes[UHDR_PLANE_V]);
    } else if (img->stride[UHDR_PLANE_Y] < img->w) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "luma stride must not be smaller than width, stride=%d, width=%d",
               img->stride[UHDR_PLANE_Y], img->w);
    } else if (img->stride[UHDR_PLANE_U] < img->w / 2) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "chroma_u stride must not be smaller than width / 2, stride=%d, width=%d",
               img->stride[UHDR_PLANE_U], img->w);
    } else if (img->stride[UHDR_PLANE_V] < img->w / 2) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "chroma_v stride must not be smaller than width / 2, stride=%d, width=%d",
               img->stride[UHDR_PLANE_V], img->w);
    }
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  if (intent == UHDR_HDR_IMG &&
      handle->m_raw_images.find(UHDR_SDR_IMG) != handle->m_raw_images.end()) {
    auto& sdr_raw_entry = handle->m_raw_images.find(UHDR_SDR_IMG)->second;
    if (img->w != sdr_raw_entry->w || img->h != sdr_raw_entry->h) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "image resolutions mismatch: hdr intent: %dx%d, sdr intent: %dx%d", img->w, img->h,
               sdr_raw_entry->w, sdr_raw_entry->h);
      return status;
    }
  }
  if (intent == UHDR_SDR_IMG &&
      handle->m_raw_images.find(UHDR_HDR_IMG) != handle->m_raw_images.end()) {
    auto& hdr_raw_entry = handle->m_raw_images.find(UHDR_HDR_IMG)->second;
    if (img->w != hdr_raw_entry->w || img->h != hdr_raw_entry->h) {
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "image resolutions mismatch: sdr intent: %dx%d, hdr intent: %dx%d", img->w, img->h,
               hdr_raw_entry->w, hdr_raw_entry->h);
      return status;
    }
  }
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_encode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> entry =
      std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(img->fmt, img->cg, img->ct, img->range,
                                                       img->w, img->h, 64);

  if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    uint8_t* y_dst = static_cast<uint8_t*>(entry->planes[UHDR_PLANE_Y]);
    uint8_t* y_src = static_cast<uint8_t*>(img->planes[UHDR_PLANE_Y]);
    uint8_t* u_dst = static_cast<uint8_t*>(entry->planes[UHDR_PLANE_U]);
    uint8_t* u_src = static_cast<uint8_t*>(img->planes[UHDR_PLANE_U]);
    uint8_t* v_dst = static_cast<uint8_t*>(entry->planes[UHDR_PLANE_V]);
    uint8_t* v_src = static_cast<uint8_t*>(img->planes[UHDR_PLANE_V]);

    // copy y
    for (size_t i = 0; i < img->h; i++) {
      memcpy(y_dst, y_src, img->w);
      y_dst += entry->stride[UHDR_PLANE_Y];
      y_src += img->stride[UHDR_PLANE_Y];
    }
    // copy cb & cr
    for (size_t i = 0; i < img->h / 2; i++) {
      memcpy(u_dst, u_src, img->w / 2);
      memcpy(v_dst, v_src, img->w / 2);
      u_dst += entry->stride[UHDR_PLANE_U];
      v_dst += entry->stride[UHDR_PLANE_V];
      u_src += img->stride[UHDR_PLANE_U];
      v_src += img->stride[UHDR_PLANE_V];
    }
  } else if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    int bpp = 2;
    uint8_t* y_dst = static_cast<uint8_t*>(entry->planes[UHDR_PLANE_Y]);
    uint8_t* y_src = static_cast<uint8_t*>(img->planes[UHDR_PLANE_Y]);
    uint8_t* uv_dst = static_cast<uint8_t*>(entry->planes[UHDR_PLANE_UV]);
    uint8_t* uv_src = static_cast<uint8_t*>(img->planes[UHDR_PLANE_UV]);

    // copy y
    for (size_t i = 0; i < img->h; i++) {
      memcpy(y_dst, y_src, img->w * bpp);
      y_dst += (entry->stride[UHDR_PLANE_Y] * bpp);
      y_src += (img->stride[UHDR_PLANE_Y] * bpp);
    }
    // copy cbcr
    for (size_t i = 0; i < img->h / 2; i++) {
      memcpy(uv_dst, uv_src, img->w * bpp);
      uv_dst += (entry->stride[UHDR_PLANE_UV] * bpp);
      uv_src += (img->stride[UHDR_PLANE_UV] * bpp);
    }
  }

  handle->m_raw_images.insert_or_assign(intent, std::move(entry));

  return status;
}

uhdr_error_info_t uhdr_enc_set_compressed_image(uhdr_codec_private_t* enc,
                                                uhdr_compressed_image_t* img,
                                                uhdr_img_label_t intent) {
  uhdr_error_info_t status = g_no_error;

  if (intent != UHDR_HDR_IMG && intent != UHDR_SDR_IMG && intent != UHDR_BASE_IMG) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid intent %d, expects one of {UHDR_HDR_IMG, UHDR_SDR_IMG, UHDR_BASE_IMG}",
             intent);
  }

  return uhdr_enc_validate_and_set_compressed_img(enc, img, intent);
}

uhdr_error_info_t uhdr_enc_set_gainmap_image(uhdr_codec_private_t* enc,
                                             uhdr_compressed_image_t* img,
                                             uhdr_gainmap_metadata_t* metadata) {
  uhdr_error_info_t status = g_no_error;

  if (metadata == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received nullptr for gainmap metadata descriptor");
  } else if (metadata->max_content_boost < metadata->min_content_boost) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received bad value for content boost min %f > max %f", metadata->min_content_boost,
             metadata->max_content_boost);
  } else if (metadata->gamma <= 0.0f) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received bad value for gamma %f, expects > 0.0f",
             metadata->gamma);
  } else if (metadata->offset_sdr < 0.0f) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received bad value for offset sdr %f, expects to be >= 0.0f", metadata->offset_sdr);
  } else if (metadata->offset_hdr < 0.0f) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received bad value for offset hdr %f, expects to be >= 0.0f", metadata->offset_hdr);
  } else if (metadata->hdr_capacity_max < metadata->hdr_capacity_min) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received bad value for hdr capacity min %f > max %f", metadata->hdr_capacity_min,
             metadata->hdr_capacity_max);
  } else if (metadata->hdr_capacity_min < 1.0f) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received bad value for hdr capacity min %f, expects to be >= 1.0f",
             metadata->hdr_capacity_min);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  status = uhdr_enc_validate_and_set_compressed_img(enc, img, UHDR_GAIN_MAP_IMG);
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  memcpy(&handle->m_metadata, metadata, sizeof *metadata);

  return status;
}

uhdr_error_info_t uhdr_enc_set_quality(uhdr_codec_private_t* enc, int quality,
                                       uhdr_img_label_t intent) {
  uhdr_error_info_t status = g_no_error;

  if (enc == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (quality < 0 || quality > 100) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid quality factor %d, expects in range [0-100]", quality);
  } else if (intent != UHDR_HDR_IMG && intent != UHDR_SDR_IMG && intent != UHDR_BASE_IMG &&
             intent != UHDR_GAIN_MAP_IMG) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid intent %d, expects one of {UHDR_HDR_IMG, UHDR_SDR_IMG, UHDR_BASE_IMG, "
             "UHDR_GAIN_MAP_IMG}",
             intent);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_encode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  handle->m_quality.insert_or_assign(intent, quality);

  return status;
}

uhdr_error_info_t uhdr_enc_set_exif_data(uhdr_codec_private_t* enc, uhdr_mem_block_t* exif) {
  uhdr_error_info_t status = g_no_error;

  if (enc == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (exif == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for exif image handle");
  } else if (exif->data == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for exif->data field");
  } else if (exif->capacity < exif->data_sz) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "exif->capacity %d is less than exif->data_sz %d",
             exif->capacity, exif->data_sz);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_encode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  uint8_t* data = static_cast<uint8_t*>(exif->data);
  std::vector<uint8_t> entry(data, data + exif->data_sz);
  handle->m_exif = std::move(entry);

  return status;
}

uhdr_error_info_t uhdr_enc_set_output_format(uhdr_codec_private_t* enc, uhdr_codec_t media_type) {
  uhdr_error_info_t status = g_no_error;

  if (enc == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (media_type != UHDR_CODEC_JPG) {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid output format %d, expects {UHDR_CODEC_JPG}", media_type);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_encode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  handle->m_output_format = media_type;

  return status;
}

uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc) {
  if (enc == nullptr) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
    return status;
  }

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);

  if (handle->m_sailed) {
    return handle->m_encode_call_status;
  }

  handle->m_sailed = true;

  uhdr_error_info_t& status = handle->m_encode_call_status;

  ultrahdr::status_t internal_status = ultrahdr::JPEGR_NO_ERROR;
  if (handle->m_output_format == UHDR_CODEC_JPG) {
    ultrahdr::jpegr_exif_struct exif{};
    if (handle->m_exif.size() > 0) {
      exif.data = handle->m_exif.data();
      exif.length = handle->m_exif.size();
    }

    ultrahdr::JpegR jpegr;
    ultrahdr::jpegr_compressed_struct dest{};
    if (handle->m_compressed_images.find(UHDR_BASE_IMG) != handle->m_compressed_images.end() &&
        handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG) != handle->m_compressed_images.end()) {
      auto& base_entry = handle->m_compressed_images.find(UHDR_BASE_IMG)->second;
      ultrahdr::jpegr_compressed_struct primary_image;
      primary_image.data = base_entry->data;
      primary_image.length = primary_image.maxLength = base_entry->data_sz;
      primary_image.colorGamut = map_cg_to_internal_cg(base_entry->cg);

      auto& gainmap_entry = handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG)->second;
      ultrahdr::jpegr_compressed_struct gainmap_image;
      gainmap_image.data = gainmap_entry->data;
      gainmap_image.length = gainmap_image.maxLength = gainmap_entry->data_sz;
      gainmap_image.colorGamut = map_cg_to_internal_cg(gainmap_entry->cg);

      ultrahdr::ultrahdr_metadata_struct metadata;
      metadata.version = ultrahdr::kJpegrVersion;
      metadata.maxContentBoost = handle->m_metadata.max_content_boost;
      metadata.minContentBoost = handle->m_metadata.min_content_boost;
      metadata.gamma = handle->m_metadata.gamma;
      metadata.offsetSdr = handle->m_metadata.offset_sdr;
      metadata.offsetHdr = handle->m_metadata.offset_hdr;
      metadata.hdrCapacityMin = handle->m_metadata.hdr_capacity_min;
      metadata.hdrCapacityMax = handle->m_metadata.hdr_capacity_max;

      size_t size = (std::max)((8 * 1024), 2 * (primary_image.length + gainmap_image.length));
      handle->m_compressed_output_buffer =
          std::move(std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
              UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size));

      dest.data = handle->m_compressed_output_buffer->data;
      dest.length = 0;
      dest.maxLength = handle->m_compressed_output_buffer->capacity;
      dest.colorGamut = ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;

      // api - 4
      internal_status = jpegr.encodeJPEGR(&primary_image, &gainmap_image, &metadata, &dest);
      map_internal_error_status_to_error_info(internal_status, status);
    } else if (handle->m_raw_images.find(UHDR_HDR_IMG) != handle->m_raw_images.end()) {
      auto& hdr_raw_entry = handle->m_raw_images.find(UHDR_HDR_IMG)->second;

      size_t size = (std::max)((8u * 1024), hdr_raw_entry->w * hdr_raw_entry->h * 3 * 2);
      handle->m_compressed_output_buffer =
          std::move(std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
              UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size));

      dest.data = handle->m_compressed_output_buffer->data;
      dest.length = 0;
      dest.maxLength = handle->m_compressed_output_buffer->capacity;
      dest.colorGamut = ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;

      ultrahdr::jpegr_uncompressed_struct p010_image;
      p010_image.data = hdr_raw_entry->planes[UHDR_PLANE_Y];
      p010_image.width = hdr_raw_entry->w;
      p010_image.height = hdr_raw_entry->h;
      p010_image.colorGamut = map_cg_to_internal_cg(hdr_raw_entry->cg);
      p010_image.luma_stride = hdr_raw_entry->stride[UHDR_PLANE_Y];
      p010_image.chroma_data = hdr_raw_entry->planes[UHDR_PLANE_UV];
      p010_image.chroma_stride = hdr_raw_entry->stride[UHDR_PLANE_UV];
      p010_image.pixelFormat = map_pix_fmt_to_internal_pix_fmt(hdr_raw_entry->fmt);

      if (handle->m_compressed_images.find(UHDR_SDR_IMG) == handle->m_compressed_images.end() &&
          handle->m_raw_images.find(UHDR_SDR_IMG) == handle->m_raw_images.end()) {
        // api - 0
        internal_status = jpegr.encodeJPEGR(&p010_image, map_ct_to_internal_ct(hdr_raw_entry->ct),
                                            &dest, handle->m_quality.find(UHDR_BASE_IMG)->second,
                                            handle->m_exif.size() > 0 ? &exif : nullptr);
      } else if (handle->m_compressed_images.find(UHDR_SDR_IMG) !=
                     handle->m_compressed_images.end() &&
                 handle->m_raw_images.find(UHDR_SDR_IMG) == handle->m_raw_images.end()) {
        auto& sdr_compressed_entry = handle->m_compressed_images.find(UHDR_SDR_IMG)->second;
        ultrahdr::jpegr_compressed_struct sdr_compressed_image;
        sdr_compressed_image.data = sdr_compressed_entry->data;
        sdr_compressed_image.length = sdr_compressed_image.maxLength =
            sdr_compressed_entry->data_sz;
        sdr_compressed_image.colorGamut = map_cg_to_internal_cg(sdr_compressed_entry->cg);
        // api - 3
        internal_status = jpegr.encodeJPEGR(&p010_image, &sdr_compressed_image,
                                            map_ct_to_internal_ct(hdr_raw_entry->ct), &dest);
      } else if (handle->m_raw_images.find(UHDR_SDR_IMG) != handle->m_raw_images.end()) {
        auto& sdr_raw_entry = handle->m_raw_images.find(UHDR_SDR_IMG)->second;

        ultrahdr::jpegr_uncompressed_struct yuv420_image;
        yuv420_image.data = sdr_raw_entry->planes[UHDR_PLANE_Y];
        yuv420_image.width = sdr_raw_entry->w;
        yuv420_image.height = sdr_raw_entry->h;
        yuv420_image.colorGamut = map_cg_to_internal_cg(sdr_raw_entry->cg);
        yuv420_image.luma_stride = sdr_raw_entry->stride[UHDR_PLANE_Y];
        yuv420_image.chroma_data = nullptr;
        yuv420_image.chroma_stride = 0;
        yuv420_image.pixelFormat = map_pix_fmt_to_internal_pix_fmt(sdr_raw_entry->fmt);

        if (handle->m_compressed_images.find(UHDR_SDR_IMG) == handle->m_compressed_images.end()) {
          // api - 1
          internal_status = jpegr.encodeJPEGR(&p010_image, &yuv420_image,
                                              map_ct_to_internal_ct(hdr_raw_entry->ct), &dest,
                                              handle->m_quality.find(UHDR_BASE_IMG)->second,
                                              handle->m_exif.size() > 0 ? &exif : nullptr);
        } else {
          auto& sdr_compressed_entry = handle->m_compressed_images.find(UHDR_SDR_IMG)->second;
          ultrahdr::jpegr_compressed_struct sdr_compressed_image;
          sdr_compressed_image.data = sdr_compressed_entry->data;
          sdr_compressed_image.length = sdr_compressed_image.maxLength =
              sdr_compressed_entry->data_sz;
          sdr_compressed_image.colorGamut = map_cg_to_internal_cg(sdr_compressed_entry->cg);

          // api - 2
          internal_status = jpegr.encodeJPEGR(&p010_image, &yuv420_image, &sdr_compressed_image,
                                              map_ct_to_internal_ct(hdr_raw_entry->ct), &dest);
        }
      }
      map_internal_error_status_to_error_info(internal_status, status);
    } else {
      status.error_code = UHDR_CODEC_INVALID_OPERATION;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "resources required for uhdr_encode() operation are not present");
    }
    if (status.error_code == UHDR_CODEC_OK) {
      handle->m_compressed_output_buffer->data_sz = dest.length;
      handle->m_compressed_output_buffer->cg = map_internal_cg_to_cg(dest.colorGamut);
    }
  }

  return status;
}

uhdr_compressed_image_t* uhdr_get_encoded_stream(uhdr_codec_private_t* enc) {
  if (enc == nullptr) {
    return nullptr;
  }

  uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);
  if (!handle->m_sailed || handle->m_encode_call_status.error_code != UHDR_CODEC_OK) {
    return nullptr;
  }

  return handle->m_compressed_output_buffer.get();
}

void uhdr_reset_encoder(uhdr_codec_private_t* enc) {
  if (enc != nullptr) {
    uhdr_encoder_private* handle = reinterpret_cast<uhdr_encoder_private*>(enc);

    // clear entries and restore defaults
    handle->m_raw_images.clear();
    handle->m_compressed_images.clear();
    handle->m_quality.clear();
    handle->m_quality.emplace(UHDR_HDR_IMG, 95);
    handle->m_quality.emplace(UHDR_SDR_IMG, 95);
    handle->m_quality.emplace(UHDR_BASE_IMG, 95);
    handle->m_quality.emplace(UHDR_GAIN_MAP_IMG, 85);
    handle->m_exif.clear();
    handle->m_output_format = UHDR_CODEC_JPG;

    handle->m_sailed = false;
    handle->m_compressed_output_buffer.reset();
    handle->m_encode_call_status = g_no_error;
  }
}

uhdr_codec_private_t* uhdr_create_decoder(void) {
  uhdr_decoder_private* handle = new uhdr_decoder_private();

  if (handle != nullptr) {
    uhdr_reset_decoder(handle);
  }
  return handle;
}

void uhdr_release_decoder(uhdr_codec_private_t* dec) {
  if (dec != nullptr) {
    uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
    delete handle;
  }
}

uhdr_error_info_t uhdr_dec_set_image(uhdr_codec_private_t* dec, uhdr_compressed_image_t* img) {
  uhdr_error_info_t status = g_no_error;

  if (dec == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (img == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for compressed image handle");
  } else if (img->data == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "received nullptr for compressed img->data field");
  } else if (img->capacity < img->data_sz) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "img->capacity %d is less than img->data_sz %d",
             img->capacity, img->data_sz);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_decode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  handle->m_uhdr_compressed_img = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
      img->cg, img->ct, img->range, img->data_sz);
  memcpy(handle->m_uhdr_compressed_img->data, img->data, img->data_sz);
  handle->m_uhdr_compressed_img->data_sz = img->data_sz;

  return status;
}

uhdr_error_info_t uhdr_dec_set_out_img_format(uhdr_codec_private_t* dec, uhdr_img_fmt_t fmt) {
  uhdr_error_info_t status = g_no_error;

  if (dec == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (fmt != UHDR_IMG_FMT_32bppRGBA8888 && fmt != UHDR_IMG_FMT_64bppRGBAHalfFloat &&
             fmt != UHDR_IMG_FMT_32bppRGBA1010102) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid output format %d, expects one of {UHDR_IMG_FMT_32bppRGBA8888,  "
             "UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_IMG_FMT_32bppRGBA1010102}",
             fmt);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_decode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  handle->m_output_fmt = fmt;

  return status;
}

uhdr_error_info_t uhdr_dec_set_out_color_transfer(uhdr_codec_private_t* dec,
                                                  uhdr_color_transfer_t ct) {
  uhdr_error_info_t status = g_no_error;

  if (dec == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (ct != UHDR_CT_HLG && ct != UHDR_CT_PQ && ct != UHDR_CT_LINEAR && ct != UHDR_CT_SRGB) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid output color transfer %d, expects one of {UHDR_CT_HLG, UHDR_CT_PQ, "
             "UHDR_CT_LINEAR, UHDR_CT_SRGB}",
             ct);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_decode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  handle->m_output_ct = ct;

  return status;
}

uhdr_error_info_t uhdr_dec_set_out_max_display_boost(uhdr_codec_private_t* dec,
                                                     float display_boost) {
  uhdr_error_info_t status = g_no_error;

  if (dec == nullptr) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
  } else if (display_boost < 1.0f) {
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "invalid display boost %f, expects to be >= 1.0f}", display_boost);
  }
  if (status.error_code != UHDR_CODEC_OK) return status;

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (handle->m_sailed) {
    status.error_code = UHDR_CODEC_INVALID_OPERATION;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "An earlier call to uhdr_decode() has switched the context from configurable state to "
             "end state. The context is no longer configurable. To reuse, call reset()");
    return status;
  }

  handle->m_output_max_disp_boost = display_boost;

  return status;
}

uhdr_error_info_t uhdr_decode(uhdr_codec_private_t* dec) {
  if (dec == nullptr) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
    return status;
  }

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);

  if (handle->m_sailed) {
    return handle->m_decode_call_status;
  }

  handle->m_sailed = true;

  uhdr_error_info_t& status = handle->m_decode_call_status;
  ultrahdr::jpeg_info_struct primary_image;
  ultrahdr::jpeg_info_struct gainmap_image;
  ultrahdr::jpegr_info_struct jpegr_info;
  jpegr_info.width = 0;
  jpegr_info.height = 0;
  jpegr_info.primaryImgInfo = &primary_image;
  jpegr_info.gainmapImgInfo = &gainmap_image;

  ultrahdr::jpegr_compressed_struct uhdr_image;
  uhdr_image.data = handle->m_uhdr_compressed_img->data;
  uhdr_image.length = uhdr_image.maxLength = handle->m_uhdr_compressed_img->data_sz;
  uhdr_image.colorGamut = map_cg_to_internal_cg(handle->m_uhdr_compressed_img->cg);

  ultrahdr::JpegR jpegr;
  ultrahdr::status_t internal_status = jpegr.getJPEGRInfo(&uhdr_image, &jpegr_info);
  map_internal_error_status_to_error_info(internal_status, status);
  if (status.error_code != UHDR_CODEC_OK) return status;

  handle->m_exif = std::move(primary_image.exifData);
  handle->m_icc = std::move(primary_image.iccData);
  handle->m_base_xmp = std::move(primary_image.xmpData);
  handle->m_gainmap_xmp = std::move(gainmap_image.xmpData);

  handle->m_decoded_img_buffer = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(
      handle->m_output_fmt, UHDR_CG_UNSPECIFIED, handle->m_output_ct, UHDR_CR_UNSPECIFIED,
      primary_image.width, primary_image.height, 1);
  // alias
  ultrahdr::jpegr_uncompressed_struct dest;
  dest.data = handle->m_decoded_img_buffer->planes[UHDR_PLANE_PACKED];
  dest.colorGamut = ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;

  handle->m_gainmap_img_buffer = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(
      UHDR_IMG_FMT_8bppYCbCr400, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED,
      gainmap_image.width, gainmap_image.height, 1);
  // alias
  ultrahdr::jpegr_uncompressed_struct dest_gainmap;
  dest_gainmap.data = handle->m_gainmap_img_buffer->planes[UHDR_PLANE_Y];

  ultrahdr::ultrahdr_metadata_struct metadata;
  internal_status = jpegr.decodeJPEGR(
      &uhdr_image, &dest, handle->m_output_max_disp_boost, nullptr,
      map_ct_fmt_to_internal_output_fmt(handle->m_output_ct, handle->m_output_fmt), &dest_gainmap,
      &metadata);
  map_internal_error_status_to_error_info(internal_status, status);
  if (status.error_code == UHDR_CODEC_OK) {
    handle->m_decoded_img_buffer->cg = map_internal_cg_to_cg(dest.colorGamut);

    handle->m_metadata.max_content_boost = metadata.maxContentBoost;
    handle->m_metadata.min_content_boost = metadata.minContentBoost;
    handle->m_metadata.gamma = metadata.gamma;
    handle->m_metadata.offset_sdr = metadata.offsetSdr;
    handle->m_metadata.offset_hdr = metadata.offsetHdr;
    handle->m_metadata.hdr_capacity_min = metadata.hdrCapacityMin;
    handle->m_metadata.hdr_capacity_max = metadata.hdrCapacityMax;
  }

  return status;
}

uhdr_raw_image_t* uhdr_get_decoded_image(uhdr_codec_private_t* dec) {
  if (dec == nullptr) {
    return nullptr;
  }

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (!handle->m_sailed || handle->m_decode_call_status.error_code != UHDR_CODEC_OK) {
    return nullptr;
  }

  return handle->m_decoded_img_buffer.get();
}

uhdr_raw_image_t* uhdr_get_gain_map_image(uhdr_codec_private_t* dec) {
  if (dec == nullptr) {
    return nullptr;
  }

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (!handle->m_sailed || handle->m_decode_call_status.error_code != UHDR_CODEC_OK) {
    return nullptr;
  }

  return handle->m_gainmap_img_buffer.get();
}

uhdr_gainmap_metadata_t* uhdr_get_gain_map_metadata(uhdr_codec_private_t* dec) {
  if (dec == nullptr) {
    return nullptr;
  }

  uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);
  if (!handle->m_sailed || handle->m_decode_call_status.error_code != UHDR_CODEC_OK) {
    return nullptr;
  }

  return &handle->m_metadata;
}

void uhdr_reset_decoder(uhdr_codec_private_t* dec) {
  if (dec != nullptr) {
    uhdr_decoder_private* handle = reinterpret_cast<uhdr_decoder_private*>(dec);

    // clear entries and restore defaults
    handle->m_uhdr_compressed_img.reset();
    handle->m_output_fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
    handle->m_output_ct = UHDR_CT_LINEAR;
    handle->m_output_max_disp_boost = FLT_MAX;

    // ready to be configured
    handle->m_sailed = false;
    handle->m_decoded_img_buffer.reset();
    handle->m_gainmap_img_buffer.reset();
    handle->m_exif.clear();
    handle->m_icc.clear();
    handle->m_base_xmp.clear();
    handle->m_gainmap_xmp.clear();
    memset(&handle->m_metadata, 0, sizeof handle->m_metadata);
    handle->m_decode_call_status = g_no_error;
  }
}
