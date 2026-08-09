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

#ifdef UHDR_ENABLE_HEIF

#include <cstdlib>
#include <map>

#include "ultrahdr/avifultrahdr.h"
#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/gainmapmetadata.h"

#define UHDR_CG_BT_601 static_cast<uhdr_color_gamut_t>(3)

namespace ultrahdr {

class MemoryWriter {
 public:
  MemoryWriter() : data_(nullptr), size_(0), capacity_(0) {}

  ~MemoryWriter() { free(data_); }

  const uint8_t* data() const { return data_; }

  size_t size() const { return size_; }

  void write(const void* data, size_t size) {
    if (capacity_ - size_ < size) {
      size_t new_capacity = capacity_ + size;
      uint8_t* new_data = static_cast<uint8_t*>(malloc(new_capacity));
      if (data_) {
        memcpy(new_data, data_, size_);
        free(data_);
      }
      data_ = new_data;
      capacity_ = new_capacity;
    }
    memcpy(&data_[size_], data, size);
    size_ += size;
  }

 public:
  uint8_t* data_;
  size_t size_;
  size_t capacity_;
};

static struct heif_error writer_write([[maybe_unused]] struct heif_context* ctx, const void* data,
                                      size_t size, void* userdata) {
  MemoryWriter* writer = static_cast<MemoryWriter*>(userdata);
  writer->write(data, size);
  struct heif_error err {
    heif_error_Ok, heif_suberror_Unspecified, nullptr
  };
  return err;
}

static struct heif_error fill_img_plane(heif_image* img, heif_channel channel, void* srcBuffer,
                                        int width, int height, int srcRowStride) {
  heif_error err = heif_image_add_plane(img, channel, width, height, 8 /*bitDepth */);
  if (err.code != heif_error_Ok) return err;

  int dstStride;
  uint8_t* dstBuffer = heif_image_get_plane(img, channel, &dstStride);
  uint8_t* srcRow = static_cast<uint8_t*>(srcBuffer);

  for (int y = 0; y < height; y++) {
    memcpy(dstBuffer, srcRow, width);
    srcRow += srcRowStride;
    dstBuffer += dstStride;
  }
  return err;
}

static struct heif_error copy_img_plane(heif_image* img, heif_channel channel, void* dstBuffer,
                                        int width, int height, int dstRowStride, int bpp) {
  if (channel != heif_channel_interleaved && channel != heif_channel_Y &&
      channel != heif_channel_Cb && channel != heif_channel_Cr) {
    return {heif_error_Invalid_input, heif_suberror_Nonexisting_image_channel_referenced,
            "supports copying only heif_channel_interleaved"};
  }

  int srcStride;
  uint8_t* srcBuffer = heif_image_get_plane(img, channel, &srcStride);
  uint8_t* srcRow = static_cast<uint8_t*>(srcBuffer);
  uint8_t* dstRow = static_cast<uint8_t*>(dstBuffer);

  for (int y = 0; y < height; y++) {
    memcpy(dstRow, srcRow, width * bpp);
    srcRow += srcStride;
    dstRow += dstRowStride;
  }
  return {heif_error_Ok, heif_suberror_Unspecified, nullptr};
}

/*!\brief map of uhdr color primaries and libheif primaries */
static const std::map<uhdr_color_gamut_t, heif_color_primaries> map_primaries = {
    {UHDR_CG_BT_709, heif_color_primaries_ITU_R_BT_709_5},
    {UHDR_CG_DISPLAY_P3, heif_color_primaries_SMPTE_EG_432_1},
    {UHDR_CG_BT_2100, heif_color_primaries_ITU_R_BT_2020_2_and_2100_0},
    {(uhdr_color_gamut_t)UHDR_CG_BT_601, heif_color_primaries_ITU_R_BT_601_6},
    {UHDR_CG_UNSPECIFIED, heif_color_primaries_unspecified},
};

/*!\brief map of uhdr color transfer and libheif transfer characteristics */
static const std::map<uhdr_color_transfer_t, heif_transfer_characteristics> map_transfer = {
    {UHDR_CT_LINEAR, heif_transfer_characteristic_linear},
    {UHDR_CT_PQ, heif_transfer_characteristic_ITU_R_BT_2100_0_PQ},
    {UHDR_CT_HLG, heif_transfer_characteristic_ITU_R_BT_2100_0_HLG},
    {UHDR_CT_SRGB, heif_transfer_characteristic_ITU_R_BT_709_5},
    {UHDR_CT_UNSPECIFIED, heif_transfer_characteristic_unspecified},
};

/*!\brief map of uhdr color gamut and libheif matrix coefficients */
static const std::map<uhdr_color_gamut_t, heif_matrix_coefficients> map_matrix = {
    {UHDR_CG_BT_709, heif_matrix_coefficients_ITU_R_BT_709_5},
    {UHDR_CG_DISPLAY_P3, heif_matrix_coefficients_chromaticity_derived_non_constant_luminance},
    {UHDR_CG_BT_2100, heif_matrix_coefficients_ITU_R_BT_2020_2_non_constant_luminance},
    {(uhdr_color_gamut_t)UHDR_CG_BT_601, heif_matrix_coefficients_ITU_R_BT_601_6},
    {UHDR_CG_UNSPECIFIED, heif_matrix_coefficients_unspecified},
};

static uhdr_color_gamut_t map_primaries_inverse(heif_color_primaries primaries) {
  for (const auto& [key, value] : map_primaries) {
    if (value == primaries) return key;
  }
  return UHDR_CG_UNSPECIFIED;
}

static uhdr_color_transfer_t map_transfer_inverse(heif_transfer_characteristics transfer) {
  for (const auto& [key, value] : map_transfer) {
    if (value == transfer) return key;
  }
  return UHDR_CT_UNSPECIFIED;
}

static uhdr_color_gamut_t map_matrix_inverse(heif_matrix_coefficients matrix) {
  for (const auto& [key, value] : map_matrix) {
    if (value == matrix) return key;
  }
  return UHDR_CG_UNSPECIFIED;
}

static heif_error map_fmt_to_heif_chroma_vars(uhdr_img_fmt_t fmt, unsigned int w, unsigned h,
                                              enum heif_chroma& heif_img_fmt, int& chromaWd,
                                              int& chromaHt) {
  if (fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    heif_img_fmt = heif_chroma_420;
    chromaWd = w / 2;
    chromaHt = h / 2;
  } else if (fmt == UHDR_IMG_FMT_16bppYCbCr422) {
    heif_img_fmt = heif_chroma_422;
    chromaWd = w;
    chromaHt = h / 2;
  } else if (fmt == UHDR_IMG_FMT_24bppYCbCr444) {
    heif_img_fmt = heif_chroma_444;
    chromaWd = w;
    chromaHt = h;
  } else {
    heif_error status;
    status.code = heif_error_Unsupported_feature;
    status.subcode = heif_suberror_Unsupported_color_conversion;
    status.message = "mapping uhdr image format to heif chroma format failed";
    return status;
  }
  return {heif_error_Ok, heif_suberror_Unspecified, nullptr};
}

static heif_error map_heif_chroma_vars_to_fmt(enum heif_colorspace colorspace,
                                              enum heif_chroma chroma_fmt, uhdr_img_fmt_t& fmt) {
  if (colorspace == heif_colorspace_YCbCr) {
    if (chroma_fmt == heif_chroma_420) {
      fmt = UHDR_IMG_FMT_12bppYCbCr420;
    } else if (chroma_fmt == heif_chroma_422) {
      fmt = UHDR_IMG_FMT_16bppYCbCr422;
    } else if (chroma_fmt == heif_chroma_444) {
      fmt = UHDR_IMG_FMT_24bppYCbCr444;
    } else {
      heif_error status;
      status.code = heif_error_Unsupported_feature;
      status.subcode = heif_suberror_Unsupported_color_conversion;
      status.message = "mapping heif image format to uhdr img format failed";
      return status;
    }
  } else if (colorspace == heif_colorspace_monochrome) {
    fmt = UHDR_IMG_FMT_8bppYCbCr400;
  } else if (colorspace == heif_colorspace_RGB) {
    if (chroma_fmt == heif_chroma_interleaved_RGB) {
      fmt = UHDR_IMG_FMT_24bppRGB888;
    } else if (chroma_fmt == heif_chroma_interleaved_RGBA) {
      fmt = UHDR_IMG_FMT_32bppRGBA8888;
    } else {
      heif_error status;
      status.code = heif_error_Unsupported_feature;
      status.subcode = heif_suberror_Unsupported_color_conversion;
      status.message = "mapping heif image format to uhdr img format failed";
      return status;
    }
  } else {
    heif_error status;
    status.code = heif_error_Unsupported_feature;
    status.subcode = heif_suberror_Unsupported_color_conversion;
    status.message = "mapping heif image format to uhdr img format failed";
    return status;
  }
  return {heif_error_Ok, heif_suberror_Unspecified, nullptr};
}

static heif_error set_internal_color_format(heif_encoder* encoder, enum heif_chroma heif_img_fmt) {
  struct heif_error err {
    heif_error_Ok, heif_suberror_Unspecified, nullptr
  };
  switch (heif_img_fmt) {
    case heif_chroma_420:
    case heif_chroma_monochrome:
      err = heif_encoder_set_parameter(encoder, "chroma", "420");
      break;
    case heif_chroma_422:
      err = heif_encoder_set_parameter(encoder, "chroma", "422");
      break;
    case heif_chroma_444:
      err = heif_encoder_set_parameter(encoder, "chroma", "444");
      break;
    default:
      err.code = heif_error_Invalid_input;
      err.subcode = heif_suberror_Unsupported_parameter;
      err.message = "unsupported heif image format setting";
      break;
  }
  return err;
}

static uhdr_error_info_t heif_get_gainmap_metadata(struct heif_image_handle* base_handle,
                                                   uhdr_gainmap_metadata_ext_t* metadata) {
  size_t iso_vec_sz = heif_image_handle_get_gain_map_metadata_size(base_handle);
  std::vector<uint8_t> iso_vec(iso_vec_sz);
  uhdr_gainmap_metadata_frac metadata_frac;

  heif_error err = heif_image_handle_get_gain_map_metadata(base_handle, iso_vec.data());
  if (err.code != heif_error_Ok) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "%s", err.message);
    return status;
  }
  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(iso_vec, &metadata_frac))
  UHDR_ERR_CHECK(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata_frac, metadata))
  return g_no_error;
}

AvifUltraHdr::AvifUltraHdr(void* uhdrGLESCtxt, int mapDimensionScaleFactor, int mapCompressQuality,
             bool useMultiChannelGainMap, float gamma, uhdr_enc_preset_t preset,
             float minContentBoost, float maxContentBoost, float targetDispPeakBrightness,
             uhdr_codec_t codec)
    : UltraHdr(uhdrGLESCtxt, mapDimensionScaleFactor, mapCompressQuality, useMultiChannelGainMap,
               gamma, preset, minContentBoost, maxContentBoost, targetDispPeakBrightness),
      mCodec(codec) {}

/* Encode API-0 */
uhdr_error_info_t AvifUltraHdr::encodeAvifUltraHdr(uhdr_raw_image_t* hdr_intent, uhdr_compressed_image_t* dest,
                                     int quality, uhdr_mem_block_t* exif) {
  uhdr_img_fmt_t sdr_intent_fmt;
  if (hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    sdr_intent_fmt = UHDR_IMG_FMT_12bppYCbCr420;
  } else if (hdr_intent->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
    sdr_intent_fmt = UHDR_IMG_FMT_24bppYCbCr444;
  } else if (hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
             hdr_intent->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    sdr_intent_fmt = UHDR_IMG_FMT_32bppRGBA8888;
  } else {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "unsupported hdr intent color format %d",
             hdr_intent->fmt);
    return status;
  }
  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent = std::make_unique<uhdr_raw_image_ext_t>(
      sdr_intent_fmt, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, hdr_intent->w,
      hdr_intent->h, 64);

  // tone map
  UHDR_ERR_CHECK(toneMap(hdr_intent, sdr_intent.get()));

  // If hdr intent is tonemapped internally, it is observed from quality pov,
  // generateGainMapOnePass() is sufficient
  mEncPreset = UHDR_USAGE_REALTIME;  // overriding the config option

  // generate gain map
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
  UHDR_ERR_CHECK(generateGainMap(sdr_intent.get(), hdr_intent, &metadata, gainmap,
                                 sdr_intent->cg == UHDR_CG_DISPLAY_P3 /* sdr_is_601 */,
                                 false /* use_luminance */));

  // compress sdr image
  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent_yuv_ext;
  uhdr_raw_image_t* sdr_intent_yuv = sdr_intent.get();
  if (isPixelFormatRgb(sdr_intent->fmt)) {
#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr_neon(sdr_intent.get());
#else
    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr(sdr_intent.get());
#endif
    sdr_intent_yuv = sdr_intent_yuv_ext.get();
  }

  std::shared_ptr<DataStruct> baseIcc = IccHelper::writeIccProfile(UHDR_CT_SRGB, sdr_intent->cg);
  std::shared_ptr<DataStruct> alternateIcc =
      IccHelper::writeIccProfile(gainmap->ct, gainmap->cg);

  return encodeAvifUltraHdr(sdr_intent_yuv, gainmap.get(), &metadata, dest, quality, exif, baseIcc.get(),
                     alternateIcc.get());
}

/* Encode API-1 */
uhdr_error_info_t AvifUltraHdr::encodeAvifUltraHdr(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                     uhdr_compressed_image_t* dest, int quality,
                                     uhdr_mem_block_t* exif) {
  // generate gain map
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
  UHDR_ERR_CHECK(generateGainMap(sdr_intent, hdr_intent, &metadata, gainmap,
                                 sdr_intent->cg == UHDR_CG_DISPLAY_P3 /* sdr_is_601 */));

  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent_yuv_ext;
  uhdr_raw_image_t* sdr_intent_yuv = sdr_intent;
  if (isPixelFormatRgb(sdr_intent->fmt)) {
#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr_neon(sdr_intent);
#else
    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr(sdr_intent);
#endif
    sdr_intent_yuv = sdr_intent_yuv_ext.get();
  }

  std::shared_ptr<DataStruct> baseIcc = IccHelper::writeIccProfile(UHDR_CT_SRGB, sdr_intent->cg);
  std::shared_ptr<DataStruct> alternateIcc =
      IccHelper::writeIccProfile(gainmap->ct, gainmap->cg);

  return encodeAvifUltraHdr(sdr_intent_yuv, gainmap.get(), &metadata, dest, quality, exif, baseIcc.get(),
                     alternateIcc.get());
}

uhdr_error_info_t AvifUltraHdr::encodeAvifUltraHdr(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
                                     uhdr_gainmap_metadata_ext_t* metadata,
                                     uhdr_compressed_image_t* dest, int quality,
                                     uhdr_mem_block_t* exif, DataStruct* baseIcc,
                                     DataStruct* alternateIcc) {
  uhdr_error_info_t status = g_no_error;
  heif_encoder* encoder = nullptr;
  heif_encoding_options* options = nullptr;
  heif_color_profile_nclx* sdrNclx = nullptr;
  heif_color_profile_nclx* gainmapNclx = nullptr;
  heif_color_profile_nclx* hdrNclx = nullptr;
  heif_image* baseImage = nullptr;
  heif_image_handle* baseHandle = nullptr;
  heif_image* secondaryImage = nullptr;
  heif_image_handle* secondaryHandle = nullptr;
  int sdr_cg_matrix;
  uhdr_gainmap_metadata_frac metadata_frac;
  std::vector<uint8_t> iso_data;

  uhdr_raw_image_t* gainmap_img_yuv = gainmap_img;
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_yuv_ext;

  MemoryWriter writer;
  struct heif_writer w;
  w.writer_api_version = 1;
  w.write = writer_write;

  heif_context* ctx = heif_context_alloc();
  if (!ctx) {
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "failed to allocate heif context");
    return status;
  }

  HEIF_ERR_CHECK(heif_context_get_encoder_for_format(
      ctx, mCodec == UHDR_CODEC_AVIF ? heif_compression_AV1 : heif_compression_HEVC, &encoder));

  // set the encoder parameters
  HEIF_ERR_CHECK(heif_encoder_set_lossy_quality(encoder, quality));

  // encode the primary image
  enum heif_chroma heif_img_fmt;
  int chromaWd, chromaHt;
  HEIF_ERR_CHECK(map_fmt_to_heif_chroma_vars(sdr_intent->fmt, sdr_intent->w, sdr_intent->h,
                                             heif_img_fmt, chromaWd, chromaHt));
  HEIF_ERR_CHECK(heif_image_create(sdr_intent->w, sdr_intent->h, heif_colorspace_YCbCr,
                                   heif_img_fmt, &baseImage));
  HEIF_ERR_CHECK(fill_img_plane(baseImage, heif_channel_Y, sdr_intent->planes[UHDR_PLANE_Y],
                                sdr_intent->w, sdr_intent->h, sdr_intent->stride[UHDR_PLANE_Y]));
  HEIF_ERR_CHECK(fill_img_plane(baseImage, heif_channel_Cb, sdr_intent->planes[UHDR_PLANE_U],
                                chromaWd, chromaHt, sdr_intent->stride[UHDR_PLANE_U]));
  HEIF_ERR_CHECK(fill_img_plane(baseImage, heif_channel_Cr, sdr_intent->planes[UHDR_PLANE_V],
                                chromaWd, chromaHt, sdr_intent->stride[UHDR_PLANE_V]));
  if (baseIcc != nullptr) {
    void* ptr = (uint8_t*)baseIcc->getData() + kICCIdentifierSize;
    HEIF_ERR_CHECK(heif_image_set_raw_color_profile(baseImage, "prof", ptr,
                                                    baseIcc->getLength() - kICCIdentifierSize));
  }
  sdrNclx = heif_nclx_color_profile_alloc();
  if (!sdrNclx) {
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "failed to allocate nclx color profile for base image");
    goto CleanUp;
  }
  HEIF_ERR_CHECK(set_internal_color_format(encoder, heif_img_fmt));
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_color_primaries(
      sdrNclx, map_primaries.find(sdr_intent->cg)->second));
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_transfer_characteristics(
      sdrNclx, map_transfer.find(sdr_intent->ct)->second));
  sdr_cg_matrix = sdr_intent->cg == UHDR_CG_DISPLAY_P3 ? UHDR_CG_BT_601 : sdr_intent->cg;
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_matrix_coefficients(
      sdrNclx, map_matrix.find((uhdr_color_gamut_t)sdr_cg_matrix)->second));
  sdrNclx->full_range_flag = sdr_intent->range == UHDR_CR_FULL_RANGE ? true : false;
  options = heif_encoding_options_alloc();
  if (!options) {
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "failed to allocate nclx color profile for base image");
    goto CleanUp;
  }
  options->save_two_colr_boxes_when_ICC_and_nclx_available = 1;
  options->output_nclx_profile = sdrNclx;
  HEIF_ERR_CHECK(heif_image_set_nclx_color_profile(baseImage, sdrNclx));
  HEIF_ERR_CHECK(heif_context_encode_image(ctx, baseImage, encoder, options, &baseHandle));
  if (exif != nullptr) {
    HEIF_ERR_CHECK(heif_context_add_exif_metadata(ctx, baseHandle, exif->data, exif->data_sz));
  }

  // encode the gain map image
  if (isUsingMultiChannelGainMap()) {
    gainmap_yuv_ext = convert_raw_input_to_ycbcr(gainmap_img, true /* use bt601 */);
    gainmap_img_yuv = gainmap_yuv_ext.get();
  }
  if (isUsingMultiChannelGainMap()) {
    HEIF_ERR_CHECK(map_fmt_to_heif_chroma_vars(gainmap_img_yuv->fmt, gainmap_img_yuv->w,
                                               gainmap_img_yuv->h, heif_img_fmt, chromaWd,
                                               chromaHt));
    HEIF_ERR_CHECK(heif_image_create(gainmap_img_yuv->w, gainmap_img_yuv->h, heif_colorspace_YCbCr,
                                     heif_img_fmt, &secondaryImage));
    HEIF_ERR_CHECK(fill_img_plane(secondaryImage, heif_channel_Y,
                                  gainmap_img_yuv->planes[UHDR_PLANE_Y], gainmap_img_yuv->w,
                                  gainmap_img_yuv->h, gainmap_img_yuv->stride[UHDR_PLANE_Y]));
    HEIF_ERR_CHECK(fill_img_plane(secondaryImage, heif_channel_Cb,
                                  gainmap_img_yuv->planes[UHDR_PLANE_U], chromaWd, chromaHt,
                                  gainmap_img_yuv->stride[UHDR_PLANE_U]));
    HEIF_ERR_CHECK(fill_img_plane(secondaryImage, heif_channel_Cr,
                                  gainmap_img_yuv->planes[UHDR_PLANE_V], chromaWd, chromaHt,
                                  gainmap_img_yuv->stride[UHDR_PLANE_V]));
    HEIF_ERR_CHECK(set_internal_color_format(encoder, heif_img_fmt));
  } else {
    HEIF_ERR_CHECK(heif_image_create(gainmap_img_yuv->w, gainmap_img_yuv->h,
                                     heif_colorspace_monochrome, heif_chroma_monochrome,
                                     &secondaryImage));
    HEIF_ERR_CHECK(fill_img_plane(secondaryImage, heif_channel_Y,
                                  gainmap_img_yuv->planes[UHDR_PLANE_Y], gainmap_img_yuv->w,
                                  gainmap_img_yuv->h, gainmap_img_yuv->stride[UHDR_PLANE_Y]));
    HEIF_ERR_CHECK(heif_encoder_set_parameter(encoder, "chroma", "420"));
  }
  gainmapNclx = heif_nclx_color_profile_alloc();
  if (!gainmapNclx) {
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "failed to allocate nclx color profile for base image");
    goto CleanUp;
  }
  HEIF_ERR_CHECK(
      heif_nclx_color_profile_set_color_primaries(gainmapNclx, heif_color_primaries_unspecified));
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_transfer_characteristics(
      gainmapNclx, heif_transfer_characteristic_unspecified));
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_matrix_coefficients(
      gainmapNclx, map_matrix.find((uhdr_color_gamut_t)UHDR_CG_BT_601)->second));
  gainmapNclx->full_range_flag = gainmap_img_yuv->range == UHDR_CR_FULL_RANGE ? true : false;
  options->output_nclx_profile = gainmapNclx;
  HEIF_ERR_CHECK(heif_image_set_nclx_color_profile(secondaryImage, gainmapNclx));

  status = uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(metadata, &metadata_frac);
  if (status.error_code != UHDR_CODEC_OK) goto CleanUp;
  status = uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata_frac, iso_data);
  if (status.error_code != UHDR_CODEC_OK) goto CleanUp;
  // TODO: pass alternateIcc write color properties of tmap item
  // TODO: write clli of tmap item
  hdrNclx = heif_nclx_color_profile_alloc();
  if (!hdrNclx) {
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "failed to allocate nclx color profile for tmap image");
    goto CleanUp;
  }
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_color_primaries(
      hdrNclx, map_primaries.find(gainmap_img->cg)->second));
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_transfer_characteristics(
      hdrNclx, map_transfer.find(gainmap_img->ct)->second));
  HEIF_ERR_CHECK(heif_nclx_color_profile_set_matrix_coefficients(
      hdrNclx, map_matrix.find(gainmap_img->cg)->second));
  hdrNclx->full_range_flag = gainmap_img->range == UHDR_CR_FULL_RANGE ? true : false;
  (void)alternateIcc;
  HEIF_ERR_CHECK(heif_encoder_set_lossy_quality(encoder, mMapCompressQuality));
  HEIF_ERR_CHECK(heif_context_encode_gain_map_image(ctx, baseHandle, encoder, secondaryImage,
                                                    options, iso_data.data(), iso_data.size(),
                                                    hdrNclx, &secondaryHandle));

  heif_context_write(ctx, &w, &writer);
  memcpy(dest->data, writer.data(), writer.size());
  dest->data_sz = dest->capacity = writer.size();

CleanUp:
  if (baseImage) heif_image_release(baseImage);
  baseImage = nullptr;
  if (baseHandle) heif_image_handle_release(baseHandle);
  baseHandle = nullptr;
  if (secondaryImage) heif_image_release(secondaryImage);
  secondaryImage = nullptr;
  if (secondaryHandle) heif_image_handle_release(secondaryHandle);
  secondaryHandle = nullptr;
  if (options) heif_encoding_options_free(options);
  options = nullptr;
  if (hdrNclx) heif_nclx_color_profile_free(hdrNclx);
  hdrNclx = nullptr;
  if (gainmapNclx) heif_nclx_color_profile_free(gainmapNclx);
  gainmapNclx = nullptr;
  if (sdrNclx) heif_nclx_color_profile_free(sdrNclx);
  sdrNclx = nullptr;
  if (encoder) heif_encoder_release(encoder);
  encoder = nullptr;
  if (ctx) heif_context_free(ctx);
  ctx = nullptr;

  return status;
}

/* Decode API */
uhdr_error_info_t AvifUltraHdr::decodeAvifUltraHdr(uhdr_compressed_image_t* uhdr_compressed_img,
                                     uhdr_raw_image_t* dest, float max_display_boost,
                                     uhdr_color_transfer_t output_ct, uhdr_img_fmt_t output_format,
                                     uhdr_raw_image_t* gainmap_img,
                                     uhdr_gainmap_metadata_t* gainmap_metadata) {
  uhdr_error_info_t status = g_no_error;
  struct heif_image_handle* base_handle = nullptr;
  struct heif_image* sdr_image = nullptr;
  struct heif_image_handle* gainmap_handle = nullptr;
  struct heif_image* gainmap_image = nullptr;
  struct heif_decoding_options* decoding_options = nullptr;
  heif_color_profile_nclx* nclx = nullptr;
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
  enum heif_colorspace out_colorspace;
  enum heif_chroma out_chroma;
  uhdr_img_fmt_t fmt;
  int sdr_width = 0, sdr_height = 0;
  int gainmap_width = 0, gainmap_height = 0;
  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent, gainmap;
  heif_context* ctx = nullptr;
  heif_error nclx_err;
  uhdr_color_gamut_t sdr_cg = UHDR_CG_BT_709;
  uhdr_color_transfer_t sdr_ct = UHDR_CT_SRGB;
  uhdr_color_range_t sdr_range = UHDR_CR_FULL_RANGE;
  uhdr_color_gamut_t gm_cg = UHDR_CG_BT_709;
  uhdr_color_transfer_t gm_ct = UHDR_CT_SRGB;
  uhdr_color_range_t gm_range = UHDR_CR_FULL_RANGE;
  heif_error err;

  ctx = heif_context_alloc();
  if (!ctx) {
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "failed to allocate heif context");
    return status;
  }
  HEIF_ERR_CHECK(heif_context_read_from_memory_without_copy(
      ctx, static_cast<const uint8_t*>(uhdr_compressed_img->data), uhdr_compressed_img->data_sz,
      nullptr))
  HEIF_ERR_CHECK(heif_context_get_primary_image_handle(ctx, &base_handle))
  decoding_options = heif_decoding_options_alloc();
  out_colorspace = heif_colorspace_RGB;
  out_chroma = heif_chroma_interleaved_RGBA;
  HEIF_ERR_CHECK(
      heif_decode_image(base_handle, &sdr_image, out_colorspace, out_chroma, decoding_options))
  nclx_err = heif_image_handle_get_nclx_color_profile(base_handle, &nclx);
  if (nclx_err.code != heif_error_Ok) {
    nclx_err = heif_image_get_nclx_color_profile(sdr_image, &nclx);
  }
  HEIF_ERR_CHECK(map_heif_chroma_vars_to_fmt(out_colorspace, out_chroma, fmt))
  sdr_width = heif_image_handle_get_width(base_handle);
  sdr_height = heif_image_handle_get_height(base_handle);
  sdr_cg = (nclx_err.code == heif_error_Ok && nclx != nullptr)
               ? map_primaries_inverse(nclx->color_primaries)
               : UHDR_CG_BT_709;
  sdr_ct = (nclx_err.code == heif_error_Ok && nclx != nullptr)
               ? map_transfer_inverse(nclx->transfer_characteristics)
               : UHDR_CT_SRGB;
  sdr_range = (nclx_err.code == heif_error_Ok && nclx != nullptr)
                  ? (nclx->full_range_flag ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE)
                  : UHDR_CR_FULL_RANGE;
  sdr_intent = std::make_unique<uhdr_raw_image_ext_t>(
      fmt, sdr_cg, sdr_ct, sdr_range, sdr_width, sdr_height, 64);
  if (nclx) {
    heif_nclx_color_profile_free(nclx);
    nclx = nullptr;
  }
  HEIF_ERR_CHECK(copy_img_plane(sdr_image, heif_channel_interleaved,
                                sdr_intent->planes[UHDR_PLANE_PACKED], sdr_width, sdr_height,
                                sdr_intent->stride[UHDR_PLANE_PACKED] * 4, 4))
  if (gainmap_metadata != nullptr || output_ct != UHDR_CT_SRGB) {
    HEIF_ERR_CHECK(heif_image_handle_get_gain_map_image_handle(base_handle, &gainmap_handle))
    status = heif_get_gainmap_metadata(base_handle, &metadata);
    if (status.error_code != UHDR_CODEC_OK) return status;
    if (gainmap_metadata != nullptr) {
      std::copy(metadata.min_content_boost, metadata.min_content_boost + 3,
                gainmap_metadata->min_content_boost);
      std::copy(metadata.max_content_boost, metadata.max_content_boost + 3,
                gainmap_metadata->max_content_boost);
      std::copy(metadata.gamma, metadata.gamma + 3, gainmap_metadata->gamma);
      std::copy(metadata.offset_sdr, metadata.offset_sdr + 3, gainmap_metadata->offset_sdr);
      std::copy(metadata.offset_hdr, metadata.offset_hdr + 3, gainmap_metadata->offset_hdr);
      gainmap_metadata->hdr_capacity_min = metadata.hdr_capacity_min;
      gainmap_metadata->hdr_capacity_max = metadata.hdr_capacity_max;
      gainmap_metadata->use_base_cg = metadata.use_base_cg;
    }
    HEIF_ERR_CHECK(heif_image_handle_get_preferred_decoding_colorspace(
        gainmap_handle, &out_colorspace, &out_chroma))
    if (out_colorspace != heif_colorspace_monochrome) {
      out_colorspace = heif_colorspace_RGB;
      out_chroma = heif_chroma_interleaved_RGBA;
    }
    heif_error decode_err = heif_decode_image(gainmap_handle, &gainmap_image, out_colorspace,
                                              out_chroma, decoding_options);
    if (decode_err.code != heif_error_Ok && out_colorspace == heif_colorspace_monochrome) {
      out_colorspace = heif_colorspace_RGB;
      out_chroma = heif_chroma_interleaved_RGBA;
      decode_err = heif_decode_image(gainmap_handle, &gainmap_image, out_colorspace, out_chroma,
                                     decoding_options);
    }
    if (decode_err.code != heif_error_Ok) {
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "%s", decode_err.message);
      goto CleanUp;
    }
    nclx_err = heif_image_handle_get_nclx_color_profile(gainmap_handle, &nclx);
    if (nclx_err.code != heif_error_Ok) {
      nclx_err = heif_image_get_nclx_color_profile(gainmap_image, &nclx);
    }
    HEIF_ERR_CHECK(map_heif_chroma_vars_to_fmt(out_colorspace, out_chroma, fmt))
    gainmap_width = heif_image_handle_get_width(gainmap_handle);
    gainmap_height = heif_image_handle_get_height(gainmap_handle);
    gm_cg = (nclx_err.code == heif_error_Ok && nclx != nullptr)
                ? map_matrix_inverse(nclx->matrix_coefficients)
                : UHDR_CG_BT_709;
    gm_ct = (nclx_err.code == heif_error_Ok && nclx != nullptr)
                ? map_transfer_inverse(nclx->transfer_characteristics)
                : UHDR_CT_SRGB;
    gm_range = (nclx_err.code == heif_error_Ok && nclx != nullptr)
                   ? (nclx->full_range_flag ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE)
                   : UHDR_CR_FULL_RANGE;
    gainmap = std::make_unique<uhdr_raw_image_ext_t>(
        fmt, gm_cg, gm_ct, gm_range, gainmap_width, gainmap_height, 64);
    if (nclx) {
      heif_nclx_color_profile_free(nclx);
      nclx = nullptr;
    }
    if (out_colorspace == heif_colorspace_monochrome) {
      HEIF_ERR_CHECK(copy_img_plane(gainmap_image, heif_channel_Y, gainmap->planes[UHDR_PLANE_Y],
                                    gainmap_width, gainmap_height, gainmap->stride[UHDR_PLANE_Y],
                                    1))
    } else {
      HEIF_ERR_CHECK(copy_img_plane(gainmap_image, heif_channel_interleaved,
                                    gainmap->planes[UHDR_PLANE_PACKED], gainmap_width,
                                    gainmap_height, gainmap->stride[UHDR_PLANE_PACKED] * 4, 4))
    }
    if (gainmap_img != nullptr) {
      status = copy_raw_image(gainmap.get(), gainmap_img);
      if (status.error_code != UHDR_CODEC_OK) goto CleanUp;
    }
    err = heif_image_handle_get_derived_image_nclx_color_profile(base_handle, &nclx);
    if (err.code == heif_error_Ok) {
      gainmap->cg = map_primaries_inverse(nclx->color_primaries);
      gainmap->ct = map_transfer_inverse(nclx->transfer_characteristics);
      gainmap->range = nclx->full_range_flag ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE;
      heif_nclx_color_profile_free(nclx);
      nclx = nullptr;
    } else {
      gainmap->cg = sdr_intent->cg;
      gainmap->ct = sdr_intent->ct;
      gainmap->range = sdr_intent->range;
    }
  }

  if (output_ct != UHDR_CT_SRGB) {
    status = applyGainMap(sdr_intent.get(), gainmap.get(), &metadata, output_ct, output_format,
                          max_display_boost, dest);
  } else {
    status = copy_raw_image(sdr_intent.get(), dest);
  }

CleanUp:
  if (decoding_options) heif_decoding_options_free(decoding_options);
  decoding_options = nullptr;
  if (nclx) heif_nclx_color_profile_free(nclx);
  nclx = nullptr;
  if (sdr_image) heif_image_release(sdr_image);
  sdr_image = nullptr;
  if (gainmap_image) heif_image_release(gainmap_image);
  gainmap_image = nullptr;
  if (gainmap_handle) heif_image_handle_release(gainmap_handle);
  gainmap_handle = nullptr;
  if (base_handle) heif_image_handle_release(base_handle);
  base_handle = nullptr;
  if (ctx) heif_context_free(ctx);
  ctx = nullptr;

  return status;
}

}  // namespace ultrahdr

#endif
