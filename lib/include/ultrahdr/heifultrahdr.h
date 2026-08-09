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

#ifndef ULTRAHDR_HEIFULTRAHDR_H
#define ULTRAHDR_HEIFULTRAHDR_H

#ifdef UHDR_ENABLE_HEIF

#include <cfloat>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/icc.h"

#include "libheif/heif.h"

#define HEIF_ERR_CHECK(x)                                               \
  {                                                                     \
    heif_error _heif_res = (x);                                         \
    if (_heif_res.code != heif_error_Ok) {                              \
      status.error_code = UHDR_CODEC_ERROR;                             \
      status.has_detail = 1;                                            \
      snprintf(status.detail, sizeof status.detail, "%s", _heif_res.message); \
      goto CleanUp;                                                     \
    }                                                                   \
  }

namespace ultrahdr {

class HeifUltraHdr : public UltraHdr {
 public:
  HeifUltraHdr(void* uhdrGLESCtxt = nullptr,
        int mapDimensionScaleFactor = kMapDimensionScaleFactorAndroidDefault,
        int mapCompressQuality = kMapCompressQualityAndroidDefault,
        bool useMultiChannelGainMap = kUseMultiChannelGainMapAndroidDefault,
        float gamma = kGainMapGammaDefault,
        uhdr_enc_preset_t preset = kEncSpeedPresetAndroidDefault, float minContentBoost = FLT_MIN,
        float maxContentBoost = FLT_MAX, float targetDispPeakBrightness = -1.0f,
        uhdr_codec_t codec = UHDR_CODEC_HEIF);

  /*!\brief Encode API-0.
   *
   * Create ultrahdr heif/avif image from raw hdr intent.
   *
   * Input hdr image is tonemapped to sdr image. A gainmap coefficient is computed between hdr and
   * sdr intent. sdr intent and gain map coefficient are compressed using heif/avif encoding.
   * compressed sdr intent is signalled as primary item and compressed gainmap is signalled as a
   * tone map derived item
   *
   * \param[in]       hdr_intent        hdr intent raw input image descriptor
   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
   * \param[in]       quality           quality factor for sdr intent heif/avif compression
   * \param[in]       exif              optional exif metadata that needs to be inserted in
   *                                    compressed output
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeHeicUltraHdr(uhdr_raw_image_t* hdr_intent, uhdr_compressed_image_t* dest,
                                int quality, uhdr_mem_block_t* exif);

  /*!\brief Encode API-1.
   *
   * Create ultrahdr heif/avif image from raw hdr intent and raw sdr intent.
   *
   * A gainmap coefficient is computed between hdr and sdr intent. sdr intent and gain map
   * coefficient are compressed using heif/avif encoding. compressed sdr intent is signalled as
   * primary item and compressed gainmap is signalled as a tone map derived item
   * NOTE: Color transfer of sdr intent is expected to be sRGB.
   *
   * \param[in]       hdr_intent        hdr intent raw input image descriptor
   * \param[in]       sdr_intent        sdr intent raw input image descriptor
   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
   * \param[in]       quality           quality factor for sdr intent heif/avif compression
   * \param[in]       exif              optional exif metadata that needs to be inserted in
   *                                    compressed output
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeHeicUltraHdr(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                uhdr_compressed_image_t* dest, int quality, uhdr_mem_block_t* exif);

  /*!\brief Decode API.
   *
   * Decompress ultrahdr heif/avif image.
   *
   * NOTE: This method requires that the ultrahdr input image contains an ICC profile with primaries
   * that match those of a color gamut that this library is aware of; Bt.709, Display-P3, or
   * Bt.2100. It also assumes the base image color transfer characteristics are sRGB.
   *
   * \param[in]       uhdr_compressed_img      compressed ultrahdr image descriptor
   * \param[in, out]  dest                     output image descriptor to store decoded output
   * \param[in]       max_display_boost        (optional) the maximum available boost supported by a
   *                                           display, the value must be greater than or equal
   *                                           to 1.0
   * \param[in]       output_ct                (optional) output color transfer
   * \param[in]       output_format            (optional) output pixel format
   * \param[in, out]  gainmap_img              (optional) output image descriptor to store decoded
   *                                           gainmap image
   * \param[in, out]  gainmap_metadata         (optional) descriptor to store gainmap metadata
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   *
   * NOTE: This method only supports single gain map metadata values for fields that allow
   * multi-channel metadata values.
   *
   * NOTE: Not all combinations of output color transfer and output pixel format are supported.
   * Refer below table for supported combinations.
   *         ----------------------------------------------------------------------
   *         |           color transfer	       |          color format            |
   *         ----------------------------------------------------------------------
   *         |                 SDR             |          32bppRGBA8888           |
   *         ----------------------------------------------------------------------
   *         |             HDR_LINEAR          |          64bppRGBAHalfFloat      |
   *         ----------------------------------------------------------------------
   *         |               HDR_PQ            |          32bppRGBA1010102        |
   *         ----------------------------------------------------------------------
   *         |               HDR_HLG           |          32bppRGBA1010102        |
   *         ----------------------------------------------------------------------
   */
  uhdr_error_info_t decodeHeicUltraHdr(uhdr_compressed_image_t* uhdr_compressed_img,
                                uhdr_raw_image_t* dest, float max_display_boost = FLT_MAX,
                                uhdr_color_transfer_t output_ct = UHDR_CT_LINEAR,
                                uhdr_img_fmt_t output_format = UHDR_IMG_FMT_64bppRGBAHalfFloat,
                                uhdr_raw_image_t* gainmap_img = nullptr,
                                uhdr_gainmap_metadata_t* gainmap_metadata = nullptr);

 private:
  /*!\brief Encode API.
   *
   * Create ultrahdr image from sdr intent, gainmap image and gainmap metadata
   *
   * A gainmap coefficient is computed between hdr and sdr intent. sdr intent and gain map
   * coefficient are compressed using heif/avif encoding. compressed sdr intent is signalled as
   * primary item and compressed gainmap is signalled as a tone map derived item
   *
   * \param[in]       sdr_intent        sdr intent raw input image descriptor
   * \param[in]       gainmap_img       gainmap raw image descriptor
   * \param[in]       metadata          gainmap metadata descriptor
   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
   * \param[in]       quality           quality factor for sdr intent heif/avif compression
   * \param[in]       exif              optional exif metadata that needs to be inserted in
   *                                    compressed output
   * \param[in]       baseIcc           base image icc
   * \param[in]       alternateIcc      alternate image icc
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeHeicUltraHdr(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
                                uhdr_gainmap_metadata_ext_t* metadata,
                                uhdr_compressed_image_t* dest, int quality, uhdr_mem_block_t* exif,
                                DataStruct* baseIcc, DataStruct* alternateIcc);

  uhdr_codec_t mCodec;
};

}  // namespace ultrahdr

#endif

#endif  // ULTRAHDR_HEIFULTRAHDR_H
