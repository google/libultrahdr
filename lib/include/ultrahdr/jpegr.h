/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef ULTRAHDR_JPEGR_H
#define ULTRAHDR_JPEGR_H

#include <array>
#include <cfloat>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdr.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegdecoderhelper.h"
#include "ultrahdr/jpegencoderhelper.h"

namespace ultrahdr {

/*
 * Holds information of jpeg image
 */
struct jpeg_info_struct {
  std::vector<uint8_t> imgData = std::vector<uint8_t>(0);
  std::vector<uint8_t> iccData = std::vector<uint8_t>(0);
  std::vector<uint8_t> exifData = std::vector<uint8_t>(0);
  std::vector<uint8_t> xmpData = std::vector<uint8_t>(0);
  std::vector<uint8_t> isoData = std::vector<uint8_t>(0);
  unsigned int width;
  unsigned int height;
  unsigned int numComponents;
};

/*
 * Holds information of jpegr image
 */
struct jpegr_info_struct {
  unsigned int width;   // copy of primary image width (for easier access)
  unsigned int height;  // copy of primary image height (for easier access)
  jpeg_info_struct* primaryImgInfo = nullptr;
  jpeg_info_struct* gainmapImgInfo = nullptr;
};

typedef struct jpeg_info_struct* j_info_ptr;
typedef struct jpegr_info_struct* jr_info_ptr;

class JpegR : public UltraHdr {
 public:
  JpegR(void* uhdrGLESCtxt = nullptr,
        int mapDimensionScaleFactor = kMapDimensionScaleFactorAndroidDefault,
        int mapCompressQuality = kMapCompressQualityAndroidDefault,
        bool useMultiChannelGainMap = kUseMultiChannelGainMapAndroidDefault,
        float gamma = kGainMapGammaDefault,
        uhdr_enc_preset_t preset = kEncSpeedPresetAndroidDefault, float minContentBoost = FLT_MIN,
        float maxContentBoost = FLT_MAX, float targetDispPeakBrightness = -1.0f);

  /*!\brief Encode API-0.
   *
   * Create ultrahdr jpeg image from raw hdr intent.
   *
   * Experimental only.
   *
   * Input hdr image is tonemapped to sdr image. A gainmap coefficient is computed between hdr and
   * sdr intent. sdr intent and gain map coefficient are compressed using jpeg encoding. compressed
   * gainmap is appended at the end of compressed sdr image.
   *
   * \param[in]       hdr_intent        hdr intent raw input image descriptor
   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
   * \param[in]       quality           quality factor for sdr intent jpeg compression
   * \param[in]       exif              optional exif metadata that needs to be inserted in
   *                                    compressed output
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_compressed_image_t* dest,
                                int quality, uhdr_mem_block_t* exif);

  /*!\brief Encode API-1.
   *
   * Create ultrahdr jpeg image from raw hdr intent and raw sdr intent.
   *
   * A gainmap coefficient is computed between hdr and sdr intent. sdr intent and gain map
   * coefficient are compressed using jpeg encoding. compressed gainmap is appended at the end of
   * compressed sdr image.
   * NOTE: Color transfer of sdr intent is expected to be sRGB.
   *
   * \param[in]       hdr_intent        hdr intent raw input image descriptor
   * \param[in]       sdr_intent        sdr intent raw input image descriptor
   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
   * \param[in]       quality           quality factor for sdr intent jpeg compression
   * \param[in]       exif              optional exif metadata that needs to be inserted in
   *                                    compressed output
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                uhdr_compressed_image_t* dest, int quality, uhdr_mem_block_t* exif);

  /*!\brief Encode API-2.
   *
   * Create ultrahdr jpeg image from raw hdr intent, raw sdr intent and compressed sdr intent.
   *
   * A gainmap coefficient is computed between hdr and sdr intent. gain map coefficient is
   * compressed using jpeg encoding. compressed gainmap is appended at the end of compressed sdr
   * intent. ICC profile is added if one isn't present in the sdr intent JPEG image.
   * NOTE: Color transfer of sdr intent is expected to be sRGB.
   * NOTE: sdr intent raw and compressed inputs are expected to be related via compress/decompress
   * operations.
   *
   * \param[in]       hdr_intent               hdr intent raw input image descriptor
   * \param[in]       sdr_intent               sdr intent raw input image descriptor
   * \param[in]       sdr_intent_compressed    sdr intent compressed input image descriptor
   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
   *                                           image
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
                                uhdr_compressed_image_t* sdr_intent_compressed,
                                uhdr_compressed_image_t* dest);

  /*!\brief Encode API-3.
   *
   * Create ultrahdr jpeg image from raw hdr intent and compressed sdr intent.
   *
   * The sdr intent is decoded and a gainmap coefficient is computed between hdr and sdr intent.
   * gain map coefficient is compressed using jpeg encoding. compressed gainmap is appended at the
   * end of compressed sdr image. ICC profile is added if one isn't present in the sdr intent JPEG
   * image.
   * NOTE: Color transfer of sdr intent is expected to be sRGB.
   *
   * \param[in]       hdr_intent               hdr intent raw input image descriptor
   * \param[in]       sdr_intent_compressed    sdr intent compressed input image descriptor
   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
   *                                           image
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent,
                                uhdr_compressed_image_t* sdr_intent_compressed,
                                uhdr_compressed_image_t* dest);

  /*!\brief Encode API-4.
   *
   * Create ultrahdr jpeg image from compressed sdr image and compressed gainmap image
   *
   * compressed gainmap image is added at the end of compressed sdr image. ICC profile is added if
   * one isn't present in the sdr intent compressed image.
   *
   * \param[in]       base_img_compressed      sdr intent compressed input image descriptor
   * \param[in]       gainmap_img_compressed   gainmap compressed image descriptor
   * \param[in]       metadata                 gainmap metadata descriptor
   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
   *                                           image
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t encodeJPEGR(uhdr_compressed_image_t* base_img_compressed,
                                uhdr_compressed_image_t* gainmap_img_compressed,
                                uhdr_gainmap_metadata_ext_t* metadata,
                                uhdr_compressed_image_t* dest);

  /*!\brief Decode API.
   *
   * Decompress ultrahdr jpeg image.
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
  uhdr_error_info_t decodeJPEGR(uhdr_compressed_image_t* uhdr_compressed_img,
                                uhdr_raw_image_t* dest, float max_display_boost = FLT_MAX,
                                uhdr_color_transfer_t output_ct = UHDR_CT_LINEAR,
                                uhdr_img_fmt_t output_format = UHDR_IMG_FMT_64bppRGBAHalfFloat,
                                uhdr_raw_image_t* gainmap_img = nullptr,
                                uhdr_gainmap_metadata_t* gainmap_metadata = nullptr);

  /*!\brief This function parses the bitstream and returns information that is useful for actual
   * decoding. This does not decode the image. That is handled by decodeJPEGR
   *
   * \param[in]       uhdr_compressed_img      compressed ultrahdr image descriptor
   * \param[in, out]  uhdr_image_info          image info descriptor
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t getJPEGRInfo(uhdr_compressed_image_t* uhdr_compressed_img,
                                 jr_info_ptr uhdr_image_info);

  /* \brief Alias of Encode API-0.
   *
   * \deprecated This function is deprecated. Use its alias
   */
  status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, ultrahdr_transfer_function hdr_tf,
                       jr_compressed_ptr dest, int quality, jr_exif_ptr exif);

  /* \brief Alias of Encode API-1.
   *
   * \deprecated This function is deprecated. Use its actual
   */
  status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, jr_uncompressed_ptr yuv420_image_ptr,
                       ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest, int quality,
                       jr_exif_ptr exif);

  /* \brief Alias of Encode API-2.
   *
   * \deprecated This function is deprecated. Use its actual
   */
  status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, jr_uncompressed_ptr yuv420_image_ptr,
                       jr_compressed_ptr yuv420jpg_image_ptr, ultrahdr_transfer_function hdr_tf,
                       jr_compressed_ptr dest);

  /* \brief Alias of Encode API-3.
   *
   * \deprecated This function is deprecated. Use its actual
   */
  status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, jr_compressed_ptr yuv420jpg_image_ptr,
                       ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest);

  /* \brief Alias of Encode API-4.
   *
   * \deprecated This function is deprecated. Use its actual
   */
  status_t encodeJPEGR(jr_compressed_ptr yuv420jpg_image_ptr,
                       jr_compressed_ptr gainmapjpg_image_ptr, ultrahdr_metadata_ptr metadata,
                       jr_compressed_ptr dest);

  /* \brief Alias of Decode API
   *
   * \deprecated This function is deprecated. Use its actual
   */
  status_t decodeJPEGR(jr_compressed_ptr jpegr_image_ptr, jr_uncompressed_ptr dest,
                       float max_display_boost = FLT_MAX, jr_exif_ptr exif = nullptr,
                       ultrahdr_output_format output_format = ULTRAHDR_OUTPUT_HDR_LINEAR,
                       jr_uncompressed_ptr gainmap_image_ptr = nullptr,
                       ultrahdr_metadata_ptr metadata = nullptr);

  /* \brief Alias of getJPEGRInfo
   *
   * \deprecated This function is deprecated. Use its actual
   */
  status_t getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpegr_image_info_ptr);

 private:
  /*!\brief compress gainmap image
   *
   * \param[in]       gainmap_img              gainmap image descriptor
   * \param[in]       jpeg_enc_obj             jpeg encoder object handle
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t compressGainMap(uhdr_raw_image_t* gainmap_img, JpegEncoderHelper* jpeg_enc_obj);

  /*!\brief This method is called to separate base image and gain map image from compressed
   * ultrahdr image
   *
   * \param[in]            jpegr_image               compressed ultrahdr image descriptor
   * \param[in, out]       primary_image             sdr image descriptor
   * \param[in, out]       gainmap_image             gainmap image descriptor
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t extractPrimaryImageAndGainMap(uhdr_compressed_image_t* jpegr_image,
                                                  uhdr_compressed_image_t* primary_image,
                                                  uhdr_compressed_image_t* gainmap_image);

  /*!\brief This function parses the bitstream and returns metadata that is useful for actual
   * decoding. This does not decode the image. That is handled by decompressImage().
   *
   * \param[in]            jpeg_image      compressed jpeg image descriptor
   * \param[in, out]       image_info      image info descriptor
   * \param[in, out]       img_width       (optional) image width
   * \param[in, out]       img_height      (optional) image height
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_info_ptr image_info,
                                  unsigned int* img_width = nullptr,
                                  unsigned int* img_height = nullptr);

  /*!\brief This method takes compressed sdr intent, compressed gainmap coefficient, gainmap
   * metadata and creates a ultrahdr image. This is done by first generating XMP packet from gainmap
   * metadata, then appending in the order,
   *    SOI, APP2 (Exif is present), APP2 (XMP), base image, gain map image.
   *
   * NOTE: In the final output, EXIF package will appear if ONLY ONE of the following conditions is
   * fulfilled:
   * (1) EXIF package is available from outside input. I.e. pExif != nullptr.
   * (2) Compressed sdr intent has EXIF.
   * If both conditions are fulfilled, this method will return error indicating that it is unable to
   * choose which exif to be placed in the bitstream.
   *
   * \param[in]       sdr_intent_compressed    sdr intent image descriptor
   * \param[in]       gainmap_compressed       gainmap intent input image descriptor
   * \param[in]       pExif                    exif block to be placed in the bitstream
   * \param[in]       pIcc                     pointer to icc segment that needs to be added to the
   *                                           compressed image
   * \param[in]       icc_size                 size of icc segment
   * \param[in]       metadata                 gainmap metadata descriptor
   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
   *                                           image
   *
   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
   */
  uhdr_error_info_t appendGainMap(uhdr_compressed_image_t* sdr_intent_compressed,
                                  uhdr_compressed_image_t* gainmap_compressed,
                                  uhdr_mem_block_t* pExif, void* pIcc, size_t icc_size,
                                  uhdr_gainmap_metadata_ext_t* metadata,
                                  uhdr_compressed_image_t* dest);

  /*
   * This method will check the validity of the input arguments.
   *
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param yuv420_image_ptr pointer to uncompressed SDR image struct. HDR image is expected to
   *                         be in 420p color format
   * @param hdr_tf transfer function of the HDR image
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the desitination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
   * @return NO_ERROR if the input args are valid, error code is not valid.
   */
  status_t areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
                                  jr_uncompressed_ptr yuv420_image_ptr,
                                  ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest_ptr);

  /*
   * This method will check the validity of the input arguments.
   *
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param yuv420_image_ptr pointer to uncompressed SDR image struct. HDR image is expected to
   *                         be in 420p color format
   * @param hdr_tf transfer function of the HDR image
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the destination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
   * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
   *                the highest quality
   * @return NO_ERROR if the input args are valid, error code is not valid.
   */
  status_t areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
                                  jr_uncompressed_ptr yuv420_image_ptr,
                                  ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest,
                                  int quality);
};

}  // namespace ultrahdr

#endif  // ULTRAHDR_JPEGR_H
