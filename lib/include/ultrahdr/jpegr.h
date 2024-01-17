/*
 * Copyright 2022 The Android Open Source Project
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

#ifndef ULTRAHDR_JPEGR_H
#define ULTRAHDR_JPEGR_H

#include <cfloat>

#include "ultrahdr/ultrahdr.h"
#include "ultrahdr/jpegdecoderhelper.h"
#include "ultrahdr/jpegencoderhelper.h"

namespace ultrahdr {

/*
 * jpegr encoder/decoder supported limits
 */
extern const char kJpegrVersion[];
extern const size_t kMapDimensionScaleFactor;
extern const int kMinWidth;
extern const int kMinHeight;

/*
 * Holds information of jpeg image
 */
struct jpeg_info_struct {
  std::vector<uint8_t> imgData = std::vector<uint8_t>(0);
  std::vector<uint8_t> iccData = std::vector<uint8_t>(0);
  std::vector<uint8_t> exifData = std::vector<uint8_t>(0);
  std::vector<uint8_t> xmpData = std::vector<uint8_t>(0);
  size_t width = 0;
  size_t height = 0;
};

/*
 * Holds information of jpegr image
 */
struct jpegr_info_struct {
  size_t width = 0;   // copy of primary image width (for easier access)
  size_t height = 0;  // copy of primary image height (for easier access)
  jpeg_info_struct* primaryImgInfo = nullptr;
  jpeg_info_struct* gainmapImgInfo = nullptr;
};

typedef struct jpeg_info_struct* j_info_ptr;
typedef struct jpegr_info_struct* jr_info_ptr;

class JpegR {
 public:
  /*
   * Experimental only
   *
   * Encode API-0
   * Compress JPEGR image from 10-bit HDR YUV.
   *
   * Tonemap the HDR input to a SDR image, generate gain map from the HDR and SDR images,
   * compress SDR YUV to 8-bit JPEG and append the gain map to the end of the compressed
   * JPEG.
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param hdr_tf transfer function of the HDR image
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the destination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
   *                the highest quality
   * @param exif pointer to the exif metadata.
   * @return NO_ERROR if encoding succeeds, error code if error occurs.
   */
  status_t encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr, ultrahdr_transfer_function hdr_tf,
                       ultrahdr_compressed_ptr dest, int quality, ultrahdr_exif_ptr exif);

  /*
   * Encode API-1
   * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
   *
   * Generate gain map from the HDR and SDR inputs, compress SDR YUV to 8-bit JPEG and append
   * the gain map to the end of the compressed JPEG. HDR and SDR inputs must be the same
   * resolution. SDR input is assumed to use the sRGB transfer function.
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
   * @param hdr_tf transfer function of the HDR image
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the desitination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
   *                the highest quality
   * @param exif pointer to the exif metadata.
   * @return NO_ERROR if encoding succeeds, error code if error occurs.
   */
  status_t encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                       ultrahdr_uncompressed_ptr yuv420_image_ptr,
                       ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest, int quality,
                       ultrahdr_exif_ptr exif);

  /*
   * Encode API-2
   * Compress JPEGR image from 10-bit HDR YUV, 8-bit SDR YUV and compressed 8-bit JPEG.
   *
   * This method requires HAL Hardware JPEG encoder.
   *
   * Generate gain map from the HDR and SDR inputs, append the gain map to the end of the
   * compressed JPEG. Adds an ICC profile if one isn't present in the input JPEG image. HDR and
   * SDR inputs must be the same resolution and color space. SDR image is assumed to use the sRGB
   * transfer function.
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
   * @param yuv420jpg_image_ptr SDR image compressed in jpeg format
   * @param hdr_tf transfer function of the HDR image
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the desitination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @return NO_ERROR if encoding succeeds, error code if error occurs.
   */
  status_t encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                       ultrahdr_uncompressed_ptr yuv420_image_ptr,
                       ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                       ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest);

  /*
   * Encode API-3
   * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
   *
   * This method requires HAL Hardware JPEG encoder.
   *
   * Decode the compressed 8-bit JPEG image to YUV SDR, generate gain map from the HDR input
   * and the decoded SDR result, append the gain map to the end of the compressed JPEG. Adds an
   * ICC profile if one isn't present in the input JPEG image. HDR and SDR inputs must be the same
   * resolution. JPEG image is assumed to use the sRGB transfer function.
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param yuv420jpg_image_ptr SDR image compressed in jpeg format
   * @param hdr_tf transfer function of the HDR image
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the desitination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @return NO_ERROR if encoding succeeds, error code if error occurs.
   */
  status_t encodeJPEGR(ultrahdr_uncompressed_ptr p010_image_ptr,
                       ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                       ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest);

  /*
   * Encode API-4
   * Assemble JPEGR image from SDR JPEG and gainmap JPEG.
   *
   * Assemble the primary JPEG image, the gain map and the metadata to JPEG/R format. Adds an ICC
   * profile if one isn't present in the input JPEG image.
   * @param yuv420jpg_image_ptr SDR image compressed in jpeg format
   * @param gainmapjpg_image_ptr gain map image compressed in jpeg format
   * @param metadata metadata to be written in XMP of the primary jpeg
   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
   *             represents the maximum available size of the desitination buffer, and it must be
   *             set before calling this method. If the encoded JPEGR size exceeds
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @return NO_ERROR if encoding succeeds, error code if error occurs.
   */
  status_t encodeJPEGR(ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                       ultrahdr_compressed_ptr gainmapjpg_image_ptr, ultrahdr_metadata_ptr metadata,
                       ultrahdr_compressed_ptr dest);

  /*
   * Decode API
   * Decompress JPEGR image.
   *
   * This method assumes that the JPEGR image contains an ICC profile with primaries that match
   * those of a color gamut that this library is aware of; Bt.709, Display-P3, or Bt.2100. It also
   * assumes the base image uses the sRGB transfer function.
   *
   * This method only supports single gain map metadata values for fields that allow multi-channel
   * metadata values.
   * @param jpegr_image_ptr compressed JPEGR image.
   * @param dest destination of the uncompressed JPEGR image.
   * @param max_display_boost (optional) the maximum available boost supported by a display,
   *                          the value must be greater than or equal to 1.0.
   * @param exif destination of the decoded EXIF metadata. The default value is NULL where the
                 decoder will do nothing about it. If configured not NULL the decoder will write
                 EXIF data into this structure. The format is defined in
                 {@code ultrahdr_exif_struct}
   * @param output_format flag for setting output color format. Its value configures the output
                          color format. The default value is {@code JPEGR_OUTPUT_HDR_LINEAR}.
                          ----------------------------------------------------------------------
                          |      output_format       |    decoded color format to be written   |
                          ----------------------------------------------------------------------
                          |     JPEGR_OUTPUT_SDR     |                RGBA_8888                |
                          ----------------------------------------------------------------------
                          | JPEGR_OUTPUT_HDR_LINEAR  |        (default)RGBA_F16 linear         |
                          ----------------------------------------------------------------------
                          |   JPEGR_OUTPUT_HDR_PQ    |             RGBA_1010102 PQ             |
                          ----------------------------------------------------------------------
                          |   JPEGR_OUTPUT_HDR_HLG   |            RGBA_1010102 HLG             |
                          ----------------------------------------------------------------------
   * @param gainmap_image_ptr destination of the decoded gain map. The default value is NULL
                              where the decoder will do nothing about it. If configured not NULL
                              the decoder will write the decoded gain_map data into this
                              structure. The format is defined in
                              {@code ultrahdr_uncompressed_struct}.
   * @param metadata destination of the decoded metadata. The default value is NULL where the
                     decoder will do nothing about it. If configured not NULL the decoder will
                     write metadata into this structure. the format of metadata is defined in
                     {@code ultrahdr_metadata_struct}.
   * @return NO_ERROR if decoding succeeds, error code if error occurs.
   */
  status_t decodeJPEGR(ultrahdr_compressed_ptr jpegr_image_ptr, ultrahdr_uncompressed_ptr dest,
                       float max_display_boost = FLT_MAX, ultrahdr_exif_ptr exif = nullptr,
                       ultrahdr_output_format output_format = ULTRAHDR_OUTPUT_HDR_LINEAR,
                       ultrahdr_uncompressed_ptr gainmap_image_ptr = nullptr,
                       ultrahdr_metadata_ptr metadata = nullptr);

  /*
   * Gets Info from JPEGR file without decoding it.
   *
   * This method only supports single gain map metadata values for fields that allow multi-channel
   * metadata values.
   *
   * The output is filled jpegr_info structure
   * @param jpegr_image_ptr compressed JPEGR image
   * @param jpeg_image_info_ptr pointer to jpegr info struct. Members of jpegr_info
   *                            are owned by the caller
   * @return NO_ERROR if JPEGR parsing succeeds, error code otherwise
   */
  status_t getJPEGRInfo(ultrahdr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpeg_image_info_ptr);

 protected:
  /*
   * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
   * 10-bit yuv images as input, and calculate the uncompressed gain map. The input images
   * must be the same resolution. The SDR input is assumed to use the sRGB transfer function.
   *
   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
   * @param p010_image_ptr uncompressed HDR image in P010 color format
   * @param hdr_tf transfer function of the HDR image
   * @param metadata everything but "version" is filled in this struct
   * @param dest location at which gain map image is stored (caller responsible for memory
                 of data).
   * @param sdr_is_601 if true, then use BT.601 decoding of YUV regardless of SDR image gamut
   * @return NO_ERROR if calculation succeeds, error code if error occurs.
   */
  status_t generateGainMap(ultrahdr_uncompressed_ptr yuv420_image_ptr,
                           ultrahdr_uncompressed_ptr p010_image_ptr,
                           ultrahdr_transfer_function hdr_tf, ultrahdr_metadata_ptr metadata,
                           ultrahdr_uncompressed_ptr dest, bool sdr_is_601 = false);

  /*
   * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
   * 8-bit yuv image, the uncompressed (decoded) gain map, and extracted JPEG/R metadata as
   * input, and calculate the 10-bit recovered image. The recovered output image is the same
   * color gamut as the SDR image, with HLG transfer function, and is in RGBA1010102 data format.
   * The SDR image is assumed to use the sRGB transfer function. The SDR image is also assumed to
   * be a decoded JPEG for the purpose of YUV interpration.
   *
   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
   * @param gainmap_image_ptr pointer to uncompressed gain map image struct.
   * @param metadata JPEG/R metadata extracted from XMP.
   * @param output_format flag for setting output color format. if set to
   *                      {@code JPEGR_OUTPUT_SDR}, decoder will only decode the primary image
   *                      which is SDR. Default value is JPEGR_OUTPUT_HDR_LINEAR.
   * @param max_display_boost the maximum available boost supported by a display
   * @param dest reconstructed HDR image
   * @return NO_ERROR if calculation succeeds, error code if error occurs.
   */
  status_t applyGainMap(ultrahdr_uncompressed_ptr yuv420_image_ptr,
                        ultrahdr_uncompressed_ptr gainmap_image_ptr, ultrahdr_metadata_ptr metadata,
                        ultrahdr_output_format output_format, float max_display_boost,
                        ultrahdr_uncompressed_ptr dest);

 private:
  /*
   * This method is called in the encoding pipeline. It will encode the gain map.
   *
   * @param gainmap_image_ptr pointer to uncompressed gain map image struct
   * @param jpeg_enc_obj_ptr helper resource to compress gain map
   * @return NO_ERROR if encoding succeeds, error code if error occurs.
   */
  status_t compressGainMap(ultrahdr_uncompressed_ptr gainmap_image_ptr,
                           JpegEncoderHelper* jpeg_enc_obj_ptr);

  /*
   * This method is called to separate primary image and gain map image from JPEGR
   *
   * @param jpegr_image_ptr pointer to compressed JPEGR image.
   * @param primary_jpg_image_ptr destination of primary image
   * @param gainmap_jpg_image_ptr destination of compressed gain map image
   * @return NO_ERROR if calculation succeeds, error code if error occurs.
   */
  status_t extractPrimaryImageAndGainMap(ultrahdr_compressed_ptr jpegr_image_ptr,
                                         ultrahdr_compressed_ptr primary_jpg_image_ptr,
                                         ultrahdr_compressed_ptr gainmap_jpg_image_ptr);

  /*
   * Gets Info from JPEG image without decoding it.
   *
   * The output is filled jpeg_info structure
   * @param jpegr_image_ptr compressed JPEG image
   * @param jpeg_image_info_ptr pointer to jpeg info struct. Members of jpeg_info_struct
   *                            are owned by the caller
   * @param img_width (optional) pointer to store width of jpeg image
   * @param img_height (optional) pointer to store height of jpeg image
   * @return NO_ERROR if JPEGR parsing succeeds, error code otherwise
   */
  status_t parseJpegInfo(ultrahdr_compressed_ptr jpeg_image_ptr, j_info_ptr jpeg_image_info_ptr,
                         size_t* img_width = nullptr, size_t* img_height = nullptr);

  /*
   * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image,
   * the compressed gain map and optionally the exif package as inputs, and generate the XMP
   * metadata, and finally append everything in the order of:
   *     SOI, APP2(EXIF) (if EXIF is from outside), APP2(XMP), primary image, gain map
   *
   * Note that in the final JPEG/R output, EXIF package will appear if ONLY ONE of the following
   * conditions is fulfilled:
   *  (1) EXIF package is available from outside input. I.e. pExif != nullptr.
   *  (2) Input JPEG has EXIF.
   * If both conditions are fulfilled, this method will return ERROR_UHDR_INVALID_INPUT_TYPE
   *
   * @param primary_jpg_image_ptr destination of primary image
   * @param gainmap_jpg_image_ptr destination of compressed gain map image
   * @param (nullable) pExif EXIF package
   * @param (nullable) pIcc ICC package
   * @param icc_size length in bytes of ICC package
   * @param metadata JPEG/R metadata to encode in XMP of the jpeg
   * @param dest compressed JPEGR image
   * @return NO_ERROR if calculation succeeds, error code if error occurs.
   */
  status_t appendGainMap(ultrahdr_compressed_ptr primary_jpg_image_ptr,
                         ultrahdr_compressed_ptr gainmap_jpg_image_ptr, ultrahdr_exif_ptr pExif,
                         void* pIcc, size_t icc_size, ultrahdr_metadata_ptr metadata,
                         ultrahdr_compressed_ptr dest);

  /*
   * This method will tone map a HDR image to an SDR image.
   *
   * @param src pointer to uncompressed HDR image struct. HDR image is expected to be
   *            in p010 color format
   * @param dest pointer to store tonemapped SDR image
   */
  status_t toneMap(ultrahdr_uncompressed_ptr src, ultrahdr_uncompressed_ptr dest);

  /*
   * This method will convert a YUV420 image from one YUV encoding to another in-place (eg.
   * Bt.709 to Bt.601 YUV encoding).
   *
   * src_encoding and dest_encoding indicate the encoding via the YUV conversion defined for that
   * gamut. P3 indicates Rec.601, since this is how DataSpace encodes Display-P3 YUV data.
   *
   * @param image the YUV420 image to convert
   * @param src_encoding input YUV encoding
   * @param dest_encoding output YUV encoding
   * @return NO_ERROR if calculation succeeds, error code if error occurs.
   */
  status_t convertYuv(ultrahdr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
                      ultrahdr_color_gamut dest_encoding);

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
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @return NO_ERROR if the input args are valid, error code is not valid.
   */
  status_t areInputArgumentsValid(ultrahdr_uncompressed_ptr p010_image_ptr,
                                  ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                  ultrahdr_transfer_function hdr_tf,
                                  ultrahdr_compressed_ptr dest_ptr);

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
   *             {@code maxLength}, this method will return {@code ERROR_UHDR_BUFFER_TOO_SMALL}.
   * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
   *                the highest quality
   * @return NO_ERROR if the input args are valid, error code is not valid.
   */
  status_t areInputArgumentsValid(ultrahdr_uncompressed_ptr p010_image_ptr,
                                  ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                  ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                                  int quality);
};
}  // namespace ultrahdr

#endif  // ULTRAHDR_JPEGR_H
