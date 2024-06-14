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

/** \file ultrahdr_api.h
 *
 *  \brief
 *  Describes the encoder or decoder algorithm interface to applications.
 */

#ifndef ULTRAHDR_API_H
#define ULTRAHDR_API_H

#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(UHDR_BUILDING_SHARED_LIBRARY)
#define UHDR_API __declspec(dllexport)
#elif defined(UHDR_USING_SHARED_LIBRARY)
#define UHDR_API __declspec(dllimport)
#else
#define UHDR_API
#endif
#elif defined(__GNUC__) && (__GNUC__ >= 4) && \
    (defined(UHDR_BUILDING_SHARED_LIBRARY) || defined(UHDR_USING_SHARED_LIBRARY))
#define UHDR_API __attribute__((visibility("default")))
#else
#define UHDR_API
#endif

#ifdef __cplusplus
#define UHDR_EXTERN extern "C" UHDR_API
#else
#define UHDR_EXTERN extern UHDR_API
#endif

// ===============================================================================================
// Enum Definitions
// ===============================================================================================

/*!\brief List of supported image formats */
typedef enum uhdr_img_fmt {
  UHDR_IMG_FMT_UNSPECIFIED = -1,   /**< Unspecified */
  UHDR_IMG_FMT_24bppYCbCrP010 = 0, /**< 10-bit-per component 4:2:0 YCbCr semiplanar format.
                               Each chroma and luma component has 16 allocated bits in
                               little-endian configuration with 10 MSB of actual data.*/
  UHDR_IMG_FMT_12bppYCbCr420 = 1,  /**< 8-bit-per component 4:2:0 YCbCr planar format */
  UHDR_IMG_FMT_8bppYCbCr400 = 2,   /**< 8-bit-per component Monochrome format */
  UHDR_IMG_FMT_32bppRGBA8888 =
      3, /**< 32 bits per pixel RGBA color format, with 8-bit red, green, blue
        and alpha components. Using 32-bit little-endian representation,
        colors stored as Red 7:0, Green 15:8, Blue 23:16, Alpha 31:24. */
  UHDR_IMG_FMT_64bppRGBAHalfFloat = 4, /**< 64 bits per pixel RGBA color format, with 16-bit signed
                                   floating point red, green, blue, and alpha components */
  UHDR_IMG_FMT_32bppRGBA1010102 = 5,   /**< 32 bits per pixel RGBA color format, with 10-bit red,
                                      green,   blue, and 2-bit alpha components. Using 32-bit
                                      little-endian   representation, colors stored as Red 9:0, Green
                                      19:10, Blue   29:20, and Alpha 31:30. */

  UHDR_IMG_FMT_24bppYCbCr444 = 6,  /**< 8-bit-per component 4:4:4 YCbCr planar format */
  UHDR_IMG_FMT_16bppYCbCr422 = 7,  /**< 8-bit-per component 4:2:2 YCbCr planar format */
  UHDR_IMG_FMT_16bppYCbCr440 = 8,  /**< 8-bit-per component 4:4:0 YCbCr planar format */
  UHDR_IMG_FMT_12bppYCbCr411 = 9,  /**< 8-bit-per component 4:1:1 YCbCr planar format */
  UHDR_IMG_FMT_10bppYCbCr410 = 10, /**< 8-bit-per component 4:1:0 YCbCr planar format */
  UHDR_IMG_FMT_24bppRGB888 = 11,   /**< 8-bit-per component RGB interleaved format */
} uhdr_img_fmt_t;                  /**< alias for enum uhdr_img_fmt */

/*!\brief List of supported color gamuts */
typedef enum uhdr_color_gamut {
  UHDR_CG_UNSPECIFIED = -1, /**< Unspecified */
  UHDR_CG_BT_709 = 0,       /**< BT.709 */
  UHDR_CG_DISPLAY_P3 = 1,   /**< Display P3 */
  UHDR_CG_BT_2100 = 2,      /**< BT.2100 */
} uhdr_color_gamut_t;       /**< alias for enum uhdr_color_gamut */

/*!\brief List of supported color transfers */
typedef enum uhdr_color_transfer {
  UHDR_CT_UNSPECIFIED = -1, /**< Unspecified */
  UHDR_CT_LINEAR = 0,       /**< Linear */
  UHDR_CT_HLG = 1,          /**< Hybrid log gamma */
  UHDR_CT_PQ = 2,           /**< Perceptual Quantizer */
  UHDR_CT_SRGB = 3,         /**< Gamma */
} uhdr_color_transfer_t;    /**< alias for enum uhdr_color_transfer */

/*!\brief List of supported color ranges */
typedef enum uhdr_color_range {
  UHDR_CR_UNSPECIFIED = -1,  /**< Unspecified */
  UHDR_CR_LIMITED_RANGE = 0, /**< Y {[16..235], UV [16..240]} * pow(2, (bpc - 8)) */
  UHDR_CR_FULL_RANGE = 1,    /**< YUV/RGB {[0..255]} * pow(2, (bpc - 8)) */
} uhdr_color_range_t;        /**< alias for enum uhdr_color_range */

/*!\brief List of supported codecs */
typedef enum uhdr_codec {
  UHDR_CODEC_JPG, /**< Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using
                  jpeg */
} uhdr_codec_t;   /**< alias for enum uhdr_codec */

/*!\brief Image identifiers in gain map technology */
typedef enum uhdr_img_label {
  UHDR_HDR_IMG,      /**< Hdr rendition image */
  UHDR_SDR_IMG,      /**< Sdr rendition image */
  UHDR_BASE_IMG,     /**< Base rendition image */
  UHDR_GAIN_MAP_IMG, /**< Gain map image */
} uhdr_img_label_t;  /**< alias for enum uhdr_img_label */

/*!\brief Algorithm return codes */
typedef enum uhdr_codec_err {

  /*!\brief Operation completed without error */
  UHDR_CODEC_OK,

  /*!\brief Unspecified error */
  UHDR_CODEC_UNKNOWN_ERROR,

  /*!\brief An application-supplied parameter is not valid. */
  UHDR_CODEC_INVALID_PARAM,

  /*!\brief Memory operation failed */
  UHDR_CODEC_MEM_ERROR,

  /*!\brief An application-invoked operation is not valid. */
  UHDR_CODEC_INVALID_OPERATION,

  /*!\brief The library does not implement a feature required for the operation */
  UHDR_CODEC_UNSUPPORTED_FEATURE,

  /*!\brief An iterator reached the end of list. */
  UHDR_CODEC_LIST_END,

} uhdr_codec_err_t; /**< alias for enum uhdr_codec_err */

// ===============================================================================================
// Structure Definitions
// ===============================================================================================

/*!\brief Detailed return status */
typedef struct uhdr_error_info {
  uhdr_codec_err_t error_code;
  int has_detail;
  char detail[256];
} uhdr_error_info_t; /**< alias for struct uhdr_error_info */

/**\brief Raw Image Descriptor */
typedef struct uhdr_raw_image {
  /* Color model, primaries, transfer, range */
  uhdr_img_fmt_t fmt;       /**< Image Format */
  uhdr_color_gamut_t cg;    /**< Color Gamut */
  uhdr_color_transfer_t ct; /**< Color Transfer */
  uhdr_color_range_t range; /**< Color Range */

  /* Image storage dimensions */
  unsigned int w; /**< Stored image width */
  unsigned int h; /**< Stored image height */

  /* Image data pointers. */
#define UHDR_PLANE_PACKED 0 /**< To be used for all packed formats */
#define UHDR_PLANE_Y 0      /**< Y (Luminance) plane */
#define UHDR_PLANE_U 1      /**< U (Chroma) plane */
#define UHDR_PLANE_UV 1     /**< UV (Chroma plane interleaved) To be used for semi planar format */
#define UHDR_PLANE_V 2      /**< V (Chroma) plane */
  void* planes[3];          /**< pointer to the top left pixel for each plane */
  unsigned int stride[3];   /**< stride in pixels between rows for each plane */
} uhdr_raw_image_t;         /**< alias for struct uhdr_raw_image */

/**\brief Compressed Image Descriptor */
typedef struct uhdr_compressed_image {
  void* data;               /**< Pointer to a block of data to decode */
  unsigned int data_sz;     /**< size of the data buffer */
  unsigned int capacity;    /**< maximum size of the data buffer */
  uhdr_color_gamut_t cg;    /**< Color Gamut */
  uhdr_color_transfer_t ct; /**< Color Transfer */
  uhdr_color_range_t range; /**< Color Range */
} uhdr_compressed_image_t;  /**< alias for struct uhdr_compressed_image */

/**\brief Buffer Descriptor */
typedef struct uhdr_mem_block {
  void* data;            /**< Pointer to a block of data to decode */
  unsigned int data_sz;  /**< size of the data buffer */
  unsigned int capacity; /**< maximum size of the data buffer */
} uhdr_mem_block_t;      /**< alias for struct uhdr_mem_block */

/**\brief Gain map metadata.
 * Note: all values stored in linear space. This differs from the metadata encoded in XMP, where
 * max_content_boost (aka gainMapMax), min_content_boost (aka gainMapMin), hdr_capacity_min, and
 * hdr_capacity_max are stored in log2 space.
 */
typedef struct uhdr_gainmap_metadata {
  float max_content_boost; /**< Max Content Boost for the map */
  float min_content_boost; /**< Min Content Boost for the map */
  float gamma;             /**< Gamma of the map data */
  float offset_sdr;        /**< Offset for SDR data in map calculations */
  float offset_hdr;        /**< Offset for HDR data in map calculations */
  float hdr_capacity_min;  /**< Min HDR capacity values for interpolating the Gain Map */
  float hdr_capacity_max;  /**< Max HDR capacity value for interpolating the Gain Map */
} uhdr_gainmap_metadata_t; /**< alias for struct uhdr_gainmap_metadata */

/**\brief ultrahdr codec context opaque descriptor */
typedef struct uhdr_codec_private uhdr_codec_private_t;

// ===============================================================================================
// Function Declarations
// ===============================================================================================

// ===============================================================================================
// Encoder APIs
// ===============================================================================================

/*!\brief Create a new encoder instance. The instance is initialized with default settings.
 * To override the settings use uhdr_enc_set_*()
 *
 * \return  nullptr if there was an error allocating memory else a fresh opaque encoder handle
 */
UHDR_EXTERN uhdr_codec_private_t* uhdr_create_encoder(void);

/*!\brief Release encoder instance.
 * Frees all allocated storage associated with encoder instance.
 *
 * \param[in]  enc  encoder instance.
 *
 * \return none
 */
UHDR_EXTERN void uhdr_release_encoder(uhdr_codec_private_t* enc);

/*!\brief Add raw image descriptor to encoder context. The function goes through all the fields of
 * the image descriptor and checks for their sanity. If no anomalies are seen then the image is
 * added to internal list. Repeated calls to this function will replace the old entry with the
 * current.
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  img  image descriptor.
 * \param[in]  intent  UHDR_HDR_IMG for hdr intent and UHDR_SDR_IMG for sdr intent.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc,
                                                     uhdr_raw_image_t* img,
                                                     uhdr_img_label_t intent);

/*!\brief Add compressed image descriptor to encoder context. The function goes through all the
 * fields of the image descriptor and checks for their sanity. If no anomalies are seen then the
 * image is added to internal list. Repeated calls to this function will replace the old entry with
 * the current.
 *
 * If both uhdr_enc_add_raw_image() and uhdr_enc_add_compressed_image() are called during a session
 * for the same intent, it is assumed that raw image descriptor and compressed image descriptor are
 * relatable via compress <-> decompress process.
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  img  image descriptor.
 * \param[in]  intent  UHDR_HDR_IMG for hdr intent,
 *                     UHDR_SDR_IMG for sdr intent,
 *                     UHDR_BASE_IMG for base image intent
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_compressed_image(uhdr_codec_private_t* enc,
                                                            uhdr_compressed_image_t* img,
                                                            uhdr_img_label_t intent);

/*!\brief Add gain map image descriptor and gainmap metadata info to encoder context. The function
 * internally goes through all the fields of the image descriptor and checks for their sanity. If no
 * anomalies are seen then the image is added to internal list. Repeated calls to this function will
 * replace the old entry with the current.
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  img  gain map image desciptor.
 * \param[in]  metadata  gainmap metadata descriptor
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_image(uhdr_codec_private_t* enc,
                                                         uhdr_compressed_image_t* img,
                                                         uhdr_gainmap_metadata_t* metadata);

/*!\brief Set quality for compression
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  quality  quality factor.
 * \param[in]  intent  UHDR_BASE_IMG for base image and UHDR_GAIN_MAP_IMG for gain map image.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_quality(uhdr_codec_private_t* enc, int quality,
                                                   uhdr_img_label_t intent);

/*!\brief Set Exif data that needs to be inserted in the output compressed stream
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  img  exif data descriptor.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_exif_data(uhdr_codec_private_t* enc,
                                                     uhdr_mem_block_t* exif);

/*!\brief Set flag of using multi-channel gainmap, default to false (use single channel gainmap)
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  use_multi_channel_gainmap  flag of using multi-channel gainmap.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_using_multi_channel_gainmap(uhdr_codec_private_t* enc,
                                                                       bool use_multi_channel_gainmap);

/*!\brief Set gain map scaling factor, default value is 4 (gain map dimension is 1/4 width and
 * 1/4 height in pixels of the primary image)
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  gain_map_scale_factor  gain map scale factor
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_scale_factor(uhdr_codec_private_t* enc,
                                                                int gain_map_scale_factor);

/*!\brief Set gain map gamma, default value is 1.0f
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  gamma  gain map gamma
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_gamma(uhdr_codec_private_t* enc,
                                                         float gamma);

/*!\brief Set output image compression format.
 *
 * \param[in]  enc  encoder instance.
 * \param[in]  media_type  output image compression format.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_output_format(uhdr_codec_private_t* enc,
                                                         uhdr_codec_t media_type);

/*!\brief Encode process call
 * After initializing the encoder context, call to this function will submit data for encoding. If
 * the call is successful, the encoded output is stored internally and is accessible via
 * uhdr_get_encoded_stream().
 *
 * The basic usage of uhdr encoder is as follows:
 * - The program creates an instance of an encoder using,
 *   - uhdr_create_encoder().
 * - The program registers input images to the encoder using,
 *   - uhdr_enc_set_raw_image(ctxt, img, UHDR_HDR_IMG)
 *   - uhdr_enc_set_raw_image(ctxt, img, UHDR_SDR_IMG)
 * - The program overrides the default settings using uhdr_enc_set_*() functions
 * - If the application wants to control the compression level
 *   - uhdr_enc_set_quality()
 * - If the application wants to insert exif data
 *   - uhdr_enc_set_exif_data()
 * - If the application wants to control target compression format
 *   - uhdr_enc_set_output_format()
 * - The program calls uhdr_encode() to encode data. This call would initiate the process of
 * computing gain map from hdr intent and sdr intent. The sdr intent and gain map image are
 * compressed at the set quality using the codec of choice.
 * - On success, the program can access the encoded output with uhdr_get_encoded_stream().
 * - The program finishes the encoding with uhdr_release_encoder().
 *
 * The library allows setting Hdr and/or Sdr intent in compressed format,
 * - uhdr_enc_set_compressed_image(ctxt, img, UHDR_HDR_IMG)
 * - uhdr_enc_set_compressed_image(ctxt, img, UHDR_SDR_IMG)
 * In this mode, the compressed image(s) are first decoded to raw image(s). These raw image(s) go
 * through the aforth mentioned gain map computation and encoding process. In this case, the usage
 * shall be like this:
 * - uhdr_create_encoder()
 * - uhdr_enc_set_compressed_image(ctxt, img, UHDR_HDR_IMG)
 * - uhdr_enc_set_compressed_image(ctxt, img, UHDR_SDR_IMG)
 * - uhdr_encode()
 * - uhdr_get_encoded_stream()
 * - uhdr_release_encoder()
 * If the set compressed image media type of intent UHDR_SDR_IMG and output media type are
 * identical, then this image is directly used for primary image. No re-encode of raw image is done.
 * This implies base image quality setting is un-used. Only gain map image is encoded at the set
 * quality using codec of choice. On the other hand, if the set compressed image media type and
 * output media type are different, then transcoding is done.
 *
 * The library also allows directly setting base and gain map image in compressed format,
 * - uhdr_enc_set_compressed_image(ctxt, img, UHDR_BASE_IMG)
 * - uhdr_enc_set_gainmap_image(ctxt, img, metadata)
 * In this mode, gain map computation is by-passed. The input images are transcoded (if necessary),
 * combined and sent back.
 *
 * It is possible to create a uhdr image solely from Hdr intent. In this case, the usage shall look
 * like this:
 * - uhdr_create_encoder()
 * - uhdr_enc_set_raw_image(ctxt, img, UHDR_HDR_IMG)
 * - uhdr_enc_set_quality() // optional
 * - uhdr_enc_set_exif_data() // optional
 * - uhdr_enc_set_output_format() // optional
 * - uhdr_encode()
 * - uhdr_get_encoded_stream()
 * - uhdr_release_encoder()
 * In this mode, the Sdr rendition is created from Hdr intent by tone-mapping. The tone-mapped sdr
 * image and hdr image go through the aforth mentioned gain map computation and encoding process to
 * create uhdr image.
 *
 * In all modes, Exif data is inserted if requested.
 *
 * \param[in]  enc  encoder instance.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc);

/*!\brief Get encoded ultra hdr stream
 *
 * \param[in]  enc  encoder instance.
 *
 * \return nullptr if encode process call is unsuccessful, uhdr image descriptor otherwise
 */
UHDR_EXTERN uhdr_compressed_image_t* uhdr_get_encoded_stream(uhdr_codec_private_t* enc);

/*!\brief Reset encoder instance.
 * Clears all previous settings and resets to default state and ready for re-initialization
 *
 * \param[in]  enc  encoder instance.
 *
 * \return none
 */
UHDR_EXTERN void uhdr_reset_encoder(uhdr_codec_private_t* enc);

// ===============================================================================================
// Decoder APIs
// ===============================================================================================

/*!\brief check if it is a valid ultrahdr image.
 *
 * @param[in]  data  pointer to input compressed stream
 * @param[in]  size  size of compressed stream
 *
 * @returns 1 if the input data has a primary image, gain map image and gain map metadata. 0
 * otherwise.
 */
UHDR_EXTERN int is_uhdr_image(void* data, int size);

/*!\brief Create a new decoder instance. The instance is initialized with default settings.
 * To override the settings use uhdr_dec_set_*()
 *
 * \return  nullptr if there was an error allocating memory else a fresh opaque decoder handle
 */
UHDR_EXTERN uhdr_codec_private_t* uhdr_create_decoder(void);

/*!\brief Release decoder instance.
 * Frees all allocated storage associated with decoder instance.
 *
 * \param[in]  dec  decoder instance.
 *
 * \return none
 */
UHDR_EXTERN void uhdr_release_decoder(uhdr_codec_private_t* dec);

/*!\brief Add compressed image descriptor to decoder context. The function goes through all the
 * fields of the image descriptor and checks for their sanity. If no anomalies are seen then the
 * image is added to internal list. Repeated calls to this function will replace the old entry with
 * the current.
 *
 * \param[in]  dec  decoder instance.
 * \param[in]  img  image descriptor.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_image(uhdr_codec_private_t* dec,
                                                 uhdr_compressed_image_t* img);

/*!\brief Set output image format
 *
 * \param[in]  dec  decoder instance.
 * \param[in]  fmt  output image format.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_out_img_format(uhdr_codec_private_t* dec,
                                                          uhdr_img_fmt_t fmt);

/*!\brief Set output color transfer
 *
 * \param[in]  dec  decoder instance.
 * \param[in]  ct  output color transfer
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_out_color_transfer(uhdr_codec_private_t* dec,
                                                              uhdr_color_transfer_t ct);

/*!\brief Set output max display boost
 *
 * \param[in]  dec  decoder instance.
 * \param[in]  display_boost  max display boost
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
 *                           #UHDR_CODEC_INVALID_PARAM otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_out_max_display_boost(uhdr_codec_private_t* dec,
                                                                 float display_boost);

/*!\brief This function parses the bitstream that is registered with the decoder context and makes
 * image information available to the client via uhdr_dec_get_() functions. It does not decompress
 * the image. That is done by uhdr_decode().
 *
 * \param[in]  dec  decoder instance.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_dec_probe(uhdr_codec_private_t* dec);

/*!\brief Get base image width
 *
 * \param[in]  dec  decoder instance.
 *
 * \return -1 if probe call is unsuccessful, base image width otherwise
 */
UHDR_EXTERN int uhdr_dec_get_image_width(uhdr_codec_private_t* dec);

/*!\brief Get base image height
 *
 * \param[in]  dec  decoder instance.
 *
 * \return -1 if probe call is unsuccessful, base image height otherwise
 */
UHDR_EXTERN int uhdr_dec_get_image_height(uhdr_codec_private_t* dec);

/*!\brief Get gainmap image width
 *
 * \param[in]  dec  decoder instance.
 *
 * \return -1 if probe call is unsuccessful, gain map image width otherwise
 */
UHDR_EXTERN int uhdr_dec_get_gainmap_width(uhdr_codec_private_t* dec);

/*!\brief Get gainmap image height
 *
 * \param[in]  dec  decoder instance.
 *
 * \return -1 if probe call is unsuccessful, gain map image height otherwise
 */
UHDR_EXTERN int uhdr_dec_get_gainmap_height(uhdr_codec_private_t* dec);

/*!\brief Get exif information
 *
 * \param[in]  dec  decoder instance.
 *
 * \return nullptr if probe call is unsuccessful, memory block with exif data otherwise
 */
UHDR_EXTERN uhdr_mem_block_t* uhdr_dec_get_exif(uhdr_codec_private_t* dec);

/*!\brief Get icc information
 *
 * \param[in]  dec  decoder instance.
 *
 * \return nullptr if probe call is unsuccessful, memory block with icc data otherwise
 */
UHDR_EXTERN uhdr_mem_block_t* uhdr_dec_get_icc(uhdr_codec_private_t* dec);

/*!\brief Get gain map metadata
 *
 * \param[in]  dec  decoder instance.
 *
 * \return nullptr if probe process call is unsuccessful, gainmap metadata descriptor otherwise
 */
UHDR_EXTERN uhdr_gainmap_metadata_t* uhdr_dec_get_gain_map_metadata(uhdr_codec_private_t* dec);

/*!\brief Decode process call
 * After initializing the decoder context, call to this function will submit data for decoding. If
 * the call is successful, the decoded output is stored internally and is accessible via
 * uhdr_get_decoded_image().
 *
 * The basic usage of uhdr decoder is as follows:
 * - The program creates an instance of a decoder using,
 *   - uhdr_create_decoder().
 * - The program registers input images to the decoder using,
 *   - uhdr_dec_set_image(ctxt, img)
 * - The program overrides the default settings using uhdr_dec_set_*() functions.
 * - If the application wants to control the output image format,
 *   - uhdr_dec_set_out_img_format()
 * - If the application wants to control the output transfer characteristics,
 *   - uhdr_dec_set_out_color_transfer()
 * - If the application wants to control the output display boost,
 *   - uhdr_dec_set_out_max_display_boost()
 * - The program calls uhdr_decode() to decode uhdr stream. This call would initiate the process
 * of decoding base image and gain map image. These two are combined to give the final rendition
 * image.
 * - The program can access the decoded output with uhdr_get_decoded_image().
 * - The program finishes the decoding with uhdr_release_decoder().
 *
 * \param[in]  dec  decoder instance.
 *
 * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
 */
UHDR_EXTERN uhdr_error_info_t uhdr_decode(uhdr_codec_private_t* dec);

/*!\brief Get final rendition image
 *
 * \param[in]  dec  decoder instance.
 *
 * \return nullptr if decoded process call is unsuccessful, raw image descriptor otherwise
 */
UHDR_EXTERN uhdr_raw_image_t* uhdr_get_decoded_image(uhdr_codec_private_t* dec);

/*!\brief Get gain map image
 *
 * \param[in]  dec  decoder instance.
 *
 * \return nullptr if decoded process call is unsuccessful, raw image descriptor otherwise
 */
UHDR_EXTERN uhdr_raw_image_t* uhdr_get_gain_map_image(uhdr_codec_private_t* dec);

/*!\brief Reset decoder instance.
 * Clears all previous settings and resets to default state and ready for re-initialization
 *
 * \param[in]  dec  decoder instance.
 *
 * \return none
 */
UHDR_EXTERN void uhdr_reset_decoder(uhdr_codec_private_t* dec);

#endif  // ULTRAHDR_API_H
