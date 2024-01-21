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

/**
 * @file     ultrahdr_api.h
 * @brief    libultrahdr API interface declarations / definitions
 */

#ifndef ULTRAHDR_ULTRAHDR_API_H
#define ULTRAHDR_ULTRAHDR_API_H

#include <stddef.h>

// ===============================================================================================
// Enum Definitions
// ===============================================================================================

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

// error codes
typedef enum {
  UHDR_NO_ERROR = 0,
  UHDR_UNKNOWN_ERROR = -1,

  UHDR_IO_ERROR_BASE = -10000,
  ERROR_UHDR_BAD_PTR = UHDR_IO_ERROR_BASE - 1,
  ERROR_UHDR_UNSUPPORTED_WIDTH_HEIGHT = UHDR_IO_ERROR_BASE - 2,
  ERROR_UHDR_INVALID_COLORGAMUT = UHDR_IO_ERROR_BASE - 3,
  ERROR_UHDR_INVALID_STRIDE = UHDR_IO_ERROR_BASE - 4,
  ERROR_UHDR_INVALID_TRANS_FUNC = UHDR_IO_ERROR_BASE - 5,
  ERROR_UHDR_RESOLUTION_MISMATCH = UHDR_IO_ERROR_BASE - 6,
  ERROR_UHDR_INVALID_QUALITY_FACTOR = UHDR_IO_ERROR_BASE - 7,
  ERROR_UHDR_INVALID_DISPLAY_BOOST = UHDR_IO_ERROR_BASE - 8,
  ERROR_UHDR_INVALID_OUTPUT_FORMAT = UHDR_IO_ERROR_BASE - 9,
  ERROR_UHDR_BAD_METADATA = UHDR_IO_ERROR_BASE - 10,
  ERROR_UHDR_INVALID_CROPPING_PARAMETERS = UHDR_IO_ERROR_BASE - 11,
  ERROR_UHDR_INVALID_PIXEL_FORMAT = UHDR_IO_ERROR_BASE - 12,

  UHDR_RUNTIME_ERROR_BASE = -20000,
  ERROR_UHDR_ENCODE_ERROR = UHDR_RUNTIME_ERROR_BASE - 1,
  ERROR_UHDR_DECODE_ERROR = UHDR_RUNTIME_ERROR_BASE - 2,
  ERROR_UHDR_GAIN_MAP_IMAGE_NOT_FOUND = UHDR_RUNTIME_ERROR_BASE - 3,
  ERROR_UHDR_BUFFER_TOO_SMALL = UHDR_RUNTIME_ERROR_BASE - 4,
  ERROR_UHDR_METADATA_ERROR = UHDR_RUNTIME_ERROR_BASE - 5,
  ERROR_UHDR_NO_IMAGES_FOUND = UHDR_RUNTIME_ERROR_BASE - 6,
  ERROR_UHDR_MULTIPLE_EXIFS_RECEIVED = UHDR_RUNTIME_ERROR_BASE - 7,
  ERROR_UHDR_UNSUPPORTED_MAP_SCALE_FACTOR = UHDR_RUNTIME_ERROR_BASE - 8,

  ERROR_UHDR_UNSUPPORTED_FEATURE = -30000,
} status_t;

// ===============================================================================================
// Structure Definitions
// ===============================================================================================

/**
 * @struct ultrahdr_uncompressed_struct
 * @brief Object type to hold uncompressed yuv data.
 */
struct ultrahdr_uncompressed_struct {
  // Pointer to the data location.
  void* data;
  // Width of luma plane of the image in pixels.
  size_t width;
  // Height of luma plane of the image in pixels.
  size_t height;
  // Color gamut.
  ultrahdr_color_gamut colorGamut;
  // Pixel format.
  ultrahdr_pixel_format pixelFormat;

  // Pointer to chroma data, if it's NULL, chroma plane is considered to be immediately
  // after the luma plane.
  void* chroma_data;
  // Stride of Y plane in number of pixels. 0 indicates the member is uninitialized. If
  // non-zero this value must be larger than or equal to luma width. If stride is
  // uninitialized then it is assumed to be equal to luma width.
  size_t luma_stride;
  // Stride of UV plane in number of pixels.
  // 1. If this handle points to P010 image then this value must be larger than
  //    or equal to luma width.
  // 2. If this handle points to 420 image then this value must be larger than
  //    or equal to (luma width / 2).
  // NOTE: if chroma_data is nullptr, chroma_stride is irrelevant. Just as the way,
  // chroma_data is derived from luma ptr, chroma stride is derived from luma stride.
  size_t chroma_stride;
};

/**
 * @struct ultrahdr_compressed_struct
 * @brief Object type to hold compressed image data.
 */
struct ultrahdr_compressed_struct {
  // Pointer to the data location.
  void* data;
  // Used data length in bytes.
  int length;
  // Maximum available data length in bytes.
  int maxLength;
  // Color gamut.
  ultrahdr_color_gamut colorGamut;
};

/**
 * @struct ultrahdr_buffer_wrapper
 * @brief Generic ultrahdr buffer object
 */
struct ultrahdr_buffer_wrapper {
  // Pointer to the data location.
  void* data;
  // Data length;
  size_t length;
};

/**
 * @struct image_attributes_struct
 * @brief Object type to hold compressed image attributes
 */
struct image_attributes_struct {
  struct ultrahdr_buffer_wrapper imgData;
  struct ultrahdr_buffer_wrapper iccData;
  struct ultrahdr_buffer_wrapper exifData;
  struct ultrahdr_buffer_wrapper xmpData;
  size_t width;
  size_t height;
};

/**
 * @struct ultrahdr_attributes_struct
 * @brief Object type to hold ultrahdr image attributes
 */
struct ultrahdr_attributes_struct {
  struct image_attributes_struct primaryImage;
  struct image_attributes_struct gainmapImage;
};

/**
 * @struct ultrahdr_metadata_struct
 * @brief Holds information for gain map related metadata.
 *
 * Note: all values stored in linear. This differs from the metadata encoding in XMP, where
 * maxContentBoost (aka gainMapMax), minContentBoost (aka gainMapMin), hdrCapacityMin, and
 * hdrCapacityMax are stored in log2 space.
 */
struct ultrahdr_metadata_struct {
  // Ultra HDR format version
  char version[8];
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

// ===============================================================================================
// Type Definitions
// ===============================================================================================

typedef struct ultrahdr_uncompressed_struct* ultrahdr_uncompressed_ptr;
typedef struct ultrahdr_compressed_struct* ultrahdr_compressed_ptr;
typedef struct ultrahdr_buffer_wrapper ultrahdr_exif_struct;
typedef struct ultrahdr_buffer_wrapper* ultrahdr_exif_ptr;
typedef struct image_attributes_struct* image_attributes_ptr;
typedef struct ultrahdr_attributes_struct* ultrahdr_attributes_ptr;
typedef struct ultrahdr_metadata_struct* ultrahdr_metadata_ptr;

// ===============================================================================================
// Function Macros
// ===============================================================================================

#define ULTRAHDR_CHECK(x)            \
  {                                  \
    status_t status = (x);           \
    if ((status) != UHDR_NO_ERROR) { \
      return status;                 \
    }                                \
  }

// ===============================================================================================
// Function Declarations
// ===============================================================================================

#ifdef __cplusplus
extern "C" {
#endif

// ===============================================================================================
// Encoder APIs
// ===============================================================================================

/**
 * @brief ultrahdr_compress_api0 - [Compress a 10-bit HDR YUV image]
 *
 * Experimental only.
 *
 * Briefly, the HDR 10-bit input is first tone-mapped to an SDR 8-bit image. Then, a gain map
 * is generated from HDR and SDR images. The SDR 8-bit YUV image and the gain map image are
 * compressed using an image compression library. These two images are signalled together using
 * multi-picture format syntax.
 *
 * @param[in] p010_image_ptr handle to an uncompressed HDR image in P010 color format
 * @param[in] hdr_tf transfer function of the HDR image
 * @param[in,out] dest destination of the compressed ultrahdr image. Please note that the fields
 *                     data and maxLength of ultrahdr_compressed_struct represents the destination
 *                     buffer and the maximum available size. These must be set before calling
 *                     this method. If the encoded output size exceeds maxLength then this method
 *                     will return ERROR_UHDR_BUFFER_TOO_SMALL
 * @param[in] quality Target quality of the encoding, must be in range of 0-100 where 100 is
 *                    the highest quality
 * @param[in] exif pointer to exif metadata of the input image.
 * @return status_t UHDR_NO_ERROR if encoding succeeds, error code otherwise.
 */
status_t ultrahdr_compress_api0(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                                int quality, ultrahdr_exif_ptr exif);

/**
 * @brief ultrahdr_compress_api1 - [Compress a 10-bit HDR YUV image]
 *
 * This function receives a HDR 10-bit YUV image and its tone-mapped SDR 8-bit YUV image as input.
 * Using these, a gain map is generated. The SDR 8-bit YUV image and the gain map image are
 * compressed using an image compression library. These two images are signalled together using
 * multi-picture format syntax.
 *
 * NOTES: SDR 8-bit input is assumed to use the sRGB transfer function.
 *
 * @param[in] p010_image_ptr handle to an uncompressed HDR image in P010 color format
 * @param[in] yuv420_image_ptr handle to an uncompressed SDR image in YUV420 color format
 * @param[in] hdr_tf transfer function of the HDR image
 * @param[in,out] dest destination of the compressed ultrahdr image. Please note that the fields
 *                     data and maxLength of ultrahdr_compressed_struct represents the destination
 *                     buffer and the maximum available size. These must be set before calling
 *                     this method. If the encoded output size exceeds maxLength then this method
 *                     will return ERROR_UHDR_BUFFER_TOO_SMALL
 * @param[in] quality Target quality of the encoding, must be in range of 0-100 where 100 is
 *                    the highest quality
 * @param[in] exif pointer to exif metadata of the input image.
 * @return status_t UHDR_NO_ERROR if encoding succeeds, error code otherwise.
 */
status_t ultrahdr_compress_api1(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest,
                                int quality, ultrahdr_exif_ptr exif);

/**
 * @brief ultrahdr_compress_api2 - [Compress a 10-bit HDR YUV image]
 *
 * This function receives a HDR 10-bit YUV image and its tone-mapped SDR 8-bit YUV image,
 * tone-mapped SDR 8-bit compressed image as input. Using the HDR and SDR YUV images a
 * gain map is generated. This gain map is compressed. The two compressed images are
 * signalled together using multi-picture format syntax.
 *
 * NOTES: 1. SDR 8-bit input is assumed to use the sRGB transfer function.
 *        2. Adds an ICC profile if one isn't present in the input compressed image
 *
 * @param[in] p010_image_ptr handle to an uncompressed HDR image in P010 color format
 * @param[in] yuv420_image_ptr handle to an uncompressed SDR image in YUV420 color format
 * @param[in] yuv420jpg_image_ptr handle to compressed SDR image
 * @param[in] hdr_tf transfer function of the HDR image
 * @param[in,out] dest destination of the compressed ultrahdr image. Please note that the fields
 *                     data and maxLength of ultrahdr_compressed_struct represents the destination
 *                     buffer and the maximum available size. These must be set before calling
 *                     this method. If the encoded output size exceeds maxLength then this method
 *                     will return ERROR_UHDR_BUFFER_TOO_SMALL
 * @return status_t UHDR_NO_ERROR if encoding succeeds, error code otherwise.
 */
status_t ultrahdr_compress_api2(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_uncompressed_ptr yuv420_image_ptr,
                                ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest);

/**
 * @brief ultrahdr_compress_api3 - [Compress a 10-bit HDR YUV image]
 *
 * This function receives a HDR 10-bit image and its tone-mapped SDR 8-bit compressed image as
 * input. The SDR image is decoded to create an SDR YUV. Using the HDR and SDR YUV images a
 * gain map is generated. This gain map is compressed. The two compressed images are signalled
 * together using multi-picture format syntax.
 *
 * NOTES: 1. SDR 8-bit input is assumed to use the sRGB transfer function.
 *        2. Adds an ICC profile if one isn't present in the input compressed image
 *
 * @param[in] p010_image_ptr handle to an uncompressed HDR image in P010 color format
 * @param[in] yuv420jpg_image_ptr handle to compressed SDR image
 * @param[in] hdr_tf transfer function of the HDR image
 * @param[in,out] dest destination of the compressed ultrahdr image. Please note that the fields
 *                     data and maxLength of ultrahdr_compressed_struct represents the destination
 *                     buffer and the maximum available size. These must be set before calling
 *                     this method. If the encoded output size exceeds maxLength then this method
 *                     will return ERROR_UHDR_BUFFER_TOO_SMALL
 * @return status_t UHDR_NO_ERROR if encoding succeeds, error code otherwise.
 */
status_t ultrahdr_compress_api3(ultrahdr_uncompressed_ptr p010_image_ptr,
                                ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                                ultrahdr_transfer_function hdr_tf, ultrahdr_compressed_ptr dest);

/**
 * @brief ultrahdr_compress_api4 - [Assemble ultrahdr image from compressed SDR and gainmap images]
 *
 * This function receives a compressed SDR and gain map images as input. These two are signalled
 * together using multi-picture format syntax.
 *
 * NOTES: 1. Adds an ICC profile if one isn't present in the input compressed image
 *
 * @param[in] yuv420jpg_image_ptr handle to compressed SDR image
 * @param[in] gainmapjpg_image_ptr handle to gain map compressed image
 * @param[in] metadata metadata to be written in XMP of the primary jpeg
 * @param[in,out] dest destination of the compressed ultrahdr image. Please note that the fields
 *                     data and maxLength of ultrahdr_compressed_struct represents the destination
 *                     buffer and the maximum available size. These must be set before calling
 *                     this method. If the encoded output size exceeds maxLength then this method
 *                     will return ERROR_UHDR_BUFFER_TOO_SMALL
 * @return status_t UHDR_NO_ERROR if encoding succeeds, error code otherwise.
 */
status_t ultrahdr_compress_api4(ultrahdr_compressed_ptr yuv420jpg_image_ptr,
                                ultrahdr_compressed_ptr gainmapjpg_image_ptr,
                                ultrahdr_metadata_ptr metadata, ultrahdr_compressed_ptr dest);

// ===============================================================================================
// Decoder APIs
// ===============================================================================================

/**
 * @brief get primary image dimensions
 *
 * @param[in] ultrahdr_image_ptr handle to compressed ultrahdr image.
 * @param[out] width width of the primary image
 * @param[out] height height of the primary image
 * @return status_t UHDR_NO_ERROR if parsing succeeds, error code otherwise.
 */
status_t get_image_dimensions(ultrahdr_compressed_ptr ultrahdr_image_ptr, size_t* width,
                              size_t* height);

/**
 * @brief get gainmap image dimensions
 *
 * @param[in] ultrahdr_image_ptr handle to compressed ultrahdr image.
 * @param[out] width width of the gainmap image
 * @param[out] height height of the gainmap image
 * @return status_t UHDR_NO_ERROR if parsing succeeds, error code otherwise.
 */
status_t get_gainmap_image_dimensions(ultrahdr_compressed_ptr ultrahdr_image_ptr, size_t* width,
                                      size_t* height);

/**
 * @brief create ultrahdr decoder app interface memory manager
 * @return void* handle to ultrahdr decoder memory context
 */
void* ultrahdr_create_memctxt(void);

/**
 * @brief destroy ultrahdr decoder app interface memory manager
 * @param[in] ctxt handle to ultrahdr decoder memory context
 * @return none
 */
void ultrahdr_destroy_memctxt(void* ctxt);

/**
 * @brief gets ultrahdr image attributes
 *
 * This method parses the input bitstream and fills individual fields of ultrahdr_attributes_struct
 *
 * @param[in] ctxt handle to to ultrahdr decoder memory context.
 * @param[in] ultrahdr_image_ptr handle to compressed ultrahdr image.
 * @param[out] ultrahdr_image_info_ptr handle to ultrahdr image attributes struct. The memory
 *                                     associated with fields of ultrahdr image attributes struct
 *                                     is owned by the library and gets released during
 *                                     ultrahdr_decompress_destroy
 * @return status_t UHDR_NO_ERROR if parsing succeeds, error code otherwise.
 */
status_t get_ultrahdr_info(void* ctxt, ultrahdr_compressed_ptr ultrahdr_image_ptr,
                           ultrahdr_attributes_ptr ultrahdr_image_info_ptr);

/**
 * @brief check if its a valid ultrahdr image.
 *
 * This function checks if the current image has a primary image and a gain map image.
 * Further, it parses gain map image for metadata and checks if the decoder is capable of
 * handling it.
 *
 * @param[in] ultrahdr_image_ptr handle to compressed ultrahdr image.
 * @return int 1 if valid, 0 otherwise.
 */
int is_valid_ultrahdr_image(ultrahdr_compressed_ptr ultrahdr_image_ptr);

/**
 * @brief ultrahdr_decompress - [Decode ultrahdr image]
 *
 * NOTES: 1. This method assumes that the compressed image contains an ICC profile with primaries
 *        that match those of a color gamut that this library is aware of; Bt.709, Display-P3,
 *        or Bt.2100.
 *        2. It also assumes the base image uses the sRGB transfer function.
 *
 * @param[in] ultrahdr_image_ptr handle to compressed ultrahdr image.
 * @param[out] dest destination of the uncompressed ultrahdr image. The function assumes the data
 *                  field of dest in initialized and has sufficient space to write the decoded
 *                  data.
 * @param[in] max_display_boost The maximum available boost supported by a display,
 *                              the value must be greater than or equal to 1.0.
 * @param[in] output_format Flag for setting output color format. Its value configures the output
 *                          color format
 * ----------------------------------------------------------------------------------------------
 * |      output_format          |    decoded color format to be written |    bytes per pixel   |
 * ----------------------------------------------------------------------------------------------
 * |     ULTRAHDR_OUTPUT_SDR     |              RGBA_8888                |          4           |
 * ----------------------------------------------------------------------------------------------
 * | ULTRAHDR_OUTPUT_HDR_LINEAR  |           RGBA_F16 linear             |          8           |
 * ----------------------------------------------------------------------------------------------
 * |   ULTRAHDR_OUTPUT_HDR_PQ    |           RGBA_1010102 PQ             |          4           |
 * ----------------------------------------------------------------------------------------------
 * |   ULTRAHDR_OUTPUT_HDR_HLG   |           RGBA_1010102 HLG            |          4           |
 * ----------------------------------------------------------------------------------------------
 * @param[in] metadata destination of the decoded metadata. If configured not NULL the decoder
 *                     will write metadata into this structure.
 * @return status_t UHDR_NO_ERROR if decoding succeeds, error code otherwise.
 */
status_t ultrahdr_decompress(ultrahdr_compressed_ptr ultrahdr_image_ptr,
                             ultrahdr_uncompressed_ptr dest, float max_display_boost,
                             ultrahdr_output_format output_format, ultrahdr_metadata_ptr metadata);

#ifdef __cplusplus
}
#endif

#endif  // ULTRAHDR_ULTRAHDR_API_H
