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

#ifndef ULTRAHDR_JPEGENCODERHELPER_H
#define ULTRAHDR_JPEGENCODERHELPER_H

#include <stdio.h>  // For jpeglib.h.

// C++ build requires extern C for jpeg internals.
#ifdef __cplusplus
extern "C" {
#endif

#include <jerror.h>
#include <jpeglib.h>

#ifdef __cplusplus
}  // extern "C"
#endif

#include <cstdint>
#include <vector>

namespace ultrahdr {

/*
 * Encapsulates a converter from raw image (YUV420planer or grey-scale) to JPEG format.
 * This class is not thread-safe.
 */
class JpegEncoderHelper {
 public:
  JpegEncoderHelper();
  ~JpegEncoderHelper();

  /*
   * Compresses YUV420Planer image to JPEG format. After calling this method, call
   * getCompressedImage() to get the image. |quality| is the jpeg image quality parameter to use.
   * It ranges from 1 (poorest quality) to 100 (highest quality). |iccBuffer| is the buffer of
   * ICC segment which will be added to the compressed image.
   * Returns false if errors occur during compression.
   */
  bool compressImage(const uint8_t* yBuffer, const uint8_t* uvBuffer, int width, int height,
                     int lumaStride, int chromaStride, int quality, const void* iccBuffer,
                     unsigned int iccSize);

  /*
   * Returns the compressed JPEG buffer pointer. This method must be called only after calling
   * compressImage().
   */
  void* getCompressedImagePtr();

  /*
   * Returns the compressed JPEG buffer size. This method must be called only after calling
   * compressImage().
   */
  size_t getCompressedImageSize();

  /*
   * Process 16 lines of Y and 16 lines of U/V each time.
   * We must pass at least 16 scanlines according to libjpeg documentation.
   */
  static const int kCompressBatchSize = 16;

 private:
  // initDestination(), emptyOutputBuffer() and emptyOutputBuffer() are callback functions to be
  // passed into jpeg library.
  static void initDestination(j_compress_ptr cinfo);
  static boolean emptyOutputBuffer(j_compress_ptr cinfo);
  static void terminateDestination(j_compress_ptr cinfo);
  static void outputErrorMessage(j_common_ptr cinfo);

  // Returns false if errors occur.
  bool encode(const uint8_t* yBuffer, const uint8_t* uvBuffer, int width, int height,
              int lumaStride, int chromaStride, int quality, const void* iccBuffer,
              unsigned int iccSize);
  void setJpegDestination(jpeg_compress_struct* cinfo);
  void setJpegCompressStruct(int width, int height, int quality, jpeg_compress_struct* cinfo,
                             bool isSingleChannel);
  // Returns false if errors occur.
  bool compressYuv(jpeg_compress_struct* cinfo, const uint8_t* yBuffer, const uint8_t* uvBuffer,
                   int lumaStride, int chromaStride);
  bool compressY(jpeg_compress_struct* cinfo, const uint8_t* yBuffer, int lumaStride);

  // The block size for encoded jpeg image buffer.
  static const int kBlockSize = 16384;

  // The buffer that holds the compressed result.
  std::vector<JOCTET> mResultBuffer;
};

} /* namespace ultrahdr  */

#endif  // ULTRAHDR_JPEGENCODERHELPER_H
