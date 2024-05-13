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

#ifndef ULTRAHDR_JPEGDECODERHELPER_H
#define ULTRAHDR_JPEGDECODERHELPER_H

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
#include <memory>
#include <vector>

namespace ultrahdr {

// constraint on max width and max height is only due to device alloc constraints
// Can tune these values basing on the target device
static const int kMaxWidth = 8192;
static const int kMaxHeight = 8192;

typedef enum {
  PARSE_ONLY = 0,          // Dont decode. Parse for dimensions, EXIF, ICC, XMP
  DECODE_TO_RGBA = 1,      // Parse and decode to rgba
  DECODE_TO_YCBCR = 2,     // Parse and decode to YCBCR or Grayscale
                           // if input has 1 channel, decode to Grayscale
                           // if input has 3 channels, decode to YCBCR
  DECODE_TO_GAIN_MAP = 3,  // parse and decode gain map.
                           // if input has 1 channel, decode to Grayscale
                           // if input has 3 channels, decode to RGBA
} decode_mode_t;

/*
 * Encapsulates a converter from JPEG to raw image (YUV420planer or grey-scale) format.
 * This class is not thread-safe.
 */
class JpegDecoderHelper {
 public:
  JpegDecoderHelper();
  ~JpegDecoderHelper();
  /*
   * Decompresses JPEG image to raw image (YUV420planer, grey-scale or RGBA) format. After
   * calling this method, call getDecompressedImage() to get the image.
   * Returns false if decompressing the image fails.
   */
  bool decompressImage(const void* image, int length, decode_mode_t decodeTo = DECODE_TO_YCBCR);
  /*
   * Returns the decompressed raw image buffer pointer. This method must be called only after
   * calling decompressImage().
   */
  void* getDecompressedImagePtr();
  /*
   * Returns the decompressed raw image buffer size. This method must be called only after
   * calling decompressImage().
   */
  size_t getDecompressedImageSize();
  /*
   * Returns the image width in pixels. This method must be called only after calling
   * decompressImage().
   */
  size_t getDecompressedImageWidth();
  /*
   * Returns the image width in pixels. This method must be called only after calling
   * decompressImage().
   */
  size_t getDecompressedImageHeight();
  /*
   * Returns the XMP data from the image.
   */
  void* getXMPPtr();
  /*
   * Returns the decompressed XMP buffer size. This method must be called only after
   * calling decompressImage() or getCompressedImageParameters().
   */
  size_t getXMPSize();
  /*
   * Extracts EXIF package and updates the EXIF position / length without decoding the image.
   */
  bool extractEXIF(const void* image, int length);
  /*
   * Returns the EXIF data from the image.
   * This method must be called after extractEXIF() or decompressImage().
   */
  void* getEXIFPtr();
  /*
   * Returns the decompressed EXIF buffer size. This method must be called only after
   * calling decompressImage(), extractEXIF() or getCompressedImageParameters().
   */
  size_t getEXIFSize();
  /*
   * Returns the position offset of EXIF package
   * (4 bypes offset to FF sign, the byte after FF E1 XX XX <this byte>),
   * or -1  if no EXIF exists.
   * This method must be called after extractEXIF() or decompressImage().
   */
  int getEXIFPos() { return mExifPos; }
  /*
   * Returns the ICC data from the image.
   */
  void* getICCPtr();
  /*
   * Returns the decompressed ICC buffer size. This method must be called only after
   * calling decompressImage() or getCompressedImageParameters().
   */
  size_t getICCSize();
  /*
   * Returns the iso metadata from the image.
   */
  void* getIsoMetadataPtr();
  /*
   * Returns the decompressed iso metadata buffer size. This method must be called only after
   * calling decompressImage() or getCompressedImageParameters().
   */
  size_t getIsoMetadataSize();
  /*
   * Decompresses metadata of the image. All vectors are owned by the caller.
   */
  bool getCompressedImageParameters(const void* image, int length);

 private:
  bool decode(const void* image, int length, decode_mode_t decodeTo);
  // Returns false if errors occur.
  bool decompress(jpeg_decompress_struct* cinfo, const uint8_t* dest, bool isSingleChannel);
  bool decompressYUV(jpeg_decompress_struct* cinfo, const uint8_t* dest);
  bool decompressRGBA(jpeg_decompress_struct* cinfo, const uint8_t* dest);
  bool decompressSingleChannel(jpeg_decompress_struct* cinfo, const uint8_t* dest);
  // Process 16 lines of Y and 16 lines of U/V each time.
  // We must pass at least 16 scanlines according to libjpeg documentation.
  static const int kCompressBatchSize = 16;
  // The buffer that holds the decompressed result.
  std::vector<JOCTET> mResultBuffer;
  // The buffer that holds XMP Data.
  std::vector<JOCTET> mXMPBuffer;
  // The buffer that holds EXIF Data.
  std::vector<JOCTET> mEXIFBuffer;
  // The buffer that holds ICC Data.
  std::vector<JOCTET> mICCBuffer;
  // The buffer that holds iso metadata.
  std::vector<JOCTET> mIsoMetadataBuffer;

  // Resolution of the decompressed image.
  size_t mWidth;
  size_t mHeight;

  // Position of EXIF package, default value is -1 which means no EXIF package appears.
  int mExifPos = -1;

  std::unique_ptr<uint8_t[]> mEmpty = nullptr;
  std::unique_ptr<uint8_t[]> mBufferIntermediate = nullptr;
};
} /* namespace ultrahdr  */

#endif  // ULTRAHDR_JPEGDECODERHELPER_H
