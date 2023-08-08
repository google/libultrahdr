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

#ifndef ANDROID_ULTRAHDR_JPEGDECODERHELPER_H
#define ANDROID_ULTRAHDR_JPEGDECODERHELPER_H

// We must include cstdio before jpeglib.h. It is a requirement of libjpeg.
#include <cstdio>
extern "C" {
#include <jerror.h>
#include <jpeglib.h>
}
#include <utils/Errors.h>
#include <vector>

static const int kMaxWidth = 8192;
static const int kMaxHeight = 8192;

namespace android::ultrahdr {
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
    bool decompressImage(const void* image, int length, bool decodeToRGBA = false);
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
     * Returns the EXIF data from the image.
     */
    void* getEXIFPtr();
    /*
     * Returns the decompressed EXIF buffer size. This method must be called only after
     * calling decompressImage() or getCompressedImageParameters().
     */
    size_t getEXIFSize();
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
     * Decompresses metadata of the image. All vectors are owned by the caller.
     */
    bool getCompressedImageParameters(const void* image, int length,
                                      size_t* pWidth, size_t* pHeight,
                                      std::vector<uint8_t>* iccData,
                                      std::vector<uint8_t>* exifData);

private:
    bool decode(const void* image, int length, bool decodeToRGBA);
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

    // Resolution of the decompressed image.
    size_t mWidth;
    size_t mHeight;
};
} /* namespace android::ultrahdr  */

#endif // ANDROID_ULTRAHDR_JPEGDECODERHELPER_H
