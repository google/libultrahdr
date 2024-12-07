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

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif
#include <gtest/gtest.h>

#include <fstream>
#include <iostream>

#include "ultrahdr_api.h"

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/jpegrutils.h"

//#define DUMP_OUTPUT

namespace ultrahdr {

// resources used by unit tests
#ifdef __ANDROID__
const char* kYCbCrP010FileName = "/data/local/tmp/raw_p010_image.p010";
const char* kYCbCr420FileName = "/data/local/tmp/raw_yuv420_image.yuv420";
const char* kSdrJpgFileName = "/data/local/tmp/jpeg_image.jpg";
#else
const char* kYCbCrP010FileName = "./data/raw_p010_image.p010";
const char* kYCbCr420FileName = "./data/raw_yuv420_image.yuv420";
const char* kSdrJpgFileName = "./data/jpeg_image.jpg";
#endif
const size_t kImageWidth = 1280;
const size_t kImageHeight = 720;
const int kQuality = 90;

// Wrapper to describe the input type
typedef enum {
  YCbCr_p010 = 0,
  YCbCr_420 = 1,
} UhdrInputFormat;

/**
 * Wrapper class for raw resource
 * Sample usage:
 *   UhdrUnCompressedStructWrapper rawImg(width, height, YCbCr_p010);
 *   rawImg.setImageColorGamut(colorGamut));
 *   rawImg.setImageStride(strideLuma, strideChroma); // optional
 *   rawImg.setChromaMode(false); // optional
 *   rawImg.allocateMemory();
 *   rawImg.loadRawResource(kYCbCrP010FileName);
 */
class UhdrUnCompressedStructWrapper {
 public:
  UhdrUnCompressedStructWrapper(unsigned int width, unsigned int height, UhdrInputFormat format);
  ~UhdrUnCompressedStructWrapper() = default;

  bool setChromaMode(bool isChromaContiguous);
  bool setImageStride(unsigned int lumaStride, unsigned int chromaStride);
  bool setImageColorGamut(ultrahdr_color_gamut colorGamut);
  bool allocateMemory();
  bool loadRawResource(const char* fileName);
  jr_uncompressed_ptr getImageHandle();

 private:
  std::unique_ptr<uint8_t[]> mLumaData;
  std::unique_ptr<uint8_t[]> mChromaData;
  jpegr_uncompressed_struct mImg;
  UhdrInputFormat mFormat;
  bool mIsChromaContiguous;
};

/**
 * Wrapper class for compressed resource
 * Sample usage:
 *   UhdrCompressedStructWrapper jpgImg(width, height);
 *   rawImg.allocateMemory();
 */
class UhdrCompressedStructWrapper {
 public:
  UhdrCompressedStructWrapper(unsigned int width, unsigned int height);
  ~UhdrCompressedStructWrapper() = default;

  bool allocateMemory();
  jr_compressed_ptr getImageHandle();

 private:
  std::unique_ptr<uint8_t[]> mData;
  jpegr_compressed_struct mImg{};
  unsigned int mWidth;
  unsigned int mHeight;
};

UhdrUnCompressedStructWrapper::UhdrUnCompressedStructWrapper(unsigned int width,
                                                             unsigned int height,
                                                             UhdrInputFormat format) {
  mImg.data = nullptr;
  mImg.width = width;
  mImg.height = height;
  mImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  mImg.chroma_data = nullptr;
  mImg.luma_stride = 0;
  mImg.chroma_stride = 0;
  mFormat = format;
  mIsChromaContiguous = true;
}

bool UhdrUnCompressedStructWrapper::setChromaMode(bool isChromaContiguous) {
  if (mLumaData.get() != nullptr) {
    std::cerr << "Object has sailed, no further modifications are allowed" << std::endl;
    return false;
  }
  mIsChromaContiguous = isChromaContiguous;
  return true;
}

bool UhdrUnCompressedStructWrapper::setImageStride(unsigned int lumaStride,
                                                   unsigned int chromaStride) {
  if (mLumaData.get() != nullptr) {
    std::cerr << "Object has sailed, no further modifications are allowed" << std::endl;
    return false;
  }
  if (lumaStride != 0) {
    if (lumaStride < mImg.width) {
      std::cerr << "Bad luma stride received" << std::endl;
      return false;
    }
    mImg.luma_stride = lumaStride;
  }
  if (chromaStride != 0) {
    if (mFormat == YCbCr_p010 && chromaStride < mImg.width) {
      std::cerr << "Bad chroma stride received for format YCbCrP010" << std::endl;
      return false;
    }
    if (mFormat == YCbCr_420 && chromaStride < (mImg.width >> 1)) {
      std::cerr << "Bad chroma stride received for format YCbCr420" << std::endl;
      return false;
    }
    mImg.chroma_stride = chromaStride;
  }
  return true;
}

bool UhdrUnCompressedStructWrapper::setImageColorGamut(ultrahdr_color_gamut colorGamut) {
  if (mLumaData.get() != nullptr) {
    std::cerr << "Object has sailed, no further modifications are allowed" << std::endl;
    return false;
  }
  mImg.colorGamut = colorGamut;
  return true;
}

bool UhdrUnCompressedStructWrapper::allocateMemory() {
  if (mImg.width == 0 || (mImg.width % 2 != 0) || mImg.height == 0 || (mImg.height % 2 != 0) ||
      (mFormat != YCbCr_p010 && mFormat != YCbCr_420)) {
    std::cerr << "Object in bad state, mem alloc failed" << std::endl;
    return false;
  }
  int lumaStride = mImg.luma_stride == 0 ? mImg.width : mImg.luma_stride;
  int lumaSize = lumaStride * mImg.height * (mFormat == YCbCr_p010 ? 2 : 1);
  int chromaSize = (mImg.height >> 1) * (mFormat == YCbCr_p010 ? 2 : 1);
  if (mIsChromaContiguous) {
    chromaSize *= lumaStride;
  } else {
    if (mImg.chroma_stride == 0) {
      std::cerr << "Object in bad state, mem alloc failed" << std::endl;
      return false;
    }
    if (mFormat == YCbCr_p010) {
      chromaSize *= mImg.chroma_stride;
    } else {
      chromaSize *= (mImg.chroma_stride * 2);
    }
  }
  if (mIsChromaContiguous) {
    mLumaData = std::make_unique<uint8_t[]>(lumaSize + chromaSize);
    mImg.data = mLumaData.get();
    mImg.chroma_data = nullptr;
  } else {
    mLumaData = std::make_unique<uint8_t[]>(lumaSize);
    mImg.data = mLumaData.get();
    mChromaData = std::make_unique<uint8_t[]>(chromaSize);
    mImg.chroma_data = mChromaData.get();
  }
  return true;
}

bool UhdrUnCompressedStructWrapper::loadRawResource(const char* fileName) {
  if (!mImg.data) {
    std::cerr << "memory is not allocated, read not possible" << std::endl;
    return false;
  }
  std::ifstream ifd(fileName, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int bpp = mFormat == YCbCr_p010 ? 2 : 1;
    int size = ifd.tellg();
    int length = mImg.width * mImg.height * bpp * 3 / 2;  // 2x2 subsampling
    if (size < length) {
      std::cerr << "requested to read " << length << " bytes from file : " << fileName
                << ", file contains only " << length << " bytes" << std::endl;
      return false;
    }
    ifd.seekg(0, std::ios::beg);
    size_t lumaStride = mImg.luma_stride == 0 ? mImg.width : mImg.luma_stride;
    char* mem = static_cast<char*>(mImg.data);
    for (size_t i = 0; i < mImg.height; i++) {
      ifd.read(mem, mImg.width * bpp);
      mem += lumaStride * bpp;
    }
    if (!mIsChromaContiguous) {
      mem = static_cast<char*>(mImg.chroma_data);
    }
    size_t chromaStride;
    if (mIsChromaContiguous) {
      chromaStride = mFormat == YCbCr_p010 ? lumaStride : lumaStride / 2;
    } else {
      if (mFormat == YCbCr_p010) {
        chromaStride = mImg.chroma_stride == 0 ? lumaStride : mImg.chroma_stride;
      } else {
        chromaStride = mImg.chroma_stride == 0 ? (lumaStride / 2) : mImg.chroma_stride;
      }
    }
    if (mFormat == YCbCr_p010) {
      for (size_t i = 0; i < mImg.height / 2; i++) {
        ifd.read(mem, mImg.width * 2);
        mem += chromaStride * 2;
      }
    } else {
      for (size_t i = 0; i < mImg.height / 2; i++) {
        ifd.read(mem, (mImg.width / 2));
        mem += chromaStride;
      }
      for (size_t i = 0; i < mImg.height / 2; i++) {
        ifd.read(mem, (mImg.width / 2));
        mem += chromaStride;
      }
    }
    return true;
  }
  std::cerr << "unable to open file : " << fileName << std::endl;
  return false;
}

jr_uncompressed_ptr UhdrUnCompressedStructWrapper::getImageHandle() { return &mImg; }

UhdrCompressedStructWrapper::UhdrCompressedStructWrapper(unsigned int width, unsigned int height) {
  mWidth = width;
  mHeight = height;
}

bool UhdrCompressedStructWrapper::allocateMemory() {
  if (mWidth == 0 || (mWidth % 2 != 0) || mHeight == 0 || (mHeight % 2 != 0)) {
    std::cerr << "Object in bad state, mem alloc failed" << std::endl;
    return false;
  }
  int maxLength = (std::max)(8 * 1024 /* min size 8kb */, (int)(mWidth * mHeight * 3 * 2));
  mData = std::make_unique<uint8_t[]>(maxLength);
  mImg.data = mData.get();
  mImg.length = 0;
  mImg.maxLength = maxLength;
  return true;
}

jr_compressed_ptr UhdrCompressedStructWrapper::getImageHandle() { return &mImg; }

#ifdef DUMP_OUTPUT
static bool writeFile(const char* filename, void*& result, int length) {
  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    ofd.write(static_cast<char*>(result), length);
    return true;
  }
  std::cerr << "unable to write to file : " << filename << std::endl;
  return false;
}
#endif

static bool readFile(const char* fileName, void*& result, size_t maxLength, size_t& length) {
  std::ifstream ifd(fileName, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    length = ifd.tellg();
    if (length > maxLength) {
      std::cerr << "not enough space to read file" << std::endl;
      return false;
    }
    ifd.seekg(0, std::ios::beg);
    ifd.read(static_cast<char*>(result), length);
    return true;
  }
  std::cerr << "unable to read file : " << fileName << std::endl;
  return false;
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

uhdr_color_transfer_t map_internal_ct_to_ct(ultrahdr::ultrahdr_transfer_function ct) {
  switch (ct) {
    case ultrahdr::ULTRAHDR_TF_HLG:
      return UHDR_CT_HLG;
    case ultrahdr::ULTRAHDR_TF_PQ:
      return UHDR_CT_PQ;
    case ultrahdr::ULTRAHDR_TF_LINEAR:
      return UHDR_CT_LINEAR;
    case ultrahdr::ULTRAHDR_TF_SRGB:
      return UHDR_CT_SRGB;
    default:
      return UHDR_CT_UNSPECIFIED;
  }
}

void decodeJpegRImg(jr_compressed_ptr img, [[maybe_unused]] const char* outFileName) {
  jpegr_info_struct info{};
  JpegR jpegHdr;
  ASSERT_EQ(JPEGR_NO_ERROR, jpegHdr.getJPEGRInfo(img, &info));
  ASSERT_EQ(kImageWidth, info.width);
  ASSERT_EQ(kImageHeight, info.height);
  size_t outSize = info.width * info.height * 8;
  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(outSize);
  jpegr_uncompressed_struct destImage{};
  destImage.data = data.get();
  ASSERT_EQ(JPEGR_NO_ERROR, jpegHdr.decodeJPEGR(img, &destImage));
  ASSERT_EQ(kImageWidth, destImage.width);
  ASSERT_EQ(kImageHeight, destImage.height);
#ifdef DUMP_OUTPUT
  if (!writeFile(outFileName, destImage.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
  uhdr_codec_private_t* obj = uhdr_create_decoder();
  uhdr_compressed_image_t uhdr_image{};
  uhdr_image.data = img->data;
  uhdr_image.data_sz = img->length;
  uhdr_image.capacity = img->length;
  uhdr_image.cg = UHDR_CG_UNSPECIFIED;
  uhdr_image.ct = UHDR_CT_UNSPECIFIED;
  uhdr_image.range = UHDR_CR_UNSPECIFIED;
  uhdr_error_info_t status = uhdr_dec_set_image(obj, &uhdr_image);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_decode(obj);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  uhdr_raw_image_t* raw_image = uhdr_get_decoded_image(obj);
  ASSERT_NE(nullptr, raw_image);
  ASSERT_EQ(map_internal_cg_to_cg(destImage.colorGamut), raw_image->cg);
  ASSERT_EQ(destImage.width, raw_image->w);
  ASSERT_EQ(destImage.height, raw_image->h);
  char* testData = static_cast<char*>(raw_image->planes[UHDR_PLANE_PACKED]);
  char* refData = static_cast<char*>(destImage.data);
  int bpp = (raw_image->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) ? 8 : 4;
  const size_t testStride = raw_image->stride[UHDR_PLANE_PACKED] * bpp;
  const size_t refStride = destImage.width * bpp;
  const size_t length = destImage.width * bpp;
  for (unsigned i = 0; i < destImage.height; i++, testData += testStride, refData += refStride) {
    ASSERT_EQ(0, memcmp(testData, refData, length));
  }
  uhdr_release_decoder(obj);
}

// ============================================================================
// Unit Tests
// ============================================================================

// Test Encode API-0 invalid arguments
TEST(JpegRTest, EncodeAPI0WithInvalidArgs) {
  JpegR uHdrLib;

  UhdrCompressedStructWrapper jpgImg(16, 16);
  ASSERT_TRUE(jpgImg.allocateMemory());

  // test quality factor and transfer function
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), -1, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad jpeg quality factor";
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), 101, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad jpeg quality factor";

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                      ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), static_cast<ultrahdr_transfer_function>(-10),
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
  }

  // test dest
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            nullptr, kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg2.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
  }

  // test p010 input
  {
    ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";
  }

  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED));
    ASSERT_TRUE(rawImg.allocateMemory());
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(
        static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1)));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg2.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";
  }

  {
    const int kWidth = 32, kHeight = 32;
    UhdrUnCompressedStructWrapper rawImg(kWidth, kHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    auto rawImgP010 = rawImg.getImageHandle();

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad chroma stride";
  }
}

/* Test Encode API-1 invalid arguments */
TEST(JpegRTest, EncodeAPI1WithInvalidArgs) {
  JpegR uHdrLib;

  UhdrCompressedStructWrapper jpgImg(16, 16);
  ASSERT_TRUE(jpgImg.allocateMemory());

  // test quality factor and transfer function
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), -1, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad jpeg quality factor";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), 101, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad jpeg quality factor";

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                      ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(-10),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
  }

  // test dest
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr, kQuality,
                                  nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
  }

  // test p010 input
  {
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";
  }

  {
    const int kWidth = 32, kHeight = 32;
    UhdrUnCompressedStructWrapper rawImg(kWidth, kHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    auto rawImgP010 = rawImg.getImageHandle();
    UhdrUnCompressedStructWrapper rawImg2(kWidth, kHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    auto rawImg420 = rawImg2.getImageHandle();

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut =
        static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad chroma stride";
  }

  // test 420 input
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), nullptr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr 420 image";

    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr 420 image";
  }
  {
    const int kWidth = 32, kHeight = 32;
    UhdrUnCompressedStructWrapper rawImg(kWidth, kHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    auto rawImgP010 = rawImg.getImageHandle();
    UhdrUnCompressedStructWrapper rawImg2(kWidth, kHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    auto rawImg420 = rawImg2.getImageHandle();

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->colorGamut =
        static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth - 1;
    rawImg420->height = kHeight;
    rawImg420->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight - 1;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height for 420";

    rawImg420->width = 0;
    rawImg420->height = kHeight;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = 0;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad luma stride for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = 0;
    rawImg420->chroma_data = rawImgP010->data;
    rawImg420->chroma_stride = kWidth / 2 - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR)
        << "fail, API allows bad chroma stride for 420";
  }
}

/* Test Encode API-2 invalid arguments */
TEST(JpegRTest, EncodeAPI2WithInvalidArgs) {
  JpegR uHdrLib;

  UhdrCompressedStructWrapper jpgImg(16, 16);
  ASSERT_TRUE(jpgImg.allocateMemory());

  // test quality factor and transfer function
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(
                  rawImg.getImageHandle(), rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED, jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                      ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(
                  rawImg.getImageHandle(), rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                  static_cast<ultrahdr_transfer_function>(-10), jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
  }

  // test dest
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(
                  rawImg.getImageHandle(), rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
  }

  // test compressed image
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());

    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(), nullptr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr for compressed image";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(
                  rawImg.getImageHandle(), rawImg2.getImageHandle(), jpgImg2.getImageHandle(),
                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr for compressed image";
  }

  // test p010 input
  {
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_NE(
        uHdrLib.encodeJPEGR(nullptr, rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(
                  rawImg.getImageHandle(), rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";
  }

  {
    const int kWidth = 32, kHeight = 32;
    UhdrUnCompressedStructWrapper rawImg(kWidth, kHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    auto rawImgP010 = rawImg.getImageHandle();
    UhdrUnCompressedStructWrapper rawImg2(kWidth, kHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    auto rawImg420 = rawImg2.getImageHandle();

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut =
        static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad chroma stride";
  }

  // test 420 input
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), nullptr, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr 420 image";

    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(
                  rawImg.getImageHandle(), rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr 420 image";
  }
  {
    const int kWidth = 32, kHeight = 32;
    UhdrUnCompressedStructWrapper rawImg(kWidth, kHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    auto rawImgP010 = rawImg.getImageHandle();
    UhdrUnCompressedStructWrapper rawImg2(kWidth, kHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    auto rawImg420 = rawImg2.getImageHandle();

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->colorGamut =
        static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth - 1;
    rawImg420->height = kHeight;
    rawImg420->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight - 1;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height for 420";

    rawImg420->width = 0;
    rawImg420->height = kHeight;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = 0;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad luma stride for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = 0;
    rawImg420->chroma_data = rawImgP010->data;
    rawImg420->chroma_stride = kWidth / 2 - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad chroma stride for 420";
  }
}

/* Test Encode API-3 invalid arguments */
TEST(JpegRTest, EncodeAPI3WithInvalidArgs) {
  JpegR uHdrLib;

  UhdrCompressedStructWrapper jpgImg(16, 16);
  ASSERT_TRUE(jpgImg.allocateMemory());

  // test quality factor and transfer function
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
                                  jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                      ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle()),
              JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                            static_cast<ultrahdr_transfer_function>(-10), jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad hdr transfer function";
  }

  // test dest
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr),
              JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr dest";
  }

  // test compressed image
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), nullptr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr for compressed image";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg2.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr for compressed image";
  }

  // test p010 input
  {
    ASSERT_NE(
        uHdrLib.encodeJPEGR(nullptr, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows nullptr p010 image";
  }

  {
    const int kWidth = 32, kHeight = 32;
    UhdrUnCompressedStructWrapper rawImg(kWidth, kHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    auto rawImgP010 = rawImg.getImageHandle();

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut =
        static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(
        uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
        JPEGR_NO_ERROR)
        << "fail, API allows bad chroma stride";
  }
}

/* Test Encode API-4 invalid arguments */
TEST(JpegRTest, EncodeAPI4WithInvalidArgs) {
  UhdrCompressedStructWrapper jpgImg(16, 16);
  ASSERT_TRUE(jpgImg.allocateMemory());
  UhdrCompressedStructWrapper jpgImg2(16, 16);
  JpegR uHdrLib;

  // test dest
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), nullptr, nullptr),
            JPEGR_NO_ERROR)
      << "fail, API allows nullptr dest";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), nullptr,
                                jpgImg2.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows nullptr dest";

  // test primary image
  ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, jpgImg.getImageHandle(), nullptr, jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows nullptr primary image";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg2.getImageHandle(), jpgImg.getImageHandle(), nullptr,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows nullptr primary image";

  // test gain map
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), nullptr, nullptr, jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows nullptr gain map image";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg2.getImageHandle(), nullptr,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows nullptr gain map image";

  // test metadata
  ultrahdr_metadata_struct good_metadata;
  good_metadata.version = "1.0";
  good_metadata.minContentBoost = 1.0f;
  good_metadata.maxContentBoost = 2.0f;
  good_metadata.gamma = 1.0f;
  good_metadata.offsetSdr = 0.0f;
  good_metadata.offsetHdr = 0.0f;
  good_metadata.hdrCapacityMin = 1.0f;
  good_metadata.hdrCapacityMax = 2.0f;

  ultrahdr_metadata_struct metadata = good_metadata;
  metadata.version = "1.1";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata version";

  metadata = good_metadata;
  metadata.minContentBoost = 3.0f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata content boost";

  metadata = good_metadata;
  metadata.gamma = -0.1f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata gamma";

  metadata = good_metadata;
  metadata.offsetSdr = -0.1f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata offset sdr";

  metadata = good_metadata;
  metadata.offsetHdr = -0.1f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata offset hdr";

  metadata = good_metadata;
  metadata.hdrCapacityMax = 0.5f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata hdr capacity max";

  metadata = good_metadata;
  metadata.hdrCapacityMin = 0.5f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            JPEGR_NO_ERROR)
      << "fail, API allows bad metadata hdr capacity min";
}

/* Test Decode API invalid arguments */
TEST(JpegRTest, DecodeAPIWithInvalidArgs) {
  JpegR uHdrLib;

  UhdrCompressedStructWrapper jpgImg(16, 16);
  jpegr_uncompressed_struct destImage{};
  size_t outSize = 16 * 16 * 8;
  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(outSize);
  destImage.data = data.get();

  // test jpegr image
  ASSERT_NE(uHdrLib.decodeJPEGR(nullptr, &destImage), JPEGR_NO_ERROR)
      << "fail, API allows nullptr for jpegr img";
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage), JPEGR_NO_ERROR)
      << "fail, API allows nullptr for jpegr img";
  ASSERT_TRUE(jpgImg.allocateMemory());

  // test dest image
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), nullptr), JPEGR_NO_ERROR)
      << "fail, API allows nullptr for dest";
  destImage.data = nullptr;
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage), JPEGR_NO_ERROR)
      << "fail, API allows nullptr for dest";
  destImage.data = data.get();

  // test max display boost
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage, 0.5), JPEGR_NO_ERROR)
      << "fail, API allows invalid max display boost";

  // test output format
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage, FLT_MAX, nullptr,
                                static_cast<ultrahdr_output_format>(-1)),
            JPEGR_NO_ERROR)
      << "fail, API allows invalid output format";
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage, FLT_MAX, nullptr,
                                static_cast<ultrahdr_output_format>(ULTRAHDR_OUTPUT_MAX + 1)),
            JPEGR_NO_ERROR)
      << "fail, API allows invalid output format";
}

TEST(JpegRTest, writeXmpThenRead) {
  uhdr_gainmap_metadata_ext_t metadata_expected("1.0");
  std::fill_n(metadata_expected.max_content_boost, 3, 1.25f);
  std::fill_n(metadata_expected.min_content_boost, 3, 0.75f);
  std::fill_n(metadata_expected.gamma, 3, 1.0f);
  std::fill_n(metadata_expected.offset_sdr, 3, 0.0f);
  std::fill_n(metadata_expected.offset_hdr, 3, 0.0f);
  metadata_expected.hdr_capacity_min = 1.0f;
  metadata_expected.hdr_capacity_max = metadata_expected.max_content_boost[0];
  metadata_expected.use_base_cg = true;

  const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
  const size_t nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator

  std::string xmp = generateXmpForSecondaryImage(metadata_expected);

  std::vector<uint8_t> xmpData;
  xmpData.reserve(nameSpaceLength + xmp.size());
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(nameSpace.c_str()),
                 reinterpret_cast<const uint8_t*>(nameSpace.c_str()) + nameSpaceLength);
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(xmp.c_str()),
                 reinterpret_cast<const uint8_t*>(xmp.c_str()) + xmp.size());

  uhdr_gainmap_metadata_ext_t metadata_read;
  EXPECT_EQ(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read).error_code,
            UHDR_CODEC_OK);
  EXPECT_FLOAT_EQ(metadata_expected.max_content_boost[0], metadata_read.max_content_boost[0]);
  EXPECT_FLOAT_EQ(metadata_expected.min_content_boost[0], metadata_read.min_content_boost[0]);
  EXPECT_FLOAT_EQ(metadata_expected.gamma[0], metadata_read.gamma[0]);
  EXPECT_FLOAT_EQ(metadata_expected.offset_sdr[0], metadata_read.offset_sdr[0]);
  EXPECT_FLOAT_EQ(metadata_expected.offset_hdr[0], metadata_read.offset_hdr[0]);
  EXPECT_FLOAT_EQ(metadata_expected.hdr_capacity_min, metadata_read.hdr_capacity_min);
  EXPECT_FLOAT_EQ(metadata_expected.hdr_capacity_max, metadata_read.hdr_capacity_max);
  EXPECT_TRUE(metadata_read.use_base_cg);
}

class JpegRAPIEncodeAndDecodeTest
    : public ::testing::TestWithParam<std::tuple<ultrahdr_color_gamut, ultrahdr_color_gamut>> {
 public:
  JpegRAPIEncodeAndDecodeTest()
      : mP010ColorGamut(std::get<0>(GetParam())), mYuv420ColorGamut(std::get<1>(GetParam())){};

  const ultrahdr_color_gamut mP010ColorGamut;
  const ultrahdr_color_gamut mYuv420ColorGamut;
};

/* Test Encode API-0 and Decode */
TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI0AndDecodeTest) {
  // reference encode
  UhdrUnCompressedStructWrapper rawImg(kImageWidth, kImageHeight, YCbCr_p010);
  ASSERT_TRUE(rawImg.setImageColorGamut(mP010ColorGamut));
  ASSERT_TRUE(rawImg.allocateMemory());
  ASSERT_TRUE(rawImg.loadRawResource(kYCbCrP010FileName));
  UhdrCompressedStructWrapper jpgImg(kImageWidth, kImageHeight);
  ASSERT_TRUE(jpgImg.allocateMemory());
  JpegR uHdrLib;
  ASSERT_EQ(
      uHdrLib.encodeJPEGR(rawImg.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                          jpgImg.getImageHandle(), kQuality, nullptr),
      JPEGR_NO_ERROR);

  uhdr_codec_private_t* obj = uhdr_create_encoder();
  uhdr_raw_image_t uhdrRawImg{};
  uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
  uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
  uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
  uhdrRawImg.w = kImageWidth;
  uhdrRawImg.h = kImageHeight;
  uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg.getImageHandle()->data;
  uhdrRawImg.stride[UHDR_PLANE_Y] = kImageWidth;
  uhdrRawImg.planes[UHDR_PLANE_UV] =
      ((uint8_t*)(rawImg.getImageHandle()->data)) + kImageWidth * kImageHeight * 2;
  uhdrRawImg.stride[UHDR_PLANE_UV] = kImageWidth;
  uhdr_error_info_t status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_HDR_IMG);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  status = uhdr_encode(obj);
  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
  uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
  ASSERT_NE(nullptr, compressedImage);
  ASSERT_EQ(jpgImg.getImageHandle()->length, compressedImage->data_sz);
  ASSERT_EQ(0,
            memcmp(jpgImg.getImageHandle()->data, compressedImage->data, compressedImage->data_sz));
  uhdr_release_encoder(obj);

  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2.setImageStride(kImageWidth + 18, 0));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_TRUE(rawImg2.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg2.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2.setImageStride(kImageWidth + 18, kImageWidth + 28));
    ASSERT_TRUE(rawImg2.setChromaMode(false));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_TRUE(rawImg2.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg2.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));

    uhdr_codec_private_t* obj = uhdr_create_encoder();
    uhdr_raw_image_t uhdrRawImg{};
    uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
    uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
    uhdrRawImg.w = kImageWidth;
    uhdrRawImg.h = kImageHeight;
    uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg2.getImageHandle()->data;
    uhdrRawImg.stride[UHDR_PLANE_Y] = rawImg2.getImageHandle()->luma_stride;
    uhdrRawImg.planes[UHDR_PLANE_UV] = rawImg2.getImageHandle()->chroma_data;
    uhdrRawImg.stride[UHDR_PLANE_UV] = rawImg2.getImageHandle()->chroma_stride;
    uhdr_error_info_t status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_HDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_encode(obj);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
    ASSERT_NE(nullptr, compressedImage);
    ASSERT_EQ(jpg1->length, compressedImage->data_sz);
    ASSERT_EQ(0, memcmp(jpg1->data, compressedImage->data, jpg1->length));
    uhdr_release_encoder(obj);
  }
  // encode with chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2.setImageStride(0, kImageWidth + 34));
    ASSERT_TRUE(rawImg2.setChromaMode(false));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_TRUE(rawImg2.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg2.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set but no chroma ptr
  {
    UhdrUnCompressedStructWrapper rawImg2(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2.setImageStride(kImageWidth, kImageWidth + 38));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_TRUE(rawImg2.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2.getImageHandle(), ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                            jpgImg2.getImageHandle(), kQuality, nullptr),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }

  auto jpg1 = jpgImg.getImageHandle();
#ifdef DUMP_OUTPUT
  if (!writeFile("encode_api0_output.jpeg", jpg1->data, jpg1->length)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif

  ASSERT_NO_FATAL_FAILURE(decodeJpegRImg(jpg1, "decode_api0_output.rgb"));
}

/* Test Encode API-1 and Decode */
TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI1AndDecodeTest) {
  UhdrUnCompressedStructWrapper rawImgP010(kImageWidth, kImageHeight, YCbCr_p010);
  ASSERT_TRUE(rawImgP010.setImageColorGamut(mP010ColorGamut));
  ASSERT_TRUE(rawImgP010.allocateMemory());
  ASSERT_TRUE(rawImgP010.loadRawResource(kYCbCrP010FileName));
  UhdrUnCompressedStructWrapper rawImg420(kImageWidth, kImageHeight, YCbCr_420);
  ASSERT_TRUE(rawImg420.setImageColorGamut(mYuv420ColorGamut));
  ASSERT_TRUE(rawImg420.allocateMemory());
  ASSERT_TRUE(rawImg420.loadRawResource(kYCbCr420FileName));
  UhdrCompressedStructWrapper jpgImg(kImageWidth, kImageHeight);
  ASSERT_TRUE(jpgImg.allocateMemory());
  JpegR uHdrLib;
  ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg420.getImageHandle(),
                                ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                jpgImg.getImageHandle(), kQuality, nullptr),
            JPEGR_NO_ERROR);
  // encode with luma stride set p010
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, 0));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set p010
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, kImageWidth + 256));
    ASSERT_TRUE(rawImg2P010.setChromaMode(false));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with chroma stride set p010
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(0, kImageWidth + 64));
    ASSERT_TRUE(rawImg2P010.setChromaMode(false));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set but no chroma ptr p010
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 64, kImageWidth + 256));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma stride set 420
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(kImageWidth + 14, 0));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set 420
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(kImageWidth + 46, kImageWidth / 2 + 34));
    ASSERT_TRUE(rawImg2420.setChromaMode(false));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));

    uhdr_codec_private_t* obj = uhdr_create_encoder();
    uhdr_raw_image_t uhdrRawImg{};
    uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
    uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
    uhdrRawImg.w = kImageWidth;
    uhdrRawImg.h = kImageHeight;
    uhdrRawImg.planes[UHDR_PLANE_Y] = rawImgP010.getImageHandle()->data;
    uhdrRawImg.stride[UHDR_PLANE_Y] = kImageWidth;
    uhdrRawImg.planes[UHDR_PLANE_UV] =
        ((uint8_t*)(rawImgP010.getImageHandle()->data)) + kImageWidth * kImageHeight * 2;
    uhdrRawImg.stride[UHDR_PLANE_UV] = kImageWidth;
    uhdr_error_info_t status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_HDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    uhdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
    uhdrRawImg.cg = map_internal_cg_to_cg(mYuv420ColorGamut);
    uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_SRGB);
    uhdrRawImg.range = UHDR_CR_FULL_RANGE;
    uhdrRawImg.w = kImageWidth;
    uhdrRawImg.h = kImageHeight;
    uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg2420.getImageHandle()->data;
    uhdrRawImg.stride[UHDR_PLANE_Y] = rawImg2420.getImageHandle()->luma_stride;
    uhdrRawImg.planes[UHDR_PLANE_U] = rawImg2420.getImageHandle()->chroma_data;
    uhdrRawImg.stride[UHDR_PLANE_U] = rawImg2420.getImageHandle()->chroma_stride;
    uhdrRawImg.planes[UHDR_PLANE_V] = ((uint8_t*)(rawImg2420.getImageHandle()->chroma_data)) +
                                      rawImg2420.getImageHandle()->chroma_stride * kImageHeight / 2;
    uhdrRawImg.stride[UHDR_PLANE_V] = rawImg2420.getImageHandle()->chroma_stride;
    status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_SDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_encode(obj);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
    ASSERT_NE(nullptr, compressedImage);
    ASSERT_EQ(jpgImg.getImageHandle()->length, compressedImage->data_sz);
    ASSERT_EQ(
        0, memcmp(jpgImg.getImageHandle()->data, compressedImage->data, compressedImage->data_sz));
    uhdr_release_encoder(obj);
  }
  // encode with chroma stride set 420
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(0, kImageWidth / 2 + 38));
    ASSERT_TRUE(rawImg2420.setChromaMode(false));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set but no chroma ptr 420
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(kImageWidth + 26, kImageWidth / 2 + 44));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }

  auto jpg1 = jpgImg.getImageHandle();

#ifdef DUMP_OUTPUT
  if (!writeFile("encode_api1_output.jpeg", jpg1->data, jpg1->length)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif

  ASSERT_NO_FATAL_FAILURE(decodeJpegRImg(jpg1, "decode_api1_output.rgb"));
}

/* Test Encode API-2 and Decode */
TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI2AndDecodeTest) {
  UhdrUnCompressedStructWrapper rawImgP010(kImageWidth, kImageHeight, YCbCr_p010);
  ASSERT_TRUE(rawImgP010.setImageColorGamut(mP010ColorGamut));
  ASSERT_TRUE(rawImgP010.allocateMemory());
  ASSERT_TRUE(rawImgP010.loadRawResource(kYCbCrP010FileName));
  UhdrUnCompressedStructWrapper rawImg420(kImageWidth, kImageHeight, YCbCr_420);
  ASSERT_TRUE(rawImg420.setImageColorGamut(mYuv420ColorGamut));
  ASSERT_TRUE(rawImg420.allocateMemory());
  ASSERT_TRUE(rawImg420.loadRawResource(kYCbCr420FileName));
  UhdrCompressedStructWrapper jpgImg(kImageWidth, kImageHeight);
  ASSERT_TRUE(jpgImg.allocateMemory());
  UhdrCompressedStructWrapper jpgSdr(kImageWidth, kImageHeight);
  ASSERT_TRUE(jpgSdr.allocateMemory());
  auto sdr = jpgSdr.getImageHandle();
  ASSERT_TRUE(readFile(kSdrJpgFileName, sdr->data, sdr->maxLength, sdr->length));
  JpegR uHdrLib;
  ASSERT_EQ(
      uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                          ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
      JPEGR_NO_ERROR);
  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, 0));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, kImageWidth + 256));
    ASSERT_TRUE(rawImg2P010.setChromaMode(false));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(0, kImageWidth + 64));
    ASSERT_TRUE(rawImg2P010.setChromaMode(false));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(kImageWidth + 128, 0));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(kImageWidth + 128, kImageWidth + 256));
    ASSERT_TRUE(rawImg2420.setChromaMode(false));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));

    uhdr_codec_private_t* obj = uhdr_create_encoder();
    uhdr_raw_image_t uhdrRawImg{};
    uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
    uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
    uhdrRawImg.w = kImageWidth;
    uhdrRawImg.h = kImageHeight;
    uhdrRawImg.planes[UHDR_PLANE_Y] = rawImgP010.getImageHandle()->data;
    uhdrRawImg.stride[UHDR_PLANE_Y] = kImageWidth;
    uhdrRawImg.planes[UHDR_PLANE_UV] =
        ((uint8_t*)(rawImgP010.getImageHandle()->data)) + kImageWidth * kImageHeight * 2;
    uhdrRawImg.stride[UHDR_PLANE_UV] = kImageWidth;
    uhdr_error_info_t status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_HDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    uhdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
    uhdrRawImg.cg = map_internal_cg_to_cg(mYuv420ColorGamut);
    uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_SRGB);
    uhdrRawImg.range = UHDR_CR_FULL_RANGE;
    uhdrRawImg.w = kImageWidth;
    uhdrRawImg.h = kImageHeight;
    uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg2420.getImageHandle()->data;
    uhdrRawImg.stride[UHDR_PLANE_Y] = rawImg2420.getImageHandle()->luma_stride;
    uhdrRawImg.planes[UHDR_PLANE_U] = rawImg2420.getImageHandle()->chroma_data;
    uhdrRawImg.stride[UHDR_PLANE_U] = rawImg2420.getImageHandle()->chroma_stride;
    uhdrRawImg.planes[UHDR_PLANE_V] = ((uint8_t*)(rawImg2420.getImageHandle()->chroma_data)) +
                                      rawImg2420.getImageHandle()->chroma_stride * kImageHeight / 2;
    uhdrRawImg.stride[UHDR_PLANE_V] = rawImg2420.getImageHandle()->chroma_stride;
    status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_SDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    uhdr_compressed_image_t uhdrCompressedImg;
    uhdrCompressedImg.data = sdr->data;
    uhdrCompressedImg.data_sz = sdr->length;
    uhdrCompressedImg.capacity = sdr->length;
    uhdrCompressedImg.cg = map_internal_cg_to_cg(sdr->colorGamut);
    uhdrCompressedImg.ct = UHDR_CT_UNSPECIFIED;
    uhdrCompressedImg.range = UHDR_CR_UNSPECIFIED;
    status = uhdr_enc_set_compressed_image(obj, &uhdrCompressedImg, UHDR_SDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_encode(obj);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
    ASSERT_NE(nullptr, compressedImage);
    ASSERT_EQ(jpgImg.getImageHandle()->length, compressedImage->data_sz);
    ASSERT_EQ(
        0, memcmp(jpgImg.getImageHandle()->data, compressedImage->data, compressedImage->data_sz));
    uhdr_release_encoder(obj);
  }
  // encode with chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2420(kImageWidth, kImageHeight, YCbCr_420);
    ASSERT_TRUE(rawImg2420.setImageColorGamut(mYuv420ColorGamut));
    ASSERT_TRUE(rawImg2420.setImageStride(0, kImageWidth + 64));
    ASSERT_TRUE(rawImg2420.setChromaMode(false));
    ASSERT_TRUE(rawImg2420.allocateMemory());
    ASSERT_TRUE(rawImg2420.loadRawResource(kYCbCr420FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }

  auto jpg1 = jpgImg.getImageHandle();

#ifdef DUMP_OUTPUT
  if (!writeFile("encode_api2_output.jpeg", jpg1->data, jpg1->length)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif

  ASSERT_NO_FATAL_FAILURE(decodeJpegRImg(jpg1, "decode_api2_output.rgb"));
}

/* Test Encode API-3 and Decode */
TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI3AndDecodeTest) {
  UhdrUnCompressedStructWrapper rawImgP010(kImageWidth, kImageHeight, YCbCr_p010);
  ASSERT_TRUE(rawImgP010.setImageColorGamut(mP010ColorGamut));
  ASSERT_TRUE(rawImgP010.allocateMemory());
  ASSERT_TRUE(rawImgP010.loadRawResource(kYCbCrP010FileName));
  UhdrCompressedStructWrapper jpgImg(kImageWidth, kImageHeight);
  ASSERT_TRUE(jpgImg.allocateMemory());
  UhdrCompressedStructWrapper jpgSdr(kImageWidth, kImageHeight);
  ASSERT_TRUE(jpgSdr.allocateMemory());
  auto sdr = jpgSdr.getImageHandle();
  ASSERT_TRUE(readFile(kSdrJpgFileName, sdr->data, sdr->maxLength, sdr->length));
  JpegR uHdrLib;
  ASSERT_EQ(
      uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), sdr,
                          ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg.getImageHandle()),
      JPEGR_NO_ERROR);
  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, 0));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, kImageWidth + 256));
    ASSERT_TRUE(rawImg2P010.setChromaMode(false));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with chroma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(0, kImageWidth + 64));
    ASSERT_TRUE(rawImg2P010.setChromaMode(false));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }
  // encode with luma and chroma stride set and no chroma ptr
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 32, kImageWidth + 256));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(
        uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                            ultrahdr_transfer_function::ULTRAHDR_TF_HLG, jpgImg2.getImageHandle()),
        JPEGR_NO_ERROR);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
  }

  {
    uhdr_codec_private_t* obj = uhdr_create_encoder();
    uhdr_raw_image_t uhdrRawImg{};
    uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
    uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
    uhdrRawImg.w = kImageWidth;
    uhdrRawImg.h = kImageHeight;
    uhdrRawImg.planes[UHDR_PLANE_Y] = rawImgP010.getImageHandle()->data;
    uhdrRawImg.stride[UHDR_PLANE_Y] = kImageWidth;
    uhdrRawImg.planes[UHDR_PLANE_UV] =
        ((uint8_t*)(rawImgP010.getImageHandle()->data)) + kImageWidth * kImageHeight * 2;
    uhdrRawImg.stride[UHDR_PLANE_UV] = kImageWidth;
    uhdr_error_info_t status = uhdr_enc_set_raw_image(obj, &uhdrRawImg, UHDR_HDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    uhdr_compressed_image_t uhdrCompressedImg;
    uhdrCompressedImg.data = sdr->data;
    uhdrCompressedImg.data_sz = sdr->length;
    uhdrCompressedImg.capacity = sdr->length;
    uhdrCompressedImg.cg = map_internal_cg_to_cg(sdr->colorGamut);
    uhdrCompressedImg.ct = UHDR_CT_UNSPECIFIED;
    uhdrCompressedImg.range = UHDR_CR_UNSPECIFIED;
    status = uhdr_enc_set_compressed_image(obj, &uhdrCompressedImg, UHDR_SDR_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;

    status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    status = uhdr_encode(obj);
    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
    uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
    ASSERT_NE(nullptr, compressedImage);
    ASSERT_EQ(jpgImg.getImageHandle()->length, compressedImage->data_sz);
    ASSERT_EQ(
        0, memcmp(jpgImg.getImageHandle()->data, compressedImage->data, compressedImage->data_sz));
    uhdr_release_encoder(obj);
  }

  auto jpg1 = jpgImg.getImageHandle();

#ifdef DUMP_OUTPUT
  if (!writeFile("encode_api3_output.jpeg", jpg1->data, jpg1->length)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif

  ASSERT_NO_FATAL_FAILURE(decodeJpegRImg(jpg1, "decode_api3_output.rgb"));
}

INSTANTIATE_TEST_SUITE_P(
    JpegRAPIParameterizedTests, JpegRAPIEncodeAndDecodeTest,
    ::testing::Combine(::testing::Values(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3,
                                         ULTRAHDR_COLORGAMUT_BT2100),
                       ::testing::Values(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3,
                                         ULTRAHDR_COLORGAMUT_BT2100)));

// ============================================================================
// Profiling
// ============================================================================
#ifdef _WIN32
class Profiler {
 public:
  void timerStart() { QueryPerformanceCounter(&mStartingTime); }

  void timerStop() { QueryPerformanceCounter(&mEndingTime); }

  double elapsedTime() {
    LARGE_INTEGER frequency;
    LARGE_INTEGER elapsedMicroseconds;
    QueryPerformanceFrequency(&frequency);
    elapsedMicroseconds.QuadPart = mEndingTime.QuadPart - mStartingTime.QuadPart;
    return (double)elapsedMicroseconds.QuadPart / (double)frequency.QuadPart * 1000000;
  }

 private:
  LARGE_INTEGER mStartingTime;
  LARGE_INTEGER mEndingTime;
};
#else
class Profiler {
 public:
  void timerStart() { gettimeofday(&mStartingTime, nullptr); }

  void timerStop() { gettimeofday(&mEndingTime, nullptr); }

  int64_t elapsedTime() {
    struct timeval elapsedMicroseconds;
    elapsedMicroseconds.tv_sec = mEndingTime.tv_sec - mStartingTime.tv_sec;
    elapsedMicroseconds.tv_usec = mEndingTime.tv_usec - mStartingTime.tv_usec;
    return elapsedMicroseconds.tv_sec * 1000000 + elapsedMicroseconds.tv_usec;
  }

 private:
  struct timeval mStartingTime;
  struct timeval mEndingTime;
};
#endif

class JpegRBenchmark : public JpegR {
 public:
#ifdef UHDR_ENABLE_GLES
  JpegRBenchmark(uhdr_opengl_ctxt_t* uhdrGLCtxt) : JpegR(uhdrGLCtxt) {}
#endif
  void BenchmarkGenerateGainMap(uhdr_raw_image_t* yuv420Image, uhdr_raw_image_t* p010Image,
                                uhdr_gainmap_metadata_ext_t* metadata,
                                std::unique_ptr<uhdr_raw_image_ext_t>& gainmap);
  void BenchmarkApplyGainMap(uhdr_raw_image_t* yuv420Image, uhdr_raw_image_t* map,
                             uhdr_gainmap_metadata_ext_t* metadata, uhdr_raw_image_t* dest);

 private:
  const int kProfileCount = 10;
};

void JpegRBenchmark::BenchmarkGenerateGainMap(uhdr_raw_image_t* yuv420Image,
                                              uhdr_raw_image_t* p010Image,
                                              uhdr_gainmap_metadata_ext_t* metadata,
                                              std::unique_ptr<uhdr_raw_image_ext_t>& gainmap) {
  ASSERT_EQ(yuv420Image->w, p010Image->w);
  ASSERT_EQ(yuv420Image->h, p010Image->h);
  Profiler profileGenerateMap;
  profileGenerateMap.timerStart();
  for (auto i = 0; i < kProfileCount; i++) {
    ASSERT_EQ(UHDR_CODEC_OK, generateGainMap(yuv420Image, p010Image, metadata, gainmap).error_code);
  }
  profileGenerateMap.timerStop();
  ALOGV("Generate Gain Map:- Res = %u x %u, time = %f ms", yuv420Image->w, yuv420Image->h,
        profileGenerateMap.elapsedTime() / (kProfileCount * 1000.f));
}

void JpegRBenchmark::BenchmarkApplyGainMap(uhdr_raw_image_t* yuv420Image, uhdr_raw_image_t* map,
                                           uhdr_gainmap_metadata_ext_t* metadata,
                                           uhdr_raw_image_t* dest) {
  Profiler profileRecMap;
  profileRecMap.timerStart();
  for (auto i = 0; i < kProfileCount; i++) {
    ASSERT_EQ(UHDR_CODEC_OK, applyGainMap(yuv420Image, map, metadata, UHDR_CT_HLG,
                                          UHDR_IMG_FMT_32bppRGBA1010102, FLT_MAX, dest)
                                 .error_code);
  }
  profileRecMap.timerStop();
  ALOGV("Apply Gain Map:- Res = %u x %u, time = %f ms", yuv420Image->w, yuv420Image->h,
        profileRecMap.elapsedTime() / (kProfileCount * 1000.f));
}

TEST(JpegRTest, ProfileGainMapFuncs) {
  UhdrUnCompressedStructWrapper rawImgP010(kImageWidth, kImageHeight, YCbCr_p010);
  ASSERT_TRUE(rawImgP010.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
  ASSERT_TRUE(rawImgP010.allocateMemory());
  ASSERT_TRUE(rawImgP010.loadRawResource(kYCbCrP010FileName));
  UhdrUnCompressedStructWrapper rawImg420(kImageWidth, kImageHeight, YCbCr_420);
  ASSERT_TRUE(rawImg420.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
  ASSERT_TRUE(rawImg420.allocateMemory());
  ASSERT_TRUE(rawImg420.loadRawResource(kYCbCr420FileName));
  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);

  uhdr_raw_image_t hdr_intent, sdr_intent;

  {
    auto rawImg = rawImgP010.getImageHandle();
    if (rawImg->luma_stride == 0) rawImg->luma_stride = rawImg->width;
    if (!rawImg->chroma_data) {
      uint16_t* data = reinterpret_cast<uint16_t*>(rawImg->data);
      rawImg->chroma_data = data + rawImg->luma_stride * rawImg->height;
      rawImg->chroma_stride = rawImg->luma_stride;
    }
    hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    hdr_intent.cg = UHDR_CG_BT_2100;
    hdr_intent.ct = UHDR_CT_HLG;
    hdr_intent.range = UHDR_CR_LIMITED_RANGE;
    hdr_intent.w = rawImg->width;
    hdr_intent.h = rawImg->height;
    hdr_intent.planes[UHDR_PLANE_Y] = rawImg->data;
    hdr_intent.stride[UHDR_PLANE_Y] = rawImg->luma_stride;
    hdr_intent.planes[UHDR_PLANE_UV] = rawImg->chroma_data;
    hdr_intent.stride[UHDR_PLANE_UV] = rawImg->chroma_stride;
    hdr_intent.planes[UHDR_PLANE_V] = nullptr;
    hdr_intent.stride[UHDR_PLANE_V] = 0;
  }
  {
    auto rawImg = rawImg420.getImageHandle();
    if (rawImg->luma_stride == 0) rawImg->luma_stride = rawImg->width;
    if (!rawImg->chroma_data) {
      uint8_t* data = reinterpret_cast<uint8_t*>(rawImg->data);
      rawImg->chroma_data = data + rawImg->luma_stride * rawImg->height;
      rawImg->chroma_stride = rawImg->luma_stride / 2;
    }
    sdr_intent.fmt = UHDR_IMG_FMT_12bppYCbCr420;
    sdr_intent.cg = UHDR_CG_DISPLAY_P3;
    sdr_intent.ct = UHDR_CT_SRGB;
    sdr_intent.range = rawImg->colorRange;
    sdr_intent.w = rawImg->width;
    sdr_intent.h = rawImg->height;
    sdr_intent.planes[UHDR_PLANE_Y] = rawImg->data;
    sdr_intent.stride[UHDR_PLANE_Y] = rawImg->luma_stride;
    sdr_intent.planes[UHDR_PLANE_U] = rawImg->chroma_data;
    sdr_intent.stride[UHDR_PLANE_U] = rawImg->chroma_stride;
    uint8_t* data = reinterpret_cast<uint8_t*>(rawImg->chroma_data);
    data += (rawImg->height * rawImg->chroma_stride) / 2;
    sdr_intent.planes[UHDR_PLANE_V] = data;
    sdr_intent.stride[UHDR_PLANE_V] = rawImg->chroma_stride;
  }

  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;

#ifdef UHDR_ENABLE_GLES
  uhdr_opengl_ctxt_t glCtxt;
  glCtxt.init_opengl_ctxt();
  JpegRBenchmark benchmark(glCtxt.mErrorStatus.error_code == UHDR_CODEC_OK ? &glCtxt : nullptr);
#else
  JpegRBenchmark benchmark;
#endif

  ASSERT_NO_FATAL_FAILURE(
      benchmark.BenchmarkGenerateGainMap(&sdr_intent, &hdr_intent, &metadata, gainmap));

  const int dstSize = kImageWidth * kImageWidth * 4;
  auto bufferDst = std::make_unique<uint8_t[]>(dstSize);
  uhdr_raw_image_t output;
  output.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
  output.cg = UHDR_CG_UNSPECIFIED;
  output.ct = UHDR_CT_UNSPECIFIED;
  output.range = UHDR_CR_UNSPECIFIED;
  output.w = kImageWidth;
  output.h = kImageHeight;
  output.planes[UHDR_PLANE_PACKED] = bufferDst.get();
  output.stride[UHDR_PLANE_PACKED] = kImageWidth;
  output.planes[UHDR_PLANE_U] = nullptr;
  output.stride[UHDR_PLANE_U] = 0;
  output.planes[UHDR_PLANE_V] = nullptr;
  output.stride[UHDR_PLANE_V] = 0;

  ASSERT_NO_FATAL_FAILURE(
      benchmark.BenchmarkApplyGainMap(&sdr_intent, gainmap.get(), &metadata, &output));

#ifdef UHDR_ENABLE_GLES
  glCtxt.delete_opengl_ctxt();
#endif
}

}  // namespace ultrahdr
