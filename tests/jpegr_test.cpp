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

#include <sys/time.h>
#include <fstream>
#include <iostream>

#include <ultrahdr/gainmapmath.h>
#include <ultrahdr/jpegr.h>
#include <ultrahdr/jpegrutils.h>

#include <gtest/gtest.h>
#include <utils/Log.h>

//#define DUMP_OUTPUT

namespace android::ultrahdr {

// resources used by unit tests
const char* kYCbCrP010FileName = "raw_p010_image.p010";
const char* kYCbCr420FileName = "raw_yuv420_image.yuv420";
const char* kSdrJpgFileName = "jpeg_image.jpg";
const int kImageWidth = 1280;
const int kImageHeight = 720;
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
  UhdrUnCompressedStructWrapper(uint32_t width, uint32_t height, UhdrInputFormat format);
  ~UhdrUnCompressedStructWrapper() = default;

  bool setChromaMode(bool isChromaContiguous);
  bool setImageStride(int lumaStride, int chromaStride);
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
  UhdrCompressedStructWrapper(uint32_t width, uint32_t height);
  ~UhdrCompressedStructWrapper() = default;

  bool allocateMemory();
  jr_compressed_ptr getImageHandle();

private:
  std::unique_ptr<uint8_t[]> mData;
  jpegr_compressed_struct mImg{};
  uint32_t mWidth;
  uint32_t mHeight;
};

UhdrUnCompressedStructWrapper::UhdrUnCompressedStructWrapper(uint32_t width, uint32_t height,
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

bool UhdrUnCompressedStructWrapper::setImageStride(int lumaStride, int chromaStride) {
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
    int length = mImg.width * mImg.height * bpp * 3 / 2; // 2x2 subsampling
    if (size < length) {
      std::cerr << "requested to read " << length << " bytes from file : " << fileName
                << ", file contains only " << length << " bytes" << std::endl;
      return false;
    }
    ifd.seekg(0, std::ios::beg);
    int lumaStride = mImg.luma_stride == 0 ? mImg.width : mImg.luma_stride;
    char* mem = static_cast<char*>(mImg.data);
    for (int i = 0; i < mImg.height; i++) {
      ifd.read(mem, mImg.width * bpp);
      mem += lumaStride * bpp;
    }
    if (!mIsChromaContiguous) {
      mem = static_cast<char*>(mImg.chroma_data);
    }
    int chromaStride;
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
      for (int i = 0; i < mImg.height / 2; i++) {
        ifd.read(mem, mImg.width * 2);
        mem += chromaStride * 2;
      }
    } else {
      for (int i = 0; i < mImg.height / 2; i++) {
        ifd.read(mem, (mImg.width / 2));
        mem += chromaStride;
      }
      for (int i = 0; i < mImg.height / 2; i++) {
        ifd.read(mem, (mImg.width / 2));
        mem += chromaStride;
      }
    }
    return true;
  }
  std::cerr << "unable to open file : " << fileName << std::endl;
  return false;
}

jr_uncompressed_ptr UhdrUnCompressedStructWrapper::getImageHandle() {
  return &mImg;
}

UhdrCompressedStructWrapper::UhdrCompressedStructWrapper(uint32_t width, uint32_t height) {
  mWidth = width;
  mHeight = height;
}

bool UhdrCompressedStructWrapper::allocateMemory() {
  if (mWidth == 0 || (mWidth % 2 != 0) || mHeight == 0 || (mHeight % 2 != 0)) {
    std::cerr << "Object in bad state, mem alloc failed" << std::endl;
    return false;
  }
  int maxLength = std::max(8 * 1024 /* min size 8kb */, (int)(mWidth * mHeight * 3 * 2));
  mData = std::make_unique<uint8_t[]>(maxLength);
  mImg.data = mData.get();
  mImg.length = 0;
  mImg.maxLength = maxLength;
  return true;
}

jr_compressed_ptr UhdrCompressedStructWrapper::getImageHandle() {
  return &mImg;
}

static bool writeFile(const char* filename, void*& result, int length) {
  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    ofd.write(static_cast<char*>(result), length);
    return true;
  }
  std::cerr << "unable to write to file : " << filename << std::endl;
  return false;
}

static bool readFile(const char* fileName, void*& result, int maxLength, int& length) {
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

void decodeJpegRImg(jr_compressed_ptr img, [[maybe_unused]] const char* outFileName) {
  std::vector<uint8_t> iccData(0);
  std::vector<uint8_t> exifData(0);
  jpegr_info_struct info{0, 0, &iccData, &exifData};
  JpegR jpegHdr;
  ASSERT_EQ(OK, jpegHdr.getJPEGRInfo(img, &info));
  ASSERT_EQ(kImageWidth, info.width);
  ASSERT_EQ(kImageHeight, info.height);
  size_t outSize = info.width * info.height * 8;
  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(outSize);
  jpegr_uncompressed_struct destImage{};
  destImage.data = data.get();
  ASSERT_EQ(OK, jpegHdr.decodeJPEGR(img, &destImage));
  ASSERT_EQ(kImageWidth, destImage.width);
  ASSERT_EQ(kImageHeight, destImage.height);
#ifdef DUMP_OUTPUT
  if (!writeFile(outFileName, destImage.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
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

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), -1, nullptr),
              OK)
            << "fail, API allows bad jpeg quality factor";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), 101, nullptr),
              OK)
            << "fail, API allows bad jpeg quality factor";

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                          ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(-10),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad hdr transfer function";
  }

  // test dest
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr, kQuality,
                                  nullptr),
              OK)
            << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows nullptr dest";
  }

  // test p010 input
  {
    ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows nullptr p010 image";
  }

  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED));
    ASSERT_TRUE(rawImg.allocateMemory());
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad p010 color gamut";

    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(
            static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1)));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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
              OK)
            << "fail, API allows bad jpeg quality factor";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), 101, nullptr),
              OK)
            << "fail, API allows bad jpeg quality factor";

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                          ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(-10),
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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
              OK)
            << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              OK)
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
              OK)
            << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut =
            static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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
              OK)
            << "fail, API allows nullptr 420 image";

    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->colorGamut =
            static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth - 1;
    rawImg420->height = kHeight;
    rawImg420->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image height for 420";

    rawImg420->width = 0;
    rawImg420->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad image height for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
            << "fail, API allows bad luma stride for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = 0;
    rawImg420->chroma_data = rawImgP010->data;
    rawImg420->chroma_stride = kWidth / 2 - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle(), kQuality, nullptr),
              OK)
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

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                          ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(-10),
                                  jpgImg.getImageHandle()),
              OK)
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
              OK)
            << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK)
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

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(), nullptr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr for compressed image";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr for compressed image";
  }

  // test p010 input
  {
    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, rawImg2.getImageHandle(), jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
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
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut =
            static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad chroma stride";
  }

  // test 420 input
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), nullptr, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr 420 image";

    UhdrUnCompressedStructWrapper rawImg2(16, 16, YCbCr_420);
    ASSERT_TRUE(rawImg2.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), rawImg2.getImageHandle(),
                                  jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
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
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->colorGamut =
            static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad 420 color gamut";

    rawImg420->width = kWidth - 1;
    rawImg420->height = kHeight;
    rawImg420->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image height for 420";

    rawImg420->width = 0;
    rawImg420->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image width for 420";

    rawImg420->width = kWidth;
    rawImg420->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image height for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad luma stride for 420";

    rawImg420->width = kWidth;
    rawImg420->height = kHeight;
    rawImg420->luma_stride = 0;
    rawImg420->chroma_data = rawImgP010->data;
    rawImg420->chroma_stride = kWidth / 2 - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, rawImg420, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
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
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(
                                          ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad hdr transfer function";
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  static_cast<ultrahdr_transfer_function>(-10),
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad hdr transfer function";
  }

  // test dest
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr),
              OK)
            << "fail, API allows nullptr dest";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK)
            << "fail, API allows nullptr dest";
  }

  // test compressed image
  {
    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_TRUE(rawImg.allocateMemory());

    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), nullptr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr for compressed image";
    UhdrCompressedStructWrapper jpgImg2(16, 16);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr for compressed image";
  }

  // test p010 input
  {
    ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows nullptr p010 image";

    UhdrUnCompressedStructWrapper rawImg(16, 16, YCbCr_p010);
    ASSERT_TRUE(rawImg.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100));
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImg.getImageHandle(), jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
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
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut =
            static_cast<ultrahdr_color_gamut>(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad p010 color gamut";

    rawImgP010->width = kWidth - 1;
    rawImgP010->height = kHeight;
    rawImgP010->colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight - 1;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = 0;
    rawImgP010->height = kHeight;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image width";

    rawImgP010->width = kWidth;
    rawImgP010->height = 0;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad image height";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
            << "fail, API allows bad luma stride";

    rawImgP010->width = kWidth;
    rawImgP010->height = kHeight;
    rawImgP010->luma_stride = kWidth + 64;
    rawImgP010->chroma_data = rawImgP010->data;
    rawImgP010->chroma_stride = kWidth - 2;
    ASSERT_NE(uHdrLib.encodeJPEGR(rawImgP010, jpgImg.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg.getImageHandle()),
              OK)
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
            OK)
          << "fail, API allows nullptr dest";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), nullptr,
                                jpgImg2.getImageHandle()),
            OK)
          << "fail, API allows nullptr dest";

  // test primary image
  ASSERT_NE(uHdrLib.encodeJPEGR(nullptr, jpgImg.getImageHandle(), nullptr, jpgImg.getImageHandle()),
            OK)
          << "fail, API allows nullptr primary image";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg2.getImageHandle(), jpgImg.getImageHandle(), nullptr,
                                jpgImg.getImageHandle()),
            OK)
          << "fail, API allows nullptr primary image";

  // test gain map
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), nullptr, nullptr, jpgImg.getImageHandle()),
            OK)
          << "fail, API allows nullptr gain map image";
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg2.getImageHandle(), nullptr,
                                jpgImg.getImageHandle()),
            OK)
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
            OK)
          << "fail, API allows bad metadata version";

  metadata = good_metadata;
  metadata.minContentBoost = 3.0f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            OK)
          << "fail, API allows bad metadata content boost";

  metadata = good_metadata;
  metadata.gamma = -0.1f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            OK)
          << "fail, API allows bad metadata gamma";

  metadata = good_metadata;
  metadata.offsetSdr = -0.1f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            OK)
          << "fail, API allows bad metadata offset sdr";

  metadata = good_metadata;
  metadata.offsetHdr = -0.1f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            OK)
          << "fail, API allows bad metadata offset hdr";

  metadata = good_metadata;
  metadata.hdrCapacityMax = 0.5f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            OK)
          << "fail, API allows bad metadata hdr capacity max";

  metadata = good_metadata;
  metadata.hdrCapacityMin = 0.5f;
  ASSERT_NE(uHdrLib.encodeJPEGR(jpgImg.getImageHandle(), jpgImg.getImageHandle(), &metadata,
                                jpgImg.getImageHandle()),
            OK)
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
  ASSERT_NE(uHdrLib.decodeJPEGR(nullptr, &destImage), OK)
          << "fail, API allows nullptr for jpegr img";
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage), OK)
          << "fail, API allows nullptr for jpegr img";
  ASSERT_TRUE(jpgImg.allocateMemory());

  // test dest image
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), nullptr), OK)
          << "fail, API allows nullptr for dest";
  destImage.data = nullptr;
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage), OK)
          << "fail, API allows nullptr for dest";
  destImage.data = data.get();

  // test max display boost
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage, 0.5), OK)
          << "fail, API allows invalid max display boost";

  // test output format
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage, FLT_MAX, nullptr,
                                static_cast<ultrahdr_output_format>(-1)),
            OK)
          << "fail, API allows invalid output format";
  ASSERT_NE(uHdrLib.decodeJPEGR(jpgImg.getImageHandle(), &destImage, FLT_MAX, nullptr,
                                static_cast<ultrahdr_output_format>(ULTRAHDR_OUTPUT_MAX + 1)),
            OK)
          << "fail, API allows invalid output format";
}

TEST(JpegRTest, writeXmpThenRead) {
  ultrahdr_metadata_struct metadata_expected;
  metadata_expected.version = "1.0";
  metadata_expected.maxContentBoost = 1.25f;
  metadata_expected.minContentBoost = 0.75f;
  metadata_expected.gamma = 1.0f;
  metadata_expected.offsetSdr = 0.0f;
  metadata_expected.offsetHdr = 0.0f;
  metadata_expected.hdrCapacityMin = 1.0f;
  metadata_expected.hdrCapacityMax = metadata_expected.maxContentBoost;
  const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
  const int nameSpaceLength = nameSpace.size() + 1; // need to count the null terminator

  std::string xmp = generateXmpForSecondaryImage(metadata_expected);

  std::vector<uint8_t> xmpData;
  xmpData.reserve(nameSpaceLength + xmp.size());
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(nameSpace.c_str()),
                 reinterpret_cast<const uint8_t*>(nameSpace.c_str()) + nameSpaceLength);
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(xmp.c_str()),
                 reinterpret_cast<const uint8_t*>(xmp.c_str()) + xmp.size());

  ultrahdr_metadata_struct metadata_read;
  EXPECT_TRUE(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read));
  EXPECT_FLOAT_EQ(metadata_expected.maxContentBoost, metadata_read.maxContentBoost);
  EXPECT_FLOAT_EQ(metadata_expected.minContentBoost, metadata_read.minContentBoost);
  EXPECT_FLOAT_EQ(metadata_expected.gamma, metadata_read.gamma);
  EXPECT_FLOAT_EQ(metadata_expected.offsetSdr, metadata_read.offsetSdr);
  EXPECT_FLOAT_EQ(metadata_expected.offsetHdr, metadata_read.offsetHdr);
  EXPECT_FLOAT_EQ(metadata_expected.hdrCapacityMin, metadata_read.hdrCapacityMin);
  EXPECT_FLOAT_EQ(metadata_expected.hdrCapacityMax, metadata_read.hdrCapacityMax);
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
  ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg.getImageHandle(),
                                ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                jpgImg.getImageHandle(), kQuality, nullptr),
            OK);
  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2.setImageStride(kImageWidth + 18, 0));
    ASSERT_TRUE(rawImg2.allocateMemory());
    ASSERT_TRUE(rawImg2.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              OK);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2.getImageHandle(),
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle(), kQuality, nullptr),
              OK);
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
            OK);
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
              OK);
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
              OK);
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
              OK);
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
              OK);
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
              OK);
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
              OK);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
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
              OK);
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
              OK);
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
  ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                                ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                jpgImg.getImageHandle()),
            OK);
  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, 0));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), rawImg420.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), rawImg2420.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
  ASSERT_EQ(uHdrLib.encodeJPEGR(rawImgP010.getImageHandle(), sdr,
                                ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                jpgImg.getImageHandle()),
            OK);
  // encode with luma stride set
  {
    UhdrUnCompressedStructWrapper rawImg2P010(kImageWidth, kImageHeight, YCbCr_p010);
    ASSERT_TRUE(rawImg2P010.setImageColorGamut(mP010ColorGamut));
    ASSERT_TRUE(rawImg2P010.setImageStride(kImageWidth + 128, 0));
    ASSERT_TRUE(rawImg2P010.allocateMemory());
    ASSERT_TRUE(rawImg2P010.loadRawResource(kYCbCrP010FileName));
    UhdrCompressedStructWrapper jpgImg2(kImageWidth, kImageHeight);
    ASSERT_TRUE(jpgImg2.allocateMemory());
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
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
    ASSERT_EQ(uHdrLib.encodeJPEGR(rawImg2P010.getImageHandle(), sdr,
                                  ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                                  jpgImg2.getImageHandle()),
              OK);
    auto jpg1 = jpgImg.getImageHandle();
    auto jpg2 = jpgImg2.getImageHandle();
    ASSERT_EQ(jpg1->length, jpg2->length);
    ASSERT_EQ(0, memcmp(jpg1->data, jpg2->data, jpg1->length));
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

class JpegRBenchmark : public JpegR {
public:
  void BenchmarkGenerateGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr p010Image,
                                ultrahdr_metadata_ptr metadata, jr_uncompressed_ptr map);
  void BenchmarkApplyGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr map,
                             ultrahdr_metadata_ptr metadata, jr_uncompressed_ptr dest);

private:
  const int kProfileCount = 10;
};

void JpegRBenchmark::BenchmarkGenerateGainMap(jr_uncompressed_ptr yuv420Image,
                                              jr_uncompressed_ptr p010Image,
                                              ultrahdr_metadata_ptr metadata,
                                              jr_uncompressed_ptr map) {
  ASSERT_EQ(yuv420Image->width, p010Image->width);
  ASSERT_EQ(yuv420Image->height, p010Image->height);
  Profiler profileGenerateMap;
  profileGenerateMap.timerStart();
  for (auto i = 0; i < kProfileCount; i++) {
    ASSERT_EQ(OK,
              generateGainMap(yuv420Image, p010Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
                              metadata, map));
    if (i != kProfileCount - 1) delete[] static_cast<uint8_t*>(map->data);
  }
  profileGenerateMap.timerStop();
  ALOGE("Generate Gain Map:- Res = %i x %i, time = %f ms", yuv420Image->width, yuv420Image->height,
        profileGenerateMap.elapsedTime() / (kProfileCount * 1000.f));
}

void JpegRBenchmark::BenchmarkApplyGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr map,
                                           ultrahdr_metadata_ptr metadata,
                                           jr_uncompressed_ptr dest) {
  Profiler profileRecMap;
  profileRecMap.timerStart();
  for (auto i = 0; i < kProfileCount; i++) {
    ASSERT_EQ(OK,
              applyGainMap(yuv420Image, map, metadata, ULTRAHDR_OUTPUT_HDR_HLG,
                           metadata->maxContentBoost /* displayBoost */, dest));
  }
  profileRecMap.timerStop();
  ALOGE("Apply Gain Map:- Res = %i x %i, time = %f ms", yuv420Image->width, yuv420Image->height,
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
  ultrahdr_metadata_struct metadata = {.version = "1.0"};
  jpegr_uncompressed_struct map = {.data = NULL,
                                   .width = 0,
                                   .height = 0,
                                   .colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED};
  {
    auto rawImg = rawImgP010.getImageHandle();
    if (rawImg->luma_stride == 0) rawImg->luma_stride = rawImg->width;
    if (!rawImg->chroma_data) {
      uint16_t* data = reinterpret_cast<uint16_t*>(rawImg->data);
      rawImg->chroma_data = data + rawImg->luma_stride * rawImg->height;
      rawImg->chroma_stride = rawImg->luma_stride;
    }
  }
  {
    auto rawImg = rawImg420.getImageHandle();
    if (rawImg->luma_stride == 0) rawImg->luma_stride = rawImg->width;
    if (!rawImg->chroma_data) {
      uint8_t* data = reinterpret_cast<uint8_t*>(rawImg->data);
      rawImg->chroma_data = data + rawImg->luma_stride * rawImg->height;
      rawImg->chroma_stride = rawImg->luma_stride / 2;
    }
  }

  JpegRBenchmark benchmark;
  ASSERT_NO_FATAL_FAILURE(benchmark.BenchmarkGenerateGainMap(rawImg420.getImageHandle(),
                                                             rawImgP010.getImageHandle(), &metadata,
                                                             &map));

  const int dstSize = kImageWidth * kImageWidth * 4;
  auto bufferDst = std::make_unique<uint8_t[]>(dstSize);
  jpegr_uncompressed_struct dest = {.data = bufferDst.get(),
                                    .width = 0,
                                    .height = 0,
                                    .colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED};

  ASSERT_NO_FATAL_FAILURE(
          benchmark.BenchmarkApplyGainMap(rawImg420.getImageHandle(), &map, &metadata, &dest));
}

} // namespace android::ultrahdr
