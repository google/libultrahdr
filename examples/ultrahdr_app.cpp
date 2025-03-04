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

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/time.h>
#endif

#include <string.h>

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>

#include "ultrahdr_api.h"

const float BT601YUVtoRGBMatrix[9] = {
    1.f, 0.f, 1.402f, 1.f, (-0.202008f / 0.587f), (-0.419198f / 0.587f), 1.0f, 1.772f, 0.0f};
const float BT709YUVtoRGBMatrix[9] = {
    1.f,  0.f,     1.5748f, 1.f, (-0.13397432f / 0.7152f), (-0.33480248f / 0.7152f),
    1.0f, 1.8556f, 0.0f};
const float BT2020YUVtoRGBMatrix[9] = {
    1.f, 0.f, 1.4746f, 1.f, (-0.11156702f / 0.6780f), (-0.38737742f / 0.6780f), 1.f, 1.8814f, 0.f};

const float BT601RGBtoYUVMatrix[9] = {0.299f,
                                      0.587f,
                                      0.114f,
                                      (-0.299f / 1.772f),
                                      (-0.587f / 1.772f),
                                      0.5f,
                                      0.5f,
                                      (-0.587f / 1.402f),
                                      (-0.114f / 1.402f)};
const float BT709RGBtoYUVMatrix[9] = {0.2126f,
                                      0.7152f,
                                      0.0722f,
                                      (-0.2126f / 1.8556f),
                                      (-0.7152f / 1.8556f),
                                      0.5f,
                                      0.5f,
                                      (-0.7152f / 1.5748f),
                                      (-0.0722f / 1.5748f)};
const float BT2020RGBtoYUVMatrix[9] = {0.2627f,
                                       0.6780f,
                                       0.0593f,
                                       (-0.2627f / 1.8814f),
                                       (-0.6780f / 1.8814f),
                                       0.5f,
                                       0.5f,
                                       (-0.6780f / 1.4746f),
                                       (-0.0593f / 1.4746f)};

// remove these once introduced in ultrahdr_api.h
const int UHDR_IMG_FMT_48bppYCbCr444 = 101;

int optind_s = 1;
int optopt_s = 0;
char* optarg_s = nullptr;

int getopt_s(int argc, char* const argv[], char* ostr) {
  if (optind_s >= argc) return -1;

  const char* arg = argv[optind_s];
  if (arg[0] != '-' || !arg[1]) {
    std::cerr << "invalid option " << arg << std::endl;
    return '?';
  }
  optopt_s = arg[1];
  char* oindex = strchr(ostr, optopt_s);
  if (!oindex) {
    std::cerr << "unsupported option " << arg << std::endl;
    return '?';
  }
  if (oindex[1] != ':') {
    optarg_s = nullptr;
    return optopt_s;
  }

  if (argc > ++optind_s) {
    optarg_s = (char*)argv[optind_s++];
  } else {
    std::cerr << "option " << arg << " requires an argument" << std::endl;
    optarg_s = nullptr;
    return '?';
  }
  return optopt_s;
}

// #define PROFILE_ENABLE 1
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

#define READ_BYTES(DESC, ADDR, LEN)                                                             \
  DESC.read(static_cast<char*>(ADDR), (LEN));                                                   \
  if (DESC.gcount() != (LEN)) {                                                                 \
    std::cerr << "failed to read : " << (LEN) << " bytes, read : " << DESC.gcount() << " bytes" \
              << std::endl;                                                                     \
    return false;                                                                               \
  }

static bool loadFile(const char* filename, void*& result, std::streamoff length) {
  if (length <= 0) {
    std::cerr << "requested to read invalid length : " << length
              << " bytes from file : " << filename << std::endl;
    return false;
  }
  std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    auto size = ifd.tellg();
    if (size < length) {
      std::cerr << "requested to read " << length << " bytes from file : " << filename
                << ", file contains only " << size << " bytes" << std::endl;
      return false;
    }
    ifd.seekg(0, std::ios::beg);
    result = malloc(length);
    if (result == nullptr) {
      std::cerr << "failed to allocate memory to store contents of file : " << filename
                << std::endl;
      return false;
    }
    READ_BYTES(ifd, result, length)
    return true;
  }
  std::cerr << "unable to open file : " << filename << std::endl;
  return false;
}

static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
  std::ifstream ifd(filename, std::ios::binary);
  if (ifd.good()) {
    if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      const size_t bpp = 2;
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], bpp * handle->w * handle->h)
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_UV], bpp * (handle->w / 2) * (handle->h / 2) * 2)
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
               handle->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
      const size_t bpp = 4;
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], bpp * handle->w * handle->h)
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
      const size_t bpp = 8;
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], bpp * handle->w * handle->h)
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], (size_t)handle->w * handle->h)
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_U], (size_t)(handle->w / 2) * (handle->h / 2))
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_V], (size_t)(handle->w / 2) * (handle->h / 2))
      return true;
    }
    return false;
  }
  std::cerr << "unable to open file : " << filename << std::endl;
  return false;
}

static bool writeFile(const char* filename, void*& result, size_t length) {
  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    ofd.write(static_cast<char*>(result), length);
    return true;
  }
  std::cerr << "unable to write to file : " << filename << std::endl;
  return false;
}

static bool writeFile(const char* filename, uhdr_raw_image_t* img) {
  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    if (img->fmt == UHDR_IMG_FMT_32bppRGBA8888 || img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ||
        img->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
      char* data = static_cast<char*>(img->planes[UHDR_PLANE_PACKED]);
      const size_t bpp = img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
      const size_t stride = img->stride[UHDR_PLANE_PACKED] * bpp;
      const size_t length = img->w * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      return true;
    } else if ((int)img->fmt == UHDR_IMG_FMT_24bppYCbCr444 ||
               (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444) {
      char* data = static_cast<char*>(img->planes[UHDR_PLANE_Y]);
      const size_t bpp = (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444 ? 2 : 1;
      size_t stride = img->stride[UHDR_PLANE_Y] * bpp;
      size_t length = img->w * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      data = static_cast<char*>(img->planes[UHDR_PLANE_U]);
      stride = img->stride[UHDR_PLANE_U] * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      data = static_cast<char*>(img->planes[UHDR_PLANE_V]);
      stride = img->stride[UHDR_PLANE_V] * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      return true;
    }
    return false;
  }
  std::cerr << "unable to write to file : " << filename << std::endl;
  return false;
}

class UltraHdrAppInput {
 public:
  UltraHdrAppInput(const char* hdrIntentRawFile, const char* sdrIntentRawFile,
                   const char* sdrIntentCompressedFile, const char* gainmapCompressedFile,
                   const char* gainmapMetadataCfgFile, const char* exifFile, const char* outputFile,
                   int width, int height, uhdr_img_fmt_t hdrCf = UHDR_IMG_FMT_32bppRGBA1010102,
                   uhdr_img_fmt_t sdrCf = UHDR_IMG_FMT_32bppRGBA8888,
                   uhdr_color_gamut_t hdrCg = UHDR_CG_DISPLAY_P3,
                   uhdr_color_gamut_t sdrCg = UHDR_CG_BT_709,
                   uhdr_color_transfer_t hdrTf = UHDR_CT_HLG, int quality = 95,
                   uhdr_color_transfer_t oTf = UHDR_CT_HLG,
                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102, bool isHdrCrFull = false,
                   int gainmapScaleFactor = 1, int gainmapQuality = 95,
                   bool enableMultiChannelGainMap = true, float gamma = 1.0f,
                   bool enableGLES = false, uhdr_enc_preset_t encPreset = UHDR_USAGE_BEST_QUALITY,
                   float minContentBoost = FLT_MIN, float maxContentBoost = FLT_MAX,
                   float targetDispPeakBrightness = -1.0f)
      : mHdrIntentRawFile(hdrIntentRawFile),
        mSdrIntentRawFile(sdrIntentRawFile),
        mSdrIntentCompressedFile(sdrIntentCompressedFile),
        mGainMapCompressedFile(gainmapCompressedFile),
        mGainMapMetadataCfgFile(gainmapMetadataCfgFile),
        mExifFile(exifFile),
        mUhdrFile(nullptr),
        mOutputFile(outputFile),
        mWidth(width),
        mHeight(height),
        mHdrCf(hdrCf),
        mSdrCf(sdrCf),
        mHdrCg(hdrCg),
        mSdrCg(sdrCg),
        mHdrTf(hdrTf),
        mQuality(quality),
        mOTf(oTf),
        mOfmt(oFmt),
        mFullRange(isHdrCrFull),
        mMapDimensionScaleFactor(gainmapScaleFactor),
        mMapCompressQuality(gainmapQuality),
        mUseMultiChannelGainMap(enableMultiChannelGainMap),
        mGamma(gamma),
        mEnableGLES(enableGLES),
        mEncPreset(encPreset),
        mMinContentBoost(minContentBoost),
        mMaxContentBoost(maxContentBoost),
        mTargetDispPeakBrightness(targetDispPeakBrightness),
        mMode(0){};

  UltraHdrAppInput(const char* gainmapMetadataCfgFile, const char* uhdrFile, const char* outputFile,
                   uhdr_color_transfer_t oTf = UHDR_CT_HLG,
                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102, bool enableGLES = false)
      : mHdrIntentRawFile(nullptr),
        mSdrIntentRawFile(nullptr),
        mSdrIntentCompressedFile(nullptr),
        mGainMapCompressedFile(nullptr),
        mGainMapMetadataCfgFile(gainmapMetadataCfgFile),
        mExifFile(nullptr),
        mUhdrFile(uhdrFile),
        mOutputFile(outputFile),
        mWidth(0),
        mHeight(0),
        mHdrCf(UHDR_IMG_FMT_UNSPECIFIED),
        mSdrCf(UHDR_IMG_FMT_UNSPECIFIED),
        mHdrCg(UHDR_CG_UNSPECIFIED),
        mSdrCg(UHDR_CG_UNSPECIFIED),
        mHdrTf(UHDR_CT_UNSPECIFIED),
        mQuality(95),
        mOTf(oTf),
        mOfmt(oFmt),
        mFullRange(false),
        mMapDimensionScaleFactor(1),
        mMapCompressQuality(95),
        mUseMultiChannelGainMap(true),
        mGamma(1.0f),
        mEnableGLES(enableGLES),
        mEncPreset(UHDR_USAGE_BEST_QUALITY),
        mMinContentBoost(FLT_MIN),
        mMaxContentBoost(FLT_MAX),
        mTargetDispPeakBrightness(-1.0f),
        mMode(1){};

  ~UltraHdrAppInput() {
    int count = sizeof mRawP010Image.planes / sizeof mRawP010Image.planes[UHDR_PLANE_Y];
    for (int i = 0; i < count; i++) {
      if (mRawP010Image.planes[i]) {
        free(mRawP010Image.planes[i]);
        mRawP010Image.planes[i] = nullptr;
      }
      if (mRawRgba1010102Image.planes[i]) {
        free(mRawRgba1010102Image.planes[i]);
        mRawRgba1010102Image.planes[i] = nullptr;
      }
      if (mRawRgbaF16Image.planes[i]) {
        free(mRawRgbaF16Image.planes[i]);
        mRawRgbaF16Image.planes[i] = nullptr;
      }
      if (mRawYuv420Image.planes[i]) {
        free(mRawYuv420Image.planes[i]);
        mRawYuv420Image.planes[i] = nullptr;
      }
      if (mRawRgba8888Image.planes[i]) {
        free(mRawRgba8888Image.planes[i]);
        mRawRgba8888Image.planes[i] = nullptr;
      }
      if (mDecodedUhdrRgbImage.planes[i]) {
        free(mDecodedUhdrRgbImage.planes[i]);
        mDecodedUhdrRgbImage.planes[i] = nullptr;
      }
      if (mDecodedUhdrYuv444Image.planes[i]) {
        free(mDecodedUhdrYuv444Image.planes[i]);
        mDecodedUhdrYuv444Image.planes[i] = nullptr;
      }
    }
    if (mExifBlock.data) free(mExifBlock.data);
    if (mUhdrImage.data) free(mUhdrImage.data);
  }

  bool fillUhdrImageHandle();
  bool fillP010ImageHandle();
  bool fillRGBA1010102ImageHandle();
  bool fillRGBAF16ImageHandle();
  bool convertP010ToRGBImage();
  bool fillYuv420ImageHandle();
  bool fillRGBA8888ImageHandle();
  bool convertYuv420ToRGBImage();
  bool fillSdrCompressedImageHandle();
  bool fillGainMapCompressedImageHandle();
  bool fillGainMapMetadataDescriptor();
  bool fillExifMemoryBlock();
  bool writeGainMapMetadataToFile(uhdr_gainmap_metadata_t* metadata);
  bool convertRgba8888ToYUV444Image();
  bool convertRgba1010102ToYUV444Image();
  bool encode();
  bool decode();
  void computeRGBHdrPSNR();
  void computeRGBSdrPSNR();
  void computeYUVHdrPSNR();
  void computeYUVSdrPSNR();

  const char* mHdrIntentRawFile;
  const char* mSdrIntentRawFile;
  const char* mSdrIntentCompressedFile;
  const char* mGainMapCompressedFile;
  const char* mGainMapMetadataCfgFile;
  const char* mExifFile;
  const char* mUhdrFile;
  const char* mOutputFile;
  const int mWidth;
  const int mHeight;
  const uhdr_img_fmt_t mHdrCf;
  const uhdr_img_fmt_t mSdrCf;
  const uhdr_color_gamut_t mHdrCg;
  const uhdr_color_gamut_t mSdrCg;
  const uhdr_color_transfer_t mHdrTf;
  const int mQuality;
  const uhdr_color_transfer_t mOTf;
  const uhdr_img_fmt_t mOfmt;
  const bool mFullRange;
  const int mMapDimensionScaleFactor;
  const int mMapCompressQuality;
  const bool mUseMultiChannelGainMap;
  const float mGamma;
  const bool mEnableGLES;
  const uhdr_enc_preset_t mEncPreset;
  const float mMinContentBoost;
  const float mMaxContentBoost;
  const float mTargetDispPeakBrightness;
  const int mMode;

  uhdr_raw_image_t mRawP010Image{};
  uhdr_raw_image_t mRawRgba1010102Image{};
  uhdr_raw_image_t mRawRgbaF16Image{};
  uhdr_raw_image_t mRawYuv420Image{};
  uhdr_raw_image_t mRawRgba8888Image{};
  uhdr_compressed_image_t mSdrIntentCompressedImage{};
  uhdr_compressed_image_t mGainMapCompressedImage{};
  uhdr_gainmap_metadata mGainMapMetadata{};
  uhdr_mem_block_t mExifBlock{};
  uhdr_compressed_image_t mUhdrImage{};
  uhdr_raw_image_t mDecodedUhdrRgbImage{};
  uhdr_raw_image_t mDecodedUhdrYuv444Image{};
  double mPsnr[3]{};
};

bool UltraHdrAppInput::fillP010ImageHandle() {
  const size_t bpp = 2;
  size_t p010Size = bpp * mWidth * mHeight * 3 / 2;
  mRawP010Image.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  mRawP010Image.cg = mHdrCg;
  mRawP010Image.ct = mHdrTf;

  mRawP010Image.range = mFullRange ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE;
  mRawP010Image.w = mWidth;
  mRawP010Image.h = mHeight;
  mRawP010Image.planes[UHDR_PLANE_Y] = malloc(bpp * mWidth * mHeight);
  mRawP010Image.planes[UHDR_PLANE_UV] = malloc(bpp * (mWidth / 2) * (mHeight / 2) * 2);
  mRawP010Image.planes[UHDR_PLANE_V] = nullptr;
  mRawP010Image.stride[UHDR_PLANE_Y] = mWidth;
  mRawP010Image.stride[UHDR_PLANE_UV] = mWidth;
  mRawP010Image.stride[UHDR_PLANE_V] = 0;
  return loadFile(mHdrIntentRawFile, &mRawP010Image);
}

bool UltraHdrAppInput::fillYuv420ImageHandle() {
  size_t yuv420Size = (size_t)mWidth * mHeight * 3 / 2;
  mRawYuv420Image.fmt = UHDR_IMG_FMT_12bppYCbCr420;
  mRawYuv420Image.cg = mSdrCg;
  mRawYuv420Image.ct = UHDR_CT_SRGB;
  mRawYuv420Image.range = UHDR_CR_FULL_RANGE;
  mRawYuv420Image.w = mWidth;
  mRawYuv420Image.h = mHeight;
  mRawYuv420Image.planes[UHDR_PLANE_Y] = malloc((size_t)mWidth * mHeight);
  mRawYuv420Image.planes[UHDR_PLANE_U] = malloc((size_t)(mWidth / 2) * (mHeight / 2));
  mRawYuv420Image.planes[UHDR_PLANE_V] = malloc((size_t)(mWidth / 2) * (mHeight / 2));
  mRawYuv420Image.stride[UHDR_PLANE_Y] = mWidth;
  mRawYuv420Image.stride[UHDR_PLANE_U] = mWidth / 2;
  mRawYuv420Image.stride[UHDR_PLANE_V] = mWidth / 2;
  return loadFile(mSdrIntentRawFile, &mRawYuv420Image);
}

bool UltraHdrAppInput::fillRGBA1010102ImageHandle() {
  const size_t bpp = 4;
  mRawRgba1010102Image.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
  mRawRgba1010102Image.cg = mHdrCg;
  mRawRgba1010102Image.ct = mHdrTf;
  mRawRgba1010102Image.range = UHDR_CR_FULL_RANGE;
  mRawRgba1010102Image.w = mWidth;
  mRawRgba1010102Image.h = mHeight;
  mRawRgba1010102Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mWidth * mHeight);
  mRawRgba1010102Image.planes[UHDR_PLANE_UV] = nullptr;
  mRawRgba1010102Image.planes[UHDR_PLANE_V] = nullptr;
  mRawRgba1010102Image.stride[UHDR_PLANE_PACKED] = mWidth;
  mRawRgba1010102Image.stride[UHDR_PLANE_UV] = 0;
  mRawRgba1010102Image.stride[UHDR_PLANE_V] = 0;
  return loadFile(mHdrIntentRawFile, &mRawRgba1010102Image);
}

bool UltraHdrAppInput::fillRGBAF16ImageHandle() {
  const size_t bpp = 8;
  mRawRgbaF16Image.fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
  mRawRgbaF16Image.cg = mHdrCg;
  mRawRgbaF16Image.ct = mHdrTf;
  mRawRgbaF16Image.range = UHDR_CR_FULL_RANGE;
  mRawRgbaF16Image.w = mWidth;
  mRawRgbaF16Image.h = mHeight;
  mRawRgbaF16Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mWidth * mHeight);
  mRawRgbaF16Image.planes[UHDR_PLANE_UV] = nullptr;
  mRawRgbaF16Image.planes[UHDR_PLANE_V] = nullptr;
  mRawRgbaF16Image.stride[UHDR_PLANE_PACKED] = mWidth;
  mRawRgbaF16Image.stride[UHDR_PLANE_UV] = 0;
  mRawRgbaF16Image.stride[UHDR_PLANE_V] = 0;
  return loadFile(mHdrIntentRawFile, &mRawRgbaF16Image);
}

bool UltraHdrAppInput::fillRGBA8888ImageHandle() {
  const size_t bpp = 4;
  mRawRgba8888Image.fmt = UHDR_IMG_FMT_32bppRGBA8888;
  mRawRgba8888Image.cg = mSdrCg;
  mRawRgba8888Image.ct = UHDR_CT_SRGB;
  mRawRgba8888Image.range = UHDR_CR_FULL_RANGE;
  mRawRgba8888Image.w = mWidth;
  mRawRgba8888Image.h = mHeight;
  mRawRgba8888Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mWidth * mHeight);
  mRawRgba8888Image.planes[UHDR_PLANE_U] = nullptr;
  mRawRgba8888Image.planes[UHDR_PLANE_V] = nullptr;
  mRawRgba8888Image.stride[UHDR_PLANE_Y] = mWidth;
  mRawRgba8888Image.stride[UHDR_PLANE_U] = 0;
  mRawRgba8888Image.stride[UHDR_PLANE_V] = 0;
  return loadFile(mSdrIntentRawFile, &mRawRgba8888Image);
}

bool UltraHdrAppInput::fillSdrCompressedImageHandle() {
  std::ifstream ifd(mSdrIntentCompressedFile, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    auto size = ifd.tellg();
    mSdrIntentCompressedImage.capacity = size;
    mSdrIntentCompressedImage.data_sz = size;
    mSdrIntentCompressedImage.data = nullptr;
    mSdrIntentCompressedImage.cg = mSdrCg;
    mSdrIntentCompressedImage.ct = UHDR_CT_UNSPECIFIED;
    mSdrIntentCompressedImage.range = UHDR_CR_UNSPECIFIED;
    ifd.close();
    return loadFile(mSdrIntentCompressedFile, mSdrIntentCompressedImage.data, size);
  }
  return false;
}

bool UltraHdrAppInput::fillGainMapCompressedImageHandle() {
  std::ifstream ifd(mGainMapCompressedFile, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    auto size = ifd.tellg();
    mGainMapCompressedImage.capacity = size;
    mGainMapCompressedImage.data_sz = size;
    mGainMapCompressedImage.data = nullptr;
    mGainMapCompressedImage.cg = UHDR_CG_UNSPECIFIED;
    mGainMapCompressedImage.ct = UHDR_CT_UNSPECIFIED;
    mGainMapCompressedImage.range = UHDR_CR_UNSPECIFIED;
    ifd.close();
    return loadFile(mGainMapCompressedFile, mGainMapCompressedImage.data, size);
  }
  return false;
}

void parse_argument(uhdr_gainmap_metadata* metadata, char* argument, float* value) {
  if (!strcmp(argument, "maxContentBoost"))
    std::copy(value, value + 3, metadata->max_content_boost);
  else if (!strcmp(argument, "minContentBoost"))
    std::copy(value, value + 3, metadata->min_content_boost);
  else if (!strcmp(argument, "gamma"))
    std::copy(value, value + 3, metadata->gamma);
  else if (!strcmp(argument, "offsetSdr"))
    std::copy(value, value + 3, metadata->offset_sdr);
  else if (!strcmp(argument, "offsetHdr"))
    std::copy(value, value + 3, metadata->offset_hdr);
  else if (!strcmp(argument, "hdrCapacityMin"))
    metadata->hdr_capacity_min = *value;
  else if (!strcmp(argument, "hdrCapacityMax"))
    metadata->hdr_capacity_max = *value;
  else if (!strcmp(argument, "useBaseColorSpace"))
    metadata->use_base_cg = *value;
  else
    std::cout << " Ignoring argument " << argument << std::endl;
}

bool UltraHdrAppInput::fillGainMapMetadataDescriptor() {
  std::ifstream file(mGainMapMetadataCfgFile);
  if (!file.is_open()) {
    return false;
  }
  std::string line;
  char argument[128];
  float value[3];
  while (std::getline(file, line)) {
    int count = sscanf(line.c_str(), "--%s %f %f %f", argument, &value[0], &value[1], &value[2]);
    if (count == 2) value[1] = value[2] = value[0];
    if (count == 2 || count == 4)
      parse_argument(&mGainMapMetadata, argument, value);
    else
      std::cout << " Ignoring line " << line << std::endl;
  }
  file.close();
  return true;
}

bool UltraHdrAppInput::fillExifMemoryBlock() {
  std::ifstream ifd(mExifFile, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    auto size = ifd.tellg();
    mExifBlock.data = nullptr;
    mExifBlock.data_sz = size;
    mExifBlock.capacity = size;
    ifd.close();
    return loadFile(mExifFile, mExifBlock.data, size);
  }
  return false;
}

bool UltraHdrAppInput::writeGainMapMetadataToFile(uhdr_gainmap_metadata_t* metadata) {
  std::ofstream file(mGainMapMetadataCfgFile);
  if (!file.is_open()) {
    return false;
  }
  bool allChannelsIdentical = metadata->max_content_boost[0] == metadata->max_content_boost[1] &&
                              metadata->max_content_boost[0] == metadata->max_content_boost[2] &&
                              metadata->min_content_boost[0] == metadata->min_content_boost[1] &&
                              metadata->min_content_boost[0] == metadata->min_content_boost[2] &&
                              metadata->gamma[0] == metadata->gamma[1] &&
                              metadata->gamma[0] == metadata->gamma[2] &&
                              metadata->offset_sdr[0] == metadata->offset_sdr[1] &&
                              metadata->offset_sdr[0] == metadata->offset_sdr[2] &&
                              metadata->offset_hdr[0] == metadata->offset_hdr[1] &&
                              metadata->offset_hdr[0] == metadata->offset_hdr[2];
  if (allChannelsIdentical) {
    file << "--maxContentBoost " << metadata->max_content_boost[0] << std::endl;
    file << "--minContentBoost " << metadata->min_content_boost[0] << std::endl;
    file << "--gamma " << metadata->gamma[0] << std::endl;
    file << "--offsetSdr " << metadata->offset_sdr[0] << std::endl;
    file << "--offsetHdr " << metadata->offset_hdr[0] << std::endl;
  } else {
    file << "--maxContentBoost " << metadata->max_content_boost[0] << " "
         << metadata->max_content_boost[1] << " " << metadata->max_content_boost[2] << std::endl;
    file << "--minContentBoost " << metadata->min_content_boost[0] << " "
         << metadata->min_content_boost[1] << " " << metadata->min_content_boost[2] << std::endl;
    file << "--gamma " << metadata->gamma[0] << " " << metadata->gamma[1] << " "
         << metadata->gamma[2] << std::endl;
    file << "--offsetSdr " << metadata->offset_sdr[0] << " " << metadata->offset_sdr[1] << " "
         << metadata->offset_sdr[2] << std::endl;
    file << "--offsetHdr " << metadata->offset_hdr[0] << " " << metadata->offset_hdr[1] << " "
         << metadata->offset_hdr[2] << std::endl;
  }
  file << "--hdrCapacityMin " << metadata->hdr_capacity_min << std::endl;
  file << "--hdrCapacityMax " << metadata->hdr_capacity_max << std::endl;
  file << "--useBaseColorSpace " << metadata->use_base_cg << std::endl;
  file.close();
  return true;
}

bool UltraHdrAppInput::fillUhdrImageHandle() {
  std::ifstream ifd(mUhdrFile, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    auto size = ifd.tellg();
    mUhdrImage.capacity = size;
    mUhdrImage.data_sz = size;
    mUhdrImage.data = nullptr;
    mUhdrImage.cg = UHDR_CG_UNSPECIFIED;
    mUhdrImage.ct = UHDR_CT_UNSPECIFIED;
    mUhdrImage.range = UHDR_CR_UNSPECIFIED;
    ifd.close();
    return loadFile(mUhdrFile, mUhdrImage.data, size);
  }
  return false;
}

bool UltraHdrAppInput::encode() {
  if (mHdrIntentRawFile != nullptr) {
    if (mHdrCf == UHDR_IMG_FMT_24bppYCbCrP010) {
      if (!fillP010ImageHandle()) {
        std::cerr << " failed to load file " << mHdrIntentRawFile << std::endl;
        return false;
      }
    } else if (mHdrCf == UHDR_IMG_FMT_32bppRGBA1010102) {
      if (!fillRGBA1010102ImageHandle()) {
        std::cerr << " failed to load file " << mHdrIntentRawFile << std::endl;
        return false;
      }
    } else if (mHdrCf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
      if (!fillRGBAF16ImageHandle()) {
        std::cerr << " failed to load file " << mHdrIntentRawFile << std::endl;
        return false;
      }
    } else {
      std::cerr << " invalid hdr intent color format " << mHdrCf << std::endl;
      return false;
    }
  }
  if (mSdrIntentRawFile != nullptr) {
    if (mSdrCf == UHDR_IMG_FMT_12bppYCbCr420) {
      if (!fillYuv420ImageHandle()) {
        std::cerr << " failed to load file " << mSdrIntentRawFile << std::endl;
        return false;
      }
    } else if (mSdrCf == UHDR_IMG_FMT_32bppRGBA8888) {
      if (!fillRGBA8888ImageHandle()) {
        std::cerr << " failed to load file " << mSdrIntentRawFile << std::endl;
        return false;
      }
    } else {
      std::cerr << " invalid sdr intent color format " << mSdrCf << std::endl;
      return false;
    }
  }
  if (mSdrIntentCompressedFile != nullptr) {
    if (!fillSdrCompressedImageHandle()) {
      std::cerr << " failed to load file " << mSdrIntentCompressedFile << std::endl;
      return false;
    }
  }
  if (mGainMapCompressedFile != nullptr && mGainMapMetadataCfgFile != nullptr) {
    if (!fillGainMapCompressedImageHandle()) {
      std::cerr << " failed to load file " << mGainMapCompressedFile << std::endl;
      return false;
    }
    if (!fillGainMapMetadataDescriptor()) {
      std::cerr << " failed to read config file " << mGainMapMetadataCfgFile << std::endl;
      return false;
    }
  }
  if (mExifFile != nullptr) {
    if (!fillExifMemoryBlock()) {
      std::cerr << " failed to load file " << mExifFile << std::endl;
      return false;
    }
  }

#define RET_IF_ERR(x)                            \
  {                                              \
    uhdr_error_info_t status = (x);              \
    if (status.error_code != UHDR_CODEC_OK) {    \
      if (status.has_detail) {                   \
        std::cerr << status.detail << std::endl; \
      }                                          \
      uhdr_release_encoder(handle);              \
      return false;                              \
    }                                            \
  }
  uhdr_codec_private_t* handle = uhdr_create_encoder();
  if (mHdrIntentRawFile != nullptr) {
    if (mHdrCf == UHDR_IMG_FMT_24bppYCbCrP010) {
      RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawP010Image, UHDR_HDR_IMG))
    } else if (mHdrCf == UHDR_IMG_FMT_32bppRGBA1010102) {
      RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawRgba1010102Image, UHDR_HDR_IMG))
    } else if (mHdrCf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
      RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawRgbaF16Image, UHDR_HDR_IMG))
    }
  }
  if (mSdrIntentRawFile != nullptr) {
    if (mSdrCf == UHDR_IMG_FMT_12bppYCbCr420) {
      RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawYuv420Image, UHDR_SDR_IMG))
    } else if (mSdrCf == UHDR_IMG_FMT_32bppRGBA8888) {
      RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawRgba8888Image, UHDR_SDR_IMG))
    }
  }
  if (mSdrIntentCompressedFile != nullptr) {
    RET_IF_ERR(uhdr_enc_set_compressed_image(
        handle, &mSdrIntentCompressedImage,
        (mGainMapCompressedFile != nullptr && mGainMapMetadataCfgFile != nullptr) ? UHDR_BASE_IMG
                                                                                  : UHDR_SDR_IMG))
  }
  if (mGainMapCompressedFile != nullptr && mGainMapMetadataCfgFile != nullptr) {
    RET_IF_ERR(uhdr_enc_set_gainmap_image(handle, &mGainMapCompressedImage, &mGainMapMetadata))
  }
  if (mExifFile != nullptr) {
    RET_IF_ERR(uhdr_enc_set_exif_data(handle, &mExifBlock))
  }

  RET_IF_ERR(uhdr_enc_set_quality(handle, mQuality, UHDR_BASE_IMG))
  RET_IF_ERR(uhdr_enc_set_quality(handle, mMapCompressQuality, UHDR_GAIN_MAP_IMG))
  RET_IF_ERR(uhdr_enc_set_using_multi_channel_gainmap(handle, mUseMultiChannelGainMap))
  RET_IF_ERR(uhdr_enc_set_gainmap_scale_factor(handle, mMapDimensionScaleFactor))
  RET_IF_ERR(uhdr_enc_set_gainmap_gamma(handle, mGamma))
  RET_IF_ERR(uhdr_enc_set_preset(handle, mEncPreset))
  if (mMinContentBoost != FLT_MIN || mMaxContentBoost != FLT_MAX) {
    RET_IF_ERR(uhdr_enc_set_min_max_content_boost(handle, mMinContentBoost, mMaxContentBoost))
  }
  if (mTargetDispPeakBrightness != -1.0f) {
    RET_IF_ERR(uhdr_enc_set_target_display_peak_brightness(handle, mTargetDispPeakBrightness))
  }
  if (mEnableGLES) {
    RET_IF_ERR(uhdr_enable_gpu_acceleration(handle, mEnableGLES))
  }
#ifdef PROFILE_ENABLE
  Profiler profileEncode;
  profileEncode.timerStart();
#endif
  RET_IF_ERR(uhdr_encode(handle))
#ifdef PROFILE_ENABLE
  profileEncode.timerStop();
  auto avgEncTime = profileEncode.elapsedTime() / 1000.f;
  printf("Average encode time for res %d x %d is %f ms \n", mWidth, mHeight, avgEncTime);
#endif

#undef RET_IF_ERR

  auto output = uhdr_get_encoded_stream(handle);

  // for decoding
  mUhdrImage.data = malloc(output->data_sz);
  memcpy(mUhdrImage.data, output->data, output->data_sz);
  mUhdrImage.capacity = mUhdrImage.data_sz = output->data_sz;
  mUhdrImage.cg = output->cg;
  mUhdrImage.ct = output->ct;
  mUhdrImage.range = output->range;
  uhdr_release_encoder(handle);

  return writeFile(mOutputFile, mUhdrImage.data, mUhdrImage.data_sz);
}

bool UltraHdrAppInput::decode() {
  if (mMode == 1 && !fillUhdrImageHandle()) {
    std::cerr << " failed to load file " << mUhdrFile << std::endl;
    return false;
  }

#define RET_IF_ERR(x)                            \
  {                                              \
    uhdr_error_info_t status = (x);              \
    if (status.error_code != UHDR_CODEC_OK) {    \
      if (status.has_detail) {                   \
        std::cerr << status.detail << std::endl; \
      }                                          \
      uhdr_release_decoder(handle);              \
      return false;                              \
    }                                            \
  }

  uhdr_codec_private_t* handle = uhdr_create_decoder();
  RET_IF_ERR(uhdr_dec_set_image(handle, &mUhdrImage))
  RET_IF_ERR(uhdr_dec_set_out_color_transfer(handle, mOTf))
  RET_IF_ERR(uhdr_dec_set_out_img_format(handle, mOfmt))
  if (mEnableGLES) {
    RET_IF_ERR(uhdr_enable_gpu_acceleration(handle, mEnableGLES))
  }
  RET_IF_ERR(uhdr_dec_probe(handle))
  if (mGainMapMetadataCfgFile != nullptr) {
    uhdr_gainmap_metadata_t* metadata = uhdr_dec_get_gainmap_metadata(handle);
    if (!writeGainMapMetadataToFile(metadata)) {
      std::cerr << "failed to write gainmap metadata to file: " << mGainMapMetadataCfgFile
                << std::endl;
    }
  }

#ifdef PROFILE_ENABLE
  Profiler profileDecode;
  profileDecode.timerStart();
#endif
  RET_IF_ERR(uhdr_decode(handle))
#ifdef PROFILE_ENABLE
  profileDecode.timerStop();
  auto avgDecTime = profileDecode.elapsedTime() / 1000.f;
  printf("Average decode time for res %d x %d is %f ms \n", uhdr_dec_get_image_width(handle),
         uhdr_dec_get_image_height(handle), avgDecTime);
#endif

#undef RET_IF_ERR

  uhdr_raw_image_t* output = uhdr_get_decoded_image(handle);

  mDecodedUhdrRgbImage.fmt = output->fmt;
  mDecodedUhdrRgbImage.cg = output->cg;
  mDecodedUhdrRgbImage.ct = output->ct;
  mDecodedUhdrRgbImage.range = output->range;
  mDecodedUhdrRgbImage.w = output->w;
  mDecodedUhdrRgbImage.h = output->h;
  size_t bpp = (output->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) ? 8 : 4;
  mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED] = malloc(bpp * output->w * output->h);
  char* inData = static_cast<char*>(output->planes[UHDR_PLANE_PACKED]);
  char* outData = static_cast<char*>(mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED]);
  const size_t inStride = output->stride[UHDR_PLANE_PACKED] * bpp;
  const size_t outStride = output->w * bpp;
  mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] = output->w;
  const size_t length = output->w * bpp;
  for (unsigned i = 0; i < output->h; i++, inData += inStride, outData += outStride) {
    memcpy(outData, inData, length);
  }
  uhdr_release_decoder(handle);

  return mMode == 1 ? writeFile(mOutputFile, &mDecodedUhdrRgbImage) : true;
}

#define CLIP3(x, min, max) ((x) < (min)) ? (min) : ((x) > (max)) ? (max) : (x)
bool UltraHdrAppInput::convertP010ToRGBImage() {
  const float* coeffs = BT2020YUVtoRGBMatrix;
  if (mHdrCg == UHDR_CG_BT_709) {
    coeffs = BT709YUVtoRGBMatrix;
  } else if (mHdrCg == UHDR_CG_BT_2100) {
    coeffs = BT2020YUVtoRGBMatrix;
  } else if (mHdrCg == UHDR_CG_DISPLAY_P3) {
    coeffs = BT601YUVtoRGBMatrix;
  } else {
    std::cerr << "color matrix not present for gamut " << mHdrCg << " using BT2020Matrix"
              << std::endl;
  }

  size_t bpp = 4;
  mRawRgba1010102Image.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
  mRawRgba1010102Image.cg = mRawP010Image.cg;
  mRawRgba1010102Image.ct = mRawP010Image.ct;
  mRawRgba1010102Image.range = UHDR_CR_FULL_RANGE;
  mRawRgba1010102Image.w = mRawP010Image.w;
  mRawRgba1010102Image.h = mRawP010Image.h;
  mRawRgba1010102Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mRawP010Image.w * mRawP010Image.h);
  mRawRgba1010102Image.planes[UHDR_PLANE_U] = nullptr;
  mRawRgba1010102Image.planes[UHDR_PLANE_V] = nullptr;
  mRawRgba1010102Image.stride[UHDR_PLANE_PACKED] = mWidth;
  mRawRgba1010102Image.stride[UHDR_PLANE_U] = 0;
  mRawRgba1010102Image.stride[UHDR_PLANE_V] = 0;

  uint32_t* rgbData = static_cast<uint32_t*>(mRawRgba1010102Image.planes[UHDR_PLANE_PACKED]);
  uint16_t* y = static_cast<uint16_t*>(mRawP010Image.planes[UHDR_PLANE_Y]);
  uint16_t* u = static_cast<uint16_t*>(mRawP010Image.planes[UHDR_PLANE_UV]);
  uint16_t* v = u + 1;

  for (size_t i = 0; i < mRawP010Image.h; i++) {
    for (size_t j = 0; j < mRawP010Image.w; j++) {
      float y0 = float(y[mRawP010Image.stride[UHDR_PLANE_Y] * i + j] >> 6);
      float u0 = float(u[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6);
      float v0 = float(v[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6);

      if (mRawP010Image.range == UHDR_CR_FULL_RANGE) {
        y0 = CLIP3(y0, 0.0f, 1023.0f);
        u0 = CLIP3(u0, 0.0f, 1023.0f);
        v0 = CLIP3(v0, 0.0f, 1023.0f);

        y0 = y0 / 1023.0f;
        u0 = u0 / 1023.0f - 0.5f;
        v0 = v0 / 1023.0f - 0.5f;
      } else {
        y0 = CLIP3(y0, 64.0f, 940.0f);
        u0 = CLIP3(u0, 64.0f, 960.0f);
        v0 = CLIP3(v0, 64.0f, 960.0f);

        y0 = (y0 - 64.0f) / 876.0f;
        u0 = (u0 - 512.0f) / 896.0f;
        v0 = (v0 - 512.0f) / 896.0f;
      }

      float r = coeffs[0] * y0 + coeffs[1] * u0 + coeffs[2] * v0;
      float g = coeffs[3] * y0 + coeffs[4] * u0 + coeffs[5] * v0;
      float b = coeffs[6] * y0 + coeffs[7] * u0 + coeffs[8] * v0;

      r = CLIP3(r * 1023.0f + 0.5f, 0.0f, 1023.0f);
      g = CLIP3(g * 1023.0f + 0.5f, 0.0f, 1023.0f);
      b = CLIP3(b * 1023.0f + 0.5f, 0.0f, 1023.0f);

      int32_t r0 = int32_t(r);
      int32_t g0 = int32_t(g);
      int32_t b0 = int32_t(b);
      *rgbData = (0x3ff & r0) | ((0x3ff & g0) << 10) | ((0x3ff & b0) << 20) |
                 (0x3 << 30);  // Set alpha to 1.0

      rgbData++;
    }
  }
#ifdef DUMP_DEBUG_DATA
  writeFile("inRgba1010102.raw", &mRawRgba1010102Image);
#endif
  return true;
}

bool UltraHdrAppInput::convertYuv420ToRGBImage() {
  size_t bpp = 4;
  mRawRgba8888Image.fmt = UHDR_IMG_FMT_32bppRGBA8888;
  mRawRgba8888Image.cg = mRawYuv420Image.cg;
  mRawRgba8888Image.ct = mRawYuv420Image.ct;
  mRawRgba8888Image.range = UHDR_CR_FULL_RANGE;
  mRawRgba8888Image.w = mRawYuv420Image.w;
  mRawRgba8888Image.h = mRawYuv420Image.h;
  mRawRgba8888Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mRawYuv420Image.w * mRawYuv420Image.h);
  mRawRgba8888Image.planes[UHDR_PLANE_U] = nullptr;
  mRawRgba8888Image.planes[UHDR_PLANE_V] = nullptr;
  mRawRgba8888Image.stride[UHDR_PLANE_PACKED] = mWidth;
  mRawRgba8888Image.stride[UHDR_PLANE_U] = 0;
  mRawRgba8888Image.stride[UHDR_PLANE_V] = 0;

  uint32_t* rgbData = static_cast<uint32_t*>(mRawRgba8888Image.planes[UHDR_PLANE_PACKED]);
  uint8_t* y = static_cast<uint8_t*>(mRawYuv420Image.planes[UHDR_PLANE_Y]);
  uint8_t* u = static_cast<uint8_t*>(mRawYuv420Image.planes[UHDR_PLANE_U]);
  uint8_t* v = static_cast<uint8_t*>(mRawYuv420Image.planes[UHDR_PLANE_V]);

  const float* coeffs = BT601YUVtoRGBMatrix;
  if (mSdrCg == UHDR_CG_BT_709) {
    coeffs = BT709YUVtoRGBMatrix;
  } else if (mSdrCg == UHDR_CG_BT_2100) {
    coeffs = BT2020YUVtoRGBMatrix;
  } else if (mSdrCg == UHDR_CG_DISPLAY_P3) {
    coeffs = BT601YUVtoRGBMatrix;
  } else {
    std::cerr << "color matrix not present for gamut " << mSdrCg << " using BT601Matrix"
              << std::endl;
  }
  for (size_t i = 0; i < mRawYuv420Image.h; i++) {
    for (size_t j = 0; j < mRawYuv420Image.w; j++) {
      float y0 = float(y[mRawYuv420Image.stride[UHDR_PLANE_Y] * i + j]);
      float u0 = float(u[mRawYuv420Image.stride[UHDR_PLANE_U] * (i / 2) + (j / 2)] - 128);
      float v0 = float(v[mRawYuv420Image.stride[UHDR_PLANE_V] * (i / 2) + (j / 2)] - 128);

      y0 /= 255.0f;
      u0 /= 255.0f;
      v0 /= 255.0f;

      float r = coeffs[0] * y0 + coeffs[1] * u0 + coeffs[2] * v0;
      float g = coeffs[3] * y0 + coeffs[4] * u0 + coeffs[5] * v0;
      float b = coeffs[6] * y0 + coeffs[7] * u0 + coeffs[8] * v0;

      r = r * 255.0f + 0.5f;
      g = g * 255.0f + 0.5f;
      b = b * 255.0f + 0.5f;

      r = CLIP3(r, 0.0f, 255.0f);
      g = CLIP3(g, 0.0f, 255.0f);
      b = CLIP3(b, 0.0f, 255.0f);

      int32_t r0 = int32_t(r);
      int32_t g0 = int32_t(g);
      int32_t b0 = int32_t(b);
      *rgbData = r0 | (g0 << 8) | (b0 << 16) | (255 << 24);  // Set alpha to 1.0

      rgbData++;
    }
  }
#ifdef DUMP_DEBUG_DATA
  writeFile("inRgba8888.raw", &mRawRgba8888Image);
#endif
  return true;
}

bool UltraHdrAppInput::convertRgba8888ToYUV444Image() {
  mDecodedUhdrYuv444Image.fmt = static_cast<uhdr_img_fmt_t>(UHDR_IMG_FMT_24bppYCbCr444);
  mDecodedUhdrYuv444Image.cg = mDecodedUhdrRgbImage.cg;
  mDecodedUhdrYuv444Image.ct = mDecodedUhdrRgbImage.ct;
  mDecodedUhdrYuv444Image.range = UHDR_CR_FULL_RANGE;
  mDecodedUhdrYuv444Image.w = mDecodedUhdrRgbImage.w;
  mDecodedUhdrYuv444Image.h = mDecodedUhdrRgbImage.h;
  mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y] =
      malloc((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U] =
      malloc((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V] =
      malloc((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] = mWidth;
  mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] = mWidth;
  mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] = mWidth;

  uint32_t* rgbData = static_cast<uint32_t*>(mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED]);

  uint8_t* yData = static_cast<uint8_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y]);
  uint8_t* uData = static_cast<uint8_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U]);
  uint8_t* vData = static_cast<uint8_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V]);

  const float* coeffs = BT601RGBtoYUVMatrix;
  if (mDecodedUhdrRgbImage.cg == UHDR_CG_BT_709) {
    coeffs = BT709RGBtoYUVMatrix;
  } else if (mDecodedUhdrRgbImage.cg == UHDR_CG_BT_2100) {
    coeffs = BT2020RGBtoYUVMatrix;
  } else if (mDecodedUhdrRgbImage.cg == UHDR_CG_DISPLAY_P3) {
    coeffs = BT601RGBtoYUVMatrix;
  } else {
    std::cerr << "color matrix not present for gamut " << mDecodedUhdrRgbImage.cg
              << " using BT601Matrix" << std::endl;
  }

  for (size_t i = 0; i < mDecodedUhdrRgbImage.h; i++) {
    for (size_t j = 0; j < mDecodedUhdrRgbImage.w; j++) {
      float r0 = float(rgbData[mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] * i + j] & 0xff);
      float g0 =
          float((rgbData[mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] * i + j] >> 8) & 0xff);
      float b0 =
          float((rgbData[mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] * i + j] >> 16) & 0xff);

      r0 /= 255.0f;
      g0 /= 255.0f;
      b0 /= 255.0f;

      float y = coeffs[0] * r0 + coeffs[1] * g0 + coeffs[2] * b0;
      float u = coeffs[3] * r0 + coeffs[4] * g0 + coeffs[5] * b0;
      float v = coeffs[6] * r0 + coeffs[7] * g0 + coeffs[8] * b0;

      y = y * 255.0f + 0.5f;
      u = u * 255.0f + 0.5f + 128.0f;
      v = v * 255.0f + 0.5f + 128.0f;

      y = CLIP3(y, 0.0f, 255.0f);
      u = CLIP3(u, 0.0f, 255.0f);
      v = CLIP3(v, 0.0f, 255.0f);

      yData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] * i + j] = uint8_t(y);
      uData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j] = uint8_t(u);
      vData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j] = uint8_t(v);
    }
  }
#ifdef DUMP_DEBUG_DATA
  writeFile("outyuv444.yuv", &mDecodedUhdrYuv444Image);
#endif
  return true;
}

bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
  const float* coeffs = BT2020RGBtoYUVMatrix;
  if (mDecodedUhdrRgbImage.cg == UHDR_CG_BT_709) {
    coeffs = BT709RGBtoYUVMatrix;
  } else if (mDecodedUhdrRgbImage.cg == UHDR_CG_BT_2100) {
    coeffs = BT2020RGBtoYUVMatrix;
  } else if (mDecodedUhdrRgbImage.cg == UHDR_CG_DISPLAY_P3) {
    coeffs = BT601RGBtoYUVMatrix;
  } else {
    std::cerr << "color matrix not present for gamut " << mDecodedUhdrRgbImage.cg
              << " using BT2020Matrix" << std::endl;
  }

  size_t bpp = 2;
  mDecodedUhdrYuv444Image.fmt = static_cast<uhdr_img_fmt_t>(UHDR_IMG_FMT_48bppYCbCr444);
  mDecodedUhdrYuv444Image.cg = mDecodedUhdrRgbImage.cg;
  mDecodedUhdrYuv444Image.ct = mDecodedUhdrRgbImage.ct;
  mDecodedUhdrYuv444Image.range = mRawP010Image.range;
  mDecodedUhdrYuv444Image.w = mDecodedUhdrRgbImage.w;
  mDecodedUhdrYuv444Image.h = mDecodedUhdrRgbImage.h;
  mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y] =
      malloc(bpp * mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U] =
      malloc(bpp * mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V] =
      malloc(bpp * mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] = mWidth;
  mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] = mWidth;
  mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] = mWidth;

  uint32_t* rgbData = static_cast<uint32_t*>(mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED]);

  uint16_t* yData = static_cast<uint16_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y]);
  uint16_t* uData = static_cast<uint16_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U]);
  uint16_t* vData = static_cast<uint16_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V]);

  for (size_t i = 0; i < mDecodedUhdrRgbImage.h; i++) {
    for (size_t j = 0; j < mDecodedUhdrRgbImage.w; j++) {
      float r0 = float(rgbData[mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] * i + j] & 0x3ff);
      float g0 =
          float((rgbData[mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] * i + j] >> 10) & 0x3ff);
      float b0 =
          float((rgbData[mDecodedUhdrRgbImage.stride[UHDR_PLANE_PACKED] * i + j] >> 20) & 0x3ff);

      r0 /= 1023.0f;
      g0 /= 1023.0f;
      b0 /= 1023.0f;

      float y = coeffs[0] * r0 + coeffs[1] * g0 + coeffs[2] * b0;
      float u = coeffs[3] * r0 + coeffs[4] * g0 + coeffs[5] * b0;
      float v = coeffs[6] * r0 + coeffs[7] * g0 + coeffs[8] * b0;

      if (mRawP010Image.range == UHDR_CR_FULL_RANGE) {
        y = y * 1023.0f + 0.5f;
        u = (u + 0.5f) * 1023.0f + 0.5f;
        v = (v + 0.5f) * 1023.0f + 0.5f;

        y = CLIP3(y, 0.0f, 1023.0f);
        u = CLIP3(u, 0.0f, 1023.0f);
        v = CLIP3(v, 0.0f, 1023.0f);
      } else {
        y = (y * 876.0f) + 64.0f + 0.5f;
        u = (u * 896.0f) + 512.0f + 0.5f;
        v = (v * 896.0f) + 512.0f + 0.5f;

        y = CLIP3(y, 64.0f, 940.0f);
        u = CLIP3(u, 64.0f, 960.0f);
        v = CLIP3(v, 64.0f, 960.0f);
      }

      yData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] * i + j] = uint16_t(y);
      uData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j] = uint16_t(u);
      vData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j] = uint16_t(v);
    }
  }
#ifdef DUMP_DEBUG_DATA
  writeFile("outyuv444.yuv", &mDecodedUhdrYuv444Image);
#endif
  return true;
}

void UltraHdrAppInput::computeRGBHdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA1010102) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }
  uint32_t* rgbDataSrc = static_cast<uint32_t*>(mRawRgba1010102Image.planes[UHDR_PLANE_PACKED]);
  uint32_t* rgbDataDst = static_cast<uint32_t*>(mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED]);
  if (rgbDataSrc == nullptr || rgbDataDst == nullptr) {
    std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
    return;
  }
  if (mRawRgba1010102Image.ct != mDecodedUhdrRgbImage.ct) {
    std::cout << "input color transfer and output color transfer are not identical, rgb psnr "
                 "results may be unreliable"
              << std::endl;
  }
  if (mRawRgba1010102Image.cg != mDecodedUhdrRgbImage.cg) {
    std::cout << "input color gamut and output color gamut are not identical, rgb psnr results "
                 "may be unreliable"
              << std::endl;
  }
  uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
  for (size_t i = 0; i < (size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h; i++) {
    int rSrc = *rgbDataSrc & 0x3ff;
    int rDst = *rgbDataDst & 0x3ff;
    rSqError += (rSrc - rDst) * (rSrc - rDst);

    int gSrc = (*rgbDataSrc >> 10) & 0x3ff;
    int gDst = (*rgbDataDst >> 10) & 0x3ff;
    gSqError += (gSrc - gDst) * (gSrc - gDst);

    int bSrc = (*rgbDataSrc >> 20) & 0x3ff;
    int bDst = (*rgbDataDst >> 20) & 0x3ff;
    bSqError += (bSrc - bDst) * (bSrc - bDst);

    rgbDataSrc++;
    rgbDataDst++;
  }
  double meanSquareError =
      (double)rSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError = (double)gSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError = (double)bSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  std::cout << "psnr rgb: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
}

void UltraHdrAppInput::computeRGBSdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA8888) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }
  uint32_t* rgbDataSrc = static_cast<uint32_t*>(mRawRgba8888Image.planes[UHDR_PLANE_PACKED]);
  uint32_t* rgbDataDst = static_cast<uint32_t*>(mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED]);
  if (rgbDataSrc == nullptr || rgbDataDst == nullptr) {
    std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
    return;
  }

  uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
  for (size_t i = 0; i < (size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h; i++) {
    int rSrc = *rgbDataSrc & 0xff;
    int rDst = *rgbDataDst & 0xff;
    rSqError += (rSrc - rDst) * (rSrc - rDst);

    int gSrc = (*rgbDataSrc >> 8) & 0xff;
    int gDst = (*rgbDataDst >> 8) & 0xff;
    gSqError += (gSrc - gDst) * (gSrc - gDst);

    int bSrc = (*rgbDataSrc >> 16) & 0xff;
    int bDst = (*rgbDataDst >> 16) & 0xff;
    bSqError += (bSrc - bDst) * (bSrc - bDst);

    rgbDataSrc++;
    rgbDataDst++;
  }
  double meanSquareError =
      (double)rSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError = (double)gSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError = (double)bSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
  mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  std::cout << "psnr rgb: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
}

void UltraHdrAppInput::computeYUVHdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA1010102) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }
  uint16_t* yDataSrc = static_cast<uint16_t*>(mRawP010Image.planes[UHDR_PLANE_Y]);
  uint16_t* uDataSrc = static_cast<uint16_t*>(mRawP010Image.planes[UHDR_PLANE_UV]);
  uint16_t* vDataSrc = uDataSrc + 1;

  uint16_t* yDataDst = static_cast<uint16_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y]);
  uint16_t* uDataDst = static_cast<uint16_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U]);
  uint16_t* vDataDst = static_cast<uint16_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V]);
  if (yDataSrc == nullptr || uDataSrc == nullptr || yDataDst == nullptr || uDataDst == nullptr ||
      vDataDst == nullptr) {
    std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
    return;
  }
  if (mRawP010Image.ct != mDecodedUhdrYuv444Image.ct) {
    std::cout << "input color transfer and output color transfer are not identical, yuv psnr "
                 "results may be unreliable"
              << std::endl;
  }
  if (mRawP010Image.cg != mDecodedUhdrYuv444Image.cg) {
    std::cout << "input color gamut and output color gamut are not identical, yuv psnr results "
                 "may be unreliable"
              << std::endl;
  }
  if (mRawP010Image.range != mDecodedUhdrYuv444Image.range) {
    std::cout << "input range and output range are not identical, yuv psnr results "
                 "may be unreliable"
              << std::endl;
  }

  uint64_t ySqError = 0, uSqError = 0, vSqError = 0;
  for (size_t i = 0; i < mDecodedUhdrYuv444Image.h; i++) {
    for (size_t j = 0; j < mDecodedUhdrYuv444Image.w; j++) {
      int ySrc = (yDataSrc[mRawP010Image.stride[UHDR_PLANE_Y] * i + j] >> 6) & 0x3ff;
      if (mRawP010Image.range == UHDR_CR_LIMITED_RANGE) ySrc = CLIP3(ySrc, 64, 940);
      int yDst = yDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] * i + j] & 0x3ff;
      ySqError += (ySrc - yDst) * (ySrc - yDst);

      if (i % 2 == 0 && j % 2 == 0) {
        int uSrc =
            (uDataSrc[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
        if (mRawP010Image.range == UHDR_CR_LIMITED_RANGE) uSrc = CLIP3(uSrc, 64, 960);
        int uDst = uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j] & 0x3ff;
        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j + 1] & 0x3ff;
        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j] & 0x3ff;
        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j + 1] & 0x3ff;
        uDst = (uDst + 2) >> 2;
        uSqError += (uSrc - uDst) * (uSrc - uDst);

        int vSrc =
            (vDataSrc[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
        if (mRawP010Image.range == UHDR_CR_LIMITED_RANGE) vSrc = CLIP3(vSrc, 64, 960);
        int vDst = vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j] & 0x3ff;
        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j + 1] & 0x3ff;
        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j] & 0x3ff;
        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j + 1] & 0x3ff;
        vDst = (vDst + 2) >> 2;
        vSqError += (vSrc - vDst) * (vSrc - vDst);
      }
    }
  }

  double meanSquareError =
      (double)ySqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError =
      (double)uSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
  mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError =
      (double)vSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
  mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  std::cout << "psnr yuv: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
}

void UltraHdrAppInput::computeYUVSdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA8888) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }

  uint8_t* yDataSrc = static_cast<uint8_t*>(mRawYuv420Image.planes[UHDR_PLANE_Y]);
  uint8_t* uDataSrc = static_cast<uint8_t*>(mRawYuv420Image.planes[UHDR_PLANE_U]);
  uint8_t* vDataSrc = static_cast<uint8_t*>(mRawYuv420Image.planes[UHDR_PLANE_V]);

  uint8_t* yDataDst = static_cast<uint8_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y]);
  uint8_t* uDataDst = static_cast<uint8_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U]);
  uint8_t* vDataDst = static_cast<uint8_t*>(mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V]);

  uint64_t ySqError = 0, uSqError = 0, vSqError = 0;
  for (size_t i = 0; i < mDecodedUhdrYuv444Image.h; i++) {
    for (size_t j = 0; j < mDecodedUhdrYuv444Image.w; j++) {
      int ySrc = yDataSrc[mRawYuv420Image.stride[UHDR_PLANE_Y] * i + j];
      int yDst = yDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] * i + j];
      ySqError += (ySrc - yDst) * (ySrc - yDst);

      if (i % 2 == 0 && j % 2 == 0) {
        int uSrc = uDataSrc[mRawYuv420Image.stride[UHDR_PLANE_U] * (i / 2) + j / 2];
        int uDst = uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j];
        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j + 1];
        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j];
        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j + 1];
        uDst = (uDst + 2) >> 2;
        uSqError += (uSrc - uDst) * (uSrc - uDst);

        int vSrc = vDataSrc[mRawYuv420Image.stride[UHDR_PLANE_V] * (i / 2) + j / 2];
        int vDst = vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j];
        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j + 1];
        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j];
        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j + 1];
        vDst = (vDst + 2) >> 2;
        vSqError += (vSrc - vDst) * (vSrc - vDst);
      }
    }
  }
  double meanSquareError =
      (double)ySqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError =
      (double)uSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
  mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError =
      (double)vSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
  mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  std::cout << "psnr yuv: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
}

static void usage(const char* name) {
  fprintf(stderr, "\n## ultra hdr demo application. lib version: v%s \nUsage : %s \n",
          UHDR_LIB_VERSION_STR, name);
  fprintf(stderr, "    -m    mode of operation. [0:encode, 1:decode] \n");
  fprintf(stderr, "\n## encoder options : \n");
  fprintf(stderr,
          "    -p    raw hdr intent input resource (10-bit), required for encoding scenarios 0, 1, "
          "2, 3. \n");
  fprintf(
      stderr,
      "    -y    raw sdr intent input resource (8-bit), required for encoding scenarios 1, 2. \n");
  fprintf(stderr,
          "    -a    raw hdr intent color format, optional. [0:p010, 4: rgbahalffloat, "
          "5:rgba1010102 (default)] \n");
  fprintf(stderr,
          "    -b    raw sdr intent color format, optional. [1:yuv420, 3:rgba8888 (default)] \n");
  fprintf(stderr,
          "    -i    compressed sdr intent input resource (jpeg), required for encoding scenarios "
          "2, 3, 4. \n");
  fprintf(
      stderr,
      "    -g    compressed gainmap input resource (jpeg), required for encoding scenario 4. \n");
  fprintf(stderr, "    -w    input file width, required for encoding scenarios 0, 1, 2, 3. \n");
  fprintf(stderr, "    -h    input file height, required for encoding scenarios 0, 1, 2, 3. \n");
  fprintf(stderr,
          "    -C    hdr intent color gamut, optional. [0:bt709, 1:p3 (default), 2:bt2100] \n");
  fprintf(stderr,
          "    -c    sdr intent color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100] \n");
  fprintf(stderr,
          "    -t    hdr intent color transfer, optional. [0:linear, 1:hlg (default), 2:pq] \n");
  fprintf(stderr,
          "          It should be noted that not all combinations of input color format and input "
          "color transfer are supported. \n"
          "          srgb color transfer shall be paired with rgba8888 or yuv420 only. \n"
          "          hlg, pq shall be paired with rgba1010102 or p010. \n"
          "          linear shall be paired with rgbahalffloat. \n");
  fprintf(stderr,
          "    -q    quality factor to be used while encoding sdr intent, optional. [0-100], 95 : "
          "default.\n");
  fprintf(stderr, "    -e    compute psnr, optional. [0:no (default), 1:yes] \n");
  fprintf(stderr,
          "    -R    color range of hdr intent, optional. [0:narrow-range (default), "
          "1:full-range]. \n");
  fprintf(stderr,
          "    -s    gainmap image downsample factor, optional. [integer values in range [1 - 128] "
          "(1 : default)]. \n");
  fprintf(stderr,
          "    -Q    quality factor to be used while encoding gain map image, optional. [0-100], "
          "95 : default. \n");
  fprintf(stderr,
          "    -G    gamma correction to be applied on the gainmap image, optional. [any positive "
          "real number (1.0 : default)].\n");
  fprintf(stderr,
          "    -M    select multi channel gain map, optional. [0:disable, 1:enable (default)]. \n");
  fprintf(
      stderr,
      "    -D    select encoding preset, optional. [0:real time, 1:best quality (default)]. \n");
  fprintf(stderr,
          "    -k    min content boost recommendation, must be in linear scale, optional. [any "
          "positive real number] \n");
  fprintf(stderr,
          "    -K    max content boost recommendation, must be in linear scale, optional.[any "
          "positive real number] \n");
  fprintf(stderr,
          "    -L    set target display peak brightness in nits, optional. \n"
          "          For HLG content, this defaults to 1000 nits. \n"
          "          For PQ content, this defaults to 10000 nits. \n"
          "          any real number in range [203, 10000]. \n");
  fprintf(stderr, "    -x    binary input resource containing exif data to insert, optional. \n");
  fprintf(stderr, "\n## decoder options : \n");
  fprintf(stderr, "    -j    ultra hdr compressed input resource, required. \n");
  fprintf(
      stderr,
      "    -o    output transfer function, optional. [0:linear, 1:hlg (default), 2:pq, 3:srgb] \n");
  fprintf(
      stderr,
      "    -O    output color format, optional. [3:rgba8888, 4:rgbahalffloat, 5:rgba1010102 "
      "(default)] \n"
      "          It should be noted that not all combinations of output color format and output \n"
      "          transfer function are supported. \n"
      "          srgb output color transfer shall be paired with rgba8888 only. \n"
      "          hlg, pq shall be paired with rgba1010102. \n"
      "          linear shall be paired with rgbahalffloat. \n");
  fprintf(stderr,
          "    -u    enable gles acceleration, optional. [0:disable (default), 1:enable]. \n");
  fprintf(stderr, "\n## common options : \n");
  fprintf(stderr,
          "    -z    output filename, optional. \n"
          "          in encoding mode, default output filename 'out.jpeg'. \n"
          "          in decoding mode, default output filename 'outrgb.raw'. \n");
  fprintf(
      stderr,
      "    -f    gainmap metadata config file. \n"
      "          in encoding mode, resource from which gainmap metadata is read, required for "
      "encoding scenario 4. \n"
      "          in decoding mode, resource to which gainmap metadata is written, optional. \n");
  fprintf(stderr, "\n## examples of usage :\n");
  fprintf(stderr, "\n## encode scenario 0 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -a 0\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_rgba1010102.raw -w 1920 -h 1080 -q 97 -a 5\n");
  fprintf(
      stderr,
      "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -C 1 -t 2 -a 0\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_rgba1010102.raw -w 1920 -h 1080 -q 97 -C 1 "
          "-t 2 -a 5\n");
  fprintf(stderr, "\n## encode scenario 1 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 "
          "-h 1080 -q 97 -a 0 -b 1\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_rgba1010102.raw "
          "-y cosmat_1920x1080_rgba8888.raw -w 1920 -h 1080 -q 97 -a 5 -b 3\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 "
          "-h 1080 -q 97 -C 2 -c 1 -t 1 -a 0 -b 1\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_rgba1010102.raw "
          "-y cosmat_1920x1080_rgba8888.raw -w 1920 -h 1080 -q 97 -C 2 -c 1 -t 1 -a 5 -b 3\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 "
          "-h 1080 -q 97 -C 2 -c 1 -t 1 -e 1 -a 0 -b 1\n");
  fprintf(stderr, "\n## encode scenario 2 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -i "
          "cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -e 1 -a 0 -b 1\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_420.yuv "
          "-i cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -e 1 -a 5 -b 1\n");
  fprintf(stderr, "\n## encode scenario 3 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -i cosmat_1920x1080_420_8bit.jpg -w "
          "1920 -h 1080 -t 1 -o 1 -O 5 -e 1 -a 0\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_rgba1010102.raw "
          "-i cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 1 -O 5 -e 1 -a 5\n");
  fprintf(stderr, "\n## encode scenario 4 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -i cosmat_1920x1080_420_8bit.jpg -g cosmat_1920x1080_420_8bit.jpg "
          "-f metadata.cfg\n");
  fprintf(stderr, "\n## encode at high quality :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p hdr_intent.raw -y sdr_intent.raw -w 640 -h 480 -c <select> -C "
          "<select> -t <select> -s 1 -M 1 -Q 98 -q 98 -D 1\n");

  fprintf(stderr, "\n## decode api :\n");
  fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg \n");
  fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg -o 3 -O 3\n");
  fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg -o 1 -O 5\n");
  fprintf(stderr, "\n");
}

int main(int argc, char* argv[]) {
  char opt_string[] = "p:y:i:g:f:w:h:C:c:t:q:o:O:m:j:e:a:b:z:R:s:M:Q:G:x:u:D:k:K:L:";
  char *hdr_intent_raw_file = nullptr, *sdr_intent_raw_file = nullptr, *uhdr_file = nullptr,
       *sdr_intent_compressed_file = nullptr, *gainmap_compressed_file = nullptr,
       *gainmap_metadata_cfg_file = nullptr, *output_file = nullptr, *exif_file = nullptr;
  int width = 0, height = 0;
  uhdr_color_gamut_t hdr_cg = UHDR_CG_DISPLAY_P3;
  uhdr_color_gamut_t sdr_cg = UHDR_CG_BT_709;
  uhdr_img_fmt_t hdr_cf = UHDR_IMG_FMT_32bppRGBA1010102;
  uhdr_img_fmt_t sdr_cf = UHDR_IMG_FMT_32bppRGBA8888;
  uhdr_color_transfer_t hdr_tf = UHDR_CT_HLG;
  int quality = 95;
  uhdr_color_transfer_t out_tf = UHDR_CT_HLG;
  uhdr_img_fmt_t out_cf = UHDR_IMG_FMT_32bppRGBA1010102;
  int mode = -1;
  int gainmap_scale_factor = 1;
  bool use_multi_channel_gainmap = true;
  bool use_full_range_color_hdr = false;
  int gainmap_compression_quality = 95;
  int compute_psnr = 0;
  float gamma = 1.0f;
  bool enable_gles = false;
  uhdr_enc_preset_t enc_preset = UHDR_USAGE_BEST_QUALITY;
  float min_content_boost = FLT_MIN;
  float max_content_boost = FLT_MAX;
  float target_disp_peak_brightness = -1.0f;
  int ch;
  while ((ch = getopt_s(argc, argv, opt_string)) != -1) {
    switch (ch) {
      case 'a':
        hdr_cf = static_cast<uhdr_img_fmt_t>(atoi(optarg_s));
        break;
      case 'b':
        sdr_cf = static_cast<uhdr_img_fmt_t>(atoi(optarg_s));
        break;
      case 'p':
        hdr_intent_raw_file = optarg_s;
        break;
      case 'y':
        sdr_intent_raw_file = optarg_s;
        break;
      case 'i':
        sdr_intent_compressed_file = optarg_s;
        break;
      case 'g':
        gainmap_compressed_file = optarg_s;
        break;
      case 'f':
        gainmap_metadata_cfg_file = optarg_s;
        break;
      case 'w':
        width = atoi(optarg_s);
        break;
      case 'h':
        height = atoi(optarg_s);
        break;
      case 'C':
        hdr_cg = static_cast<uhdr_color_gamut_t>(atoi(optarg_s));
        break;
      case 'c':
        sdr_cg = static_cast<uhdr_color_gamut_t>(atoi(optarg_s));
        break;
      case 't':
        hdr_tf = static_cast<uhdr_color_transfer_t>(atoi(optarg_s));
        break;
      case 'q':
        quality = atoi(optarg_s);
        break;
      case 'O':
        out_cf = static_cast<uhdr_img_fmt_t>(atoi(optarg_s));
        break;
      case 'o':
        out_tf = static_cast<uhdr_color_transfer_t>(atoi(optarg_s));
        break;
      case 'm':
        mode = atoi(optarg_s);
        break;
      case 'R':
        use_full_range_color_hdr = atoi(optarg_s) == 1 ? true : false;
        break;
      // TODO
      /*case 'r':
        use_full_range_color_sdr = atoi(optarg_s) == 1 ? true : false;
        break;*/
      case 's':
        gainmap_scale_factor = atoi(optarg_s);
        break;
      case 'M':
        use_multi_channel_gainmap = atoi(optarg_s) == 1 ? true : false;
        break;
      case 'Q':
        gainmap_compression_quality = atoi(optarg_s);
        break;
      case 'G':
        gamma = (float)atof(optarg_s);
        break;
      case 'j':
        uhdr_file = optarg_s;
        break;
      case 'e':
        compute_psnr = atoi(optarg_s);
        break;
      case 'z':
        output_file = optarg_s;
        break;
      case 'x':
        exif_file = optarg_s;
        break;
      case 'u':
        enable_gles = atoi(optarg_s) == 1 ? true : false;
        break;
      case 'D':
        enc_preset = static_cast<uhdr_enc_preset_t>(atoi(optarg_s));
        break;
      case 'k':
        min_content_boost = (float)atof(optarg_s);
        break;
      case 'K':
        max_content_boost = (float)atof(optarg_s);
        break;
      case 'L':
        target_disp_peak_brightness = (float)atof(optarg_s);
        break;
      default:
        usage(argv[0]);
        return -1;
    }
  }
  if (mode == 0) {
    if (width <= 0 && gainmap_metadata_cfg_file == nullptr) {
      std::cerr << "did not receive valid image width for encoding. width :  " << width
                << std::endl;
      return -1;
    }
    if (height <= 0 && gainmap_metadata_cfg_file == nullptr) {
      std::cerr << "did not receive valid image height for encoding. height :  " << height
                << std::endl;
      return -1;
    }
    if (hdr_intent_raw_file == nullptr &&
        (sdr_intent_compressed_file == nullptr || gainmap_compressed_file == nullptr ||
         gainmap_metadata_cfg_file == nullptr)) {
      std::cerr << "did not receive raw resources for encoding." << std::endl;
      return -1;
    }
    UltraHdrAppInput appInput(
        hdr_intent_raw_file, sdr_intent_raw_file, sdr_intent_compressed_file,
        gainmap_compressed_file, gainmap_metadata_cfg_file, exif_file,
        output_file ? output_file : "out.jpeg", width, height, hdr_cf, sdr_cf, hdr_cg, sdr_cg,
        hdr_tf, quality, out_tf, out_cf, use_full_range_color_hdr, gainmap_scale_factor,
        gainmap_compression_quality, use_multi_channel_gainmap, gamma, enable_gles, enc_preset,
        min_content_boost, max_content_boost, target_disp_peak_brightness);
    if (!appInput.encode()) return -1;
    if (compute_psnr == 1) {
      if (!appInput.decode()) return -1;
      if (out_cf == UHDR_IMG_FMT_32bppRGBA8888 && sdr_intent_raw_file != nullptr) {
        if (sdr_cf == UHDR_IMG_FMT_12bppYCbCr420) {
          appInput.convertYuv420ToRGBImage();
        }
        appInput.computeRGBSdrPSNR();
        if (sdr_cf == UHDR_IMG_FMT_12bppYCbCr420) {
          appInput.convertRgba8888ToYUV444Image();
          appInput.computeYUVSdrPSNR();
        }
      } else if (out_cf == UHDR_IMG_FMT_32bppRGBA1010102 && hdr_intent_raw_file != nullptr &&
                 hdr_cf != UHDR_IMG_FMT_64bppRGBAHalfFloat) {
        if (hdr_cf == UHDR_IMG_FMT_24bppYCbCrP010) {
          appInput.convertP010ToRGBImage();
        }
        appInput.computeRGBHdrPSNR();
        if (hdr_cf == UHDR_IMG_FMT_24bppYCbCrP010) {
          appInput.convertRgba1010102ToYUV444Image();
          appInput.computeYUVHdrPSNR();
        }
      } else {
        std::cerr << "failed to compute psnr " << std::endl;
      }
    }
  } else if (mode == 1) {
    if (uhdr_file == nullptr) {
      std::cerr << "did not receive resources for decoding " << std::endl;
      return -1;
    }
    UltraHdrAppInput appInput(gainmap_metadata_cfg_file, uhdr_file,
                              output_file ? output_file : "outrgb.raw", out_tf, out_cf,
                              enable_gles);
    if (!appInput.decode()) return -1;
  } else {
    if (argc > 1) std::cerr << "did not receive valid mode of operation " << mode << std::endl;
    usage(argv[0]);
    return -1;
  }

  return 0;
}
