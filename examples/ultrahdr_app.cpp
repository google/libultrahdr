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
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>

#include "ultrahdr_api.h"

const float BT601YUVtoRGBMatrix[9] = {
    1, 0, 1.402, 1, (-0.202008 / 0.587), (-0.419198 / 0.587), 1.0, 1.772, 0.0};
const float BT709YUVtoRGBMatrix[9] = {
    1, 0, 1.5748, 1, (-0.13397432 / 0.7152), (-0.33480248 / 0.7152), 1.0, 1.8556, 0.0};
const float BT2020YUVtoRGBMatrix[9] = {
    1, 0, 1.4746, 1, (-0.11156702 / 0.6780), (-0.38737742 / 0.6780), 1, 1.8814, 0};

const float BT601RGBtoYUVMatrix[9] = {
    0.299,           0.587, 0.114, (-0.299 / 1.772), (-0.587 / 1.772), 0.5, 0.5, (-0.587 / 1.402),
    (-0.114 / 1.402)};
const float BT709RGBtoYUVMatrix[9] = {0.2126,
                                      0.7152,
                                      0.0722,
                                      (-0.2126 / 1.8556),
                                      (-0.7152 / 1.8556),
                                      0.5,
                                      0.5,
                                      (-0.7152 / 1.5748),
                                      (-0.0722 / 1.5748)};
const float BT2020RGBtoYUVMatrix[9] = {0.2627,
                                       0.6780,
                                       0.0593,
                                       (-0.2627 / 1.8814),
                                       (-0.6780 / 1.8814),
                                       0.5,
                                       0.5,
                                       (-0.6780 / 1.4746),
                                       (-0.0593 / 1.4746)};

// remove these once introduced in ultrahdr_api.h
const int UHDR_IMG_FMT_24bppYCbCr444 = 100;
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

  int64_t elapsedTime() {
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

static bool loadFile(const char* filename, void*& result, int length) {
  std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int size = ifd.tellg();
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
    ifd.read(static_cast<char*>(result), length);
    return true;
  }
  std::cerr << "unable to open file : " << filename << std::endl;
  return false;
}

static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
  std::ifstream ifd(filename, std::ios::binary);
  if (ifd.good()) {
    if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      const int bpp = 2;
      ifd.read(static_cast<char*>(handle->planes[0]), handle->w * handle->h * bpp);
      ifd.read(static_cast<char*>(handle->planes[1]), (handle->w / 2) * (handle->h / 2) * bpp * 2);
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      ifd.read(static_cast<char*>(handle->planes[0]), handle->w * handle->h);
      ifd.read(static_cast<char*>(handle->planes[1]), (handle->w / 2) * (handle->h / 2));
      ifd.read(static_cast<char*>(handle->planes[2]), (handle->w / 2) * (handle->h / 2));
      return true;
    }
    return false;
  }
  std::cerr << "unable to open file : " << filename << std::endl;
  return false;
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

static bool writeFile(const char* filename, uhdr_raw_image_t* img) {
  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    if (img->fmt == UHDR_IMG_FMT_32bppRGBA8888 || img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ||
        img->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
      char* data = static_cast<char*>(img->planes[0]);
      int bpp = img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
      const size_t stride = img->stride[0] * bpp;
      const size_t length = img->w * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      return true;
    } else if ((int)img->fmt == UHDR_IMG_FMT_24bppYCbCr444 ||
               (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444) {
      char* data = static_cast<char*>(img->planes[0]);
      int bpp = (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444 ? 2 : 1;
      size_t stride = img->stride[0] * bpp;
      size_t length = img->w * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      data = static_cast<char*>(img->planes[1]);
      stride = img->stride[1] * bpp;
      for (unsigned i = 0; i < img->h; i++, data += stride) {
        ofd.write(data, length);
      }
      data = static_cast<char*>(img->planes[2]);
      stride = img->stride[2] * bpp;
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
  UltraHdrAppInput(const char* p010File, const char* yuv420File, const char* yuv420JpegFile,
                   size_t width, size_t height, uhdr_color_gamut_t p010Cg = UHDR_CG_BT_709,
                   uhdr_color_gamut_t yuv420Cg = UHDR_CG_BT_709,
                   uhdr_color_transfer_t p010Tf = UHDR_CT_HLG, int quality = 100,
                   uhdr_color_transfer_t oTf = UHDR_CT_HLG,
                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102)
      : mP010File(p010File),
        mYuv420File(yuv420File),
        mYuv420JpegFile(yuv420JpegFile),
        mJpegRFile(nullptr),
        mWidth(width),
        mHeight(height),
        mP010Cg(p010Cg),
        mYuv420Cg(yuv420Cg),
        mP010Tf(p010Tf),
        mQuality(quality),
        mOTf(oTf),
        mOfmt(oFmt),
        mMode(0){};

  UltraHdrAppInput(const char* jpegRFile, uhdr_color_transfer_t oTf = UHDR_CT_HLG,
                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102)
      : mP010File(nullptr),
        mYuv420File(nullptr),
        mJpegRFile(jpegRFile),
        mWidth(0),
        mHeight(0),
        mP010Cg(UHDR_CG_UNSPECIFIED),
        mYuv420Cg(UHDR_CG_UNSPECIFIED),
        mP010Tf(UHDR_CT_UNSPECIFIED),
        mQuality(100),
        mOTf(oTf),
        mOfmt(oFmt),
        mMode(1){};

  ~UltraHdrAppInput() {
    int count = sizeof mRawP010Image.planes / sizeof mRawP010Image.planes[0];
    for (int i = 0; i < count; i++) {
      if (mRawP010Image.planes[i]) {
        free(mRawP010Image.planes[i]);
        mRawP010Image.planes[i] = nullptr;
      }
      if (mRawRgba1010102Image.planes[i]) {
        free(mRawRgba1010102Image.planes[i]);
        mRawRgba1010102Image.planes[i] = nullptr;
      }
      if (mRawYuv420Image.planes[i]) {
        free(mRawYuv420Image.planes[i]);
        mRawYuv420Image.planes[i] = nullptr;
      }
      if (mRawRgba8888Image.planes[i]) {
        free(mRawRgba8888Image.planes[i]);
        mRawRgba8888Image.planes[i] = nullptr;
      }
      if (mDestImage.planes[i]) {
        free(mDestImage.planes[i]);
        mDestImage.planes[i] = nullptr;
      }
      if (mDestYUV444Image.planes[i]) {
        free(mDestYUV444Image.planes[i]);
        mDestYUV444Image.planes[i] = nullptr;
      }
    }
    if (mJpegImgR.data) free(mJpegImgR.data);
  }

  bool fillJpegRImageHandle();
  bool fillP010ImageHandle();
  bool convertP010ToRGBImage();
  bool fillYuv420ImageHandle();
  bool fillYuv420JpegImageHandle();
  bool convertYuv420ToRGBImage();
  bool convertRgba8888ToYUV444Image();
  bool convertRgba1010102ToYUV444Image();
  bool encode();
  bool decode();
  void computeRGBHdrPSNR();
  void computeRGBSdrPSNR();
  void computeYUVHdrPSNR();
  void computeYUVSdrPSNR();

  const char* mP010File;
  const char* mYuv420File;
  const char* mYuv420JpegFile;
  const char* mJpegRFile;
  const int mWidth;
  const int mHeight;
  const uhdr_color_gamut_t mP010Cg;
  const uhdr_color_gamut_t mYuv420Cg;
  const uhdr_color_transfer_t mP010Tf;
  const int mQuality;
  const uhdr_color_transfer_t mOTf;
  const uhdr_img_fmt mOfmt;
  const int mMode;

  uhdr_raw_image_t mRawP010Image{};
  uhdr_raw_image_t mRawRgba1010102Image{};
  uhdr_raw_image_t mRawYuv420Image{};
  uhdr_compressed_image_t mYuv420JpegImage{};
  uhdr_raw_image_t mRawRgba8888Image{};
  uhdr_compressed_image_t mJpegImgR{};
  uhdr_raw_image_t mDestImage{};
  uhdr_raw_image_t mDestYUV444Image{};
  double mPsnr[3]{};
};

bool UltraHdrAppInput::fillP010ImageHandle() {
  const int bpp = 2;
  int p010Size = mWidth * mHeight * bpp * 1.5;
  mRawP010Image.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  mRawP010Image.cg = mP010Cg;
  mRawP010Image.ct = mP010Tf;
  mRawP010Image.range = UHDR_CR_LIMITED_RANGE;
  mRawP010Image.w = mWidth;
  mRawP010Image.h = mHeight;
  mRawP010Image.planes[0] = malloc(mWidth * mHeight * bpp);
  mRawP010Image.planes[1] = malloc((mWidth / 2) * (mHeight / 2) * bpp * 2);
  mRawP010Image.planes[2] = nullptr;
  mRawP010Image.stride[0] = mWidth;
  mRawP010Image.stride[1] = mWidth;
  mRawP010Image.stride[2] = 0;
  return loadFile(mP010File, &mRawP010Image);
}

bool UltraHdrAppInput::fillYuv420ImageHandle() {
  int yuv420Size = mWidth * mHeight * 1.5;
  mRawYuv420Image.fmt = UHDR_IMG_FMT_12bppYCbCr420;
  mRawYuv420Image.cg = mYuv420Cg;
  mRawYuv420Image.ct = UHDR_CT_SRGB;
  mRawYuv420Image.range = UHDR_CR_FULL_RANGE;
  mRawYuv420Image.w = mWidth;
  mRawYuv420Image.h = mHeight;
  mRawYuv420Image.planes[0] = malloc(mWidth * mHeight);
  mRawYuv420Image.planes[1] = malloc((mWidth / 2) * (mHeight / 2));
  mRawYuv420Image.planes[2] = malloc((mWidth / 2) * (mHeight / 2));
  mRawYuv420Image.stride[0] = mWidth;
  mRawYuv420Image.stride[1] = mWidth / 2;
  mRawYuv420Image.stride[2] = mWidth / 2;
  return loadFile(mYuv420File, &mRawYuv420Image);
}

bool UltraHdrAppInput::fillYuv420JpegImageHandle() {
  std::ifstream ifd(mYuv420JpegFile, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int size = ifd.tellg();
    mYuv420JpegImage.capacity = size;
    mYuv420JpegImage.data_sz = size;
    mYuv420JpegImage.data = nullptr;
    mYuv420JpegImage.cg = mYuv420Cg;
    mYuv420JpegImage.ct = UHDR_CT_UNSPECIFIED;
    mYuv420JpegImage.range = UHDR_CR_UNSPECIFIED;
    ifd.close();
    return loadFile(mYuv420JpegFile, mYuv420JpegImage.data, size);
  }
  return false;
}

bool UltraHdrAppInput::fillJpegRImageHandle() {
  std::ifstream ifd(mJpegRFile, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int size = ifd.tellg();
    mJpegImgR.capacity = size;
    mJpegImgR.data_sz = size;
    mJpegImgR.data = nullptr;
    mYuv420JpegImage.cg = UHDR_CG_UNSPECIFIED;
    mYuv420JpegImage.ct = UHDR_CT_UNSPECIFIED;
    mYuv420JpegImage.range = UHDR_CR_UNSPECIFIED;
    ifd.close();
    return loadFile(mJpegRFile, mJpegImgR.data, size);
  }
  return false;
}

bool UltraHdrAppInput::encode() {
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
  if (mP010File != nullptr) {
    if (!fillP010ImageHandle()) {
      std::cerr << " failed to load file " << mP010File << std::endl;
      return false;
    }
    RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawP010Image, UHDR_HDR_IMG))
  }
  if (mYuv420File != nullptr) {
    if (!fillYuv420ImageHandle()) {
      std::cerr << " failed to load file " << mYuv420File << std::endl;
      return false;
    }
    RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawYuv420Image, UHDR_SDR_IMG))
  }
  if (mYuv420JpegFile != nullptr) {
    if (!fillYuv420JpegImageHandle()) {
      std::cerr << " failed to load file " << mYuv420JpegFile << std::endl;
      return false;
    }
    RET_IF_ERR(uhdr_enc_set_compressed_image(handle, &mYuv420JpegImage, UHDR_SDR_IMG))
  }
  RET_IF_ERR(uhdr_enc_set_quality(handle, mQuality, UHDR_BASE_IMG))
#ifdef PROFILE_ENABLE
  const int profileCount = 10;
  Profiler profileEncode;
  profileEncode.timerStart();
  for (auto i = 0; i < profileCount; i++) {
#endif
    RET_IF_ERR(uhdr_encode(handle))
#ifdef PROFILE_ENABLE
  }
  profileEncode.timerStop();
  auto avgEncTime = profileEncode.elapsedTime() / (profileCount * 1000.f);
  printf("Average encode time for res %d x %d is %f ms \n", mWidth, mHeight, avgEncTime);
#endif

#undef RET_IF_ERR

  auto output = uhdr_get_encoded_stream(handle);

  // for decoding
  mJpegImgR.data = malloc(output->data_sz);
  memcpy(mJpegImgR.data, output->data, output->data_sz);
  mJpegImgR.capacity = mJpegImgR.data_sz = output->data_sz;
  mJpegImgR.cg = output->cg;
  mJpegImgR.ct = output->ct;
  mJpegImgR.range = output->range;
  writeFile("out.jpeg", output->data, output->data_sz);
  uhdr_release_encoder(handle);

  return true;
}

bool UltraHdrAppInput::decode() {
  if (mMode == 1 && !fillJpegRImageHandle()) {
    std::cerr << " failed to load file " << mJpegRFile << std::endl;
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
  RET_IF_ERR(uhdr_dec_set_image(handle, &mJpegImgR))
  RET_IF_ERR(uhdr_dec_set_out_color_transfer(handle, mOTf))
  RET_IF_ERR(uhdr_dec_set_out_img_format(handle, mOfmt))

#ifdef PROFILE_ENABLE
  const int profileCount = 10;
  Profiler profileDecode;
  profileDecode.timerStart();
  for (auto i = 0; i < profileCount; i++) {
#endif
    RET_IF_ERR(uhdr_decode(handle))
#ifdef PROFILE_ENABLE
  }
  profileDecode.timerStop();
  auto avgDecTime = profileDecode.elapsedTime() / (profileCount * 1000.f);
  printf("Average decode time for res %ld x %ld is %f ms \n", info.width, info.height, avgDecTime);
#endif

#undef RET_IF_ERR

  uhdr_raw_image_t* output = uhdr_get_decoded_image(handle);

  mDestImage.fmt = output->fmt;
  mDestImage.cg = output->cg;
  mDestImage.ct = output->ct;
  mDestImage.range = output->range;
  mDestImage.w = output->w;
  mDestImage.h = output->h;
  int bpp = (output->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) ? 8 : 4;
  mDestImage.planes[0] = malloc(output->w * output->h * bpp);
  char* inData = static_cast<char*>(output->planes[0]);
  char* outData = static_cast<char*>(mDestImage.planes[0]);
  const size_t inStride = output->stride[0] * bpp;
  const size_t outStride = output->w * bpp;
  mDestImage.stride[0] = output->w;
  const size_t length = output->w * bpp;
  for (unsigned i = 0; i < output->h; i++, inData += inStride, outData += outStride) {
    memcpy(outData, inData, length);
  }
  writeFile("outrgb.raw", output);
  uhdr_release_decoder(handle);

  return true;
}

#define CLIP3(x, min, max) ((x) < (min)) ? (min) : ((x) > (max)) ? (max) : (x)
bool UltraHdrAppInput::convertP010ToRGBImage() {
  const float* coeffs = BT2020YUVtoRGBMatrix;
  if (mP010Cg == UHDR_CG_BT_709) {
    coeffs = BT709YUVtoRGBMatrix;
  } else if (mP010Cg == UHDR_CG_BT_2100) {
    coeffs = BT2020YUVtoRGBMatrix;
  } else if (mP010Cg == UHDR_CG_DISPLAY_P3) {
    coeffs = BT601YUVtoRGBMatrix;
  } else {
    std::cerr << "color matrix not present for gamut " << mP010Cg << " using BT2020Matrix"
              << std::endl;
  }

  mRawRgba1010102Image.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
  mRawRgba1010102Image.cg = mRawP010Image.cg;
  mRawRgba1010102Image.ct = mRawP010Image.ct;
  mRawRgba1010102Image.range = UHDR_CR_FULL_RANGE;
  mRawRgba1010102Image.w = mRawP010Image.w;
  mRawRgba1010102Image.h = mRawP010Image.h;
  mRawRgba1010102Image.planes[0] = malloc(mRawP010Image.w * mRawP010Image.h * 4);
  mRawRgba1010102Image.planes[1] = nullptr;
  mRawRgba1010102Image.planes[2] = nullptr;
  mRawRgba1010102Image.stride[0] = mWidth;
  mRawRgba1010102Image.stride[1] = 0;
  mRawRgba1010102Image.stride[2] = 0;

  uint32_t* rgbData = static_cast<uint32_t*>(mRawRgba1010102Image.planes[0]);
  uint16_t* y = static_cast<uint16_t*>(mRawP010Image.planes[0]);
  uint16_t* u = static_cast<uint16_t*>(mRawP010Image.planes[1]);
  uint16_t* v = u + 1;

  for (size_t i = 0; i < mRawP010Image.h; i++) {
    for (size_t j = 0; j < mRawP010Image.w; j++) {
      float y0 = float(y[mRawP010Image.stride[0] * i + j] >> 6);
      float u0 = float(u[mRawP010Image.stride[1] * (i / 2) + (j / 2) * 2] >> 6);
      float v0 = float(v[mRawP010Image.stride[1] * (i / 2) + (j / 2) * 2] >> 6);

      y0 = CLIP3(y0, 64.0f, 940.0f);
      u0 = CLIP3(u0, 64.0f, 960.0f);
      v0 = CLIP3(v0, 64.0f, 960.0f);

      y0 = (y0 - 64.0f) / 876.0f;
      u0 = (u0 - 64.0f) / 896.0f - 0.5f;
      v0 = (v0 - 64.0f) / 896.0f - 0.5f;

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
  writeFile("inRgba1010102.raw", &mRawRgba1010102Image);
  return true;
}

bool UltraHdrAppInput::convertYuv420ToRGBImage() {
  mRawRgba8888Image.fmt = UHDR_IMG_FMT_32bppRGBA8888;
  mRawRgba8888Image.cg = mRawYuv420Image.cg;
  mRawRgba8888Image.ct = mRawYuv420Image.ct;
  mRawRgba8888Image.range = UHDR_CR_FULL_RANGE;
  mRawRgba8888Image.w = mRawYuv420Image.w;
  mRawRgba8888Image.h = mRawYuv420Image.h;
  mRawRgba8888Image.planes[0] = malloc(mRawYuv420Image.w * mRawYuv420Image.h * 4);
  mRawRgba8888Image.planes[1] = nullptr;
  mRawRgba8888Image.planes[2] = nullptr;
  mRawRgba8888Image.stride[0] = mWidth;
  mRawRgba8888Image.stride[1] = 0;
  mRawRgba8888Image.stride[2] = 0;

  uint32_t* rgbData = static_cast<uint32_t*>(mRawRgba8888Image.planes[0]);
  uint8_t* y = static_cast<uint8_t*>(mRawYuv420Image.planes[0]);
  uint8_t* u = static_cast<uint8_t*>(mRawYuv420Image.planes[1]);
  uint8_t* v = static_cast<uint8_t*>(mRawYuv420Image.planes[2]);

  const float* coeffs = BT601YUVtoRGBMatrix;
  for (size_t i = 0; i < mRawYuv420Image.h; i++) {
    for (size_t j = 0; j < mRawYuv420Image.w; j++) {
      float y0 = float(y[mRawYuv420Image.stride[0] * i + j]);
      float u0 = float(u[mRawYuv420Image.stride[1] * (i / 2) + (j / 2)] - 128);
      float v0 = float(v[mRawYuv420Image.stride[2] * (i / 2) + (j / 2)] - 128);

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
  writeFile("inRgba8888.raw", &mRawRgba8888Image);
  return true;
}

bool UltraHdrAppInput::convertRgba8888ToYUV444Image() {
  mDestYUV444Image.fmt = static_cast<uhdr_img_fmt_t>(UHDR_IMG_FMT_24bppYCbCr444);
  mDestYUV444Image.cg = mDestImage.cg;
  mDestYUV444Image.ct = mDestImage.ct;
  mDestYUV444Image.range = UHDR_CR_FULL_RANGE;
  mDestYUV444Image.w = mDestImage.w;
  mDestYUV444Image.h = mDestImage.h;
  mDestYUV444Image.planes[0] = malloc(mDestImage.w * mDestImage.h);
  mDestYUV444Image.planes[1] = malloc(mDestImage.w * mDestImage.h);
  mDestYUV444Image.planes[2] = malloc(mDestImage.w * mDestImage.h);
  mDestYUV444Image.stride[0] = mWidth;
  mDestYUV444Image.stride[1] = mWidth;
  mDestYUV444Image.stride[2] = mWidth;

  uint32_t* rgbData = static_cast<uint32_t*>(mDestImage.planes[0]);

  uint8_t* yData = static_cast<uint8_t*>(mDestYUV444Image.planes[0]);
  uint8_t* uData = static_cast<uint8_t*>(mDestYUV444Image.planes[1]);
  uint8_t* vData = static_cast<uint8_t*>(mDestYUV444Image.planes[2]);

  const float* coeffs = BT601RGBtoYUVMatrix;
  for (size_t i = 0; i < mDestImage.h; i++) {
    for (size_t j = 0; j < mDestImage.w; j++) {
      float r0 = float(rgbData[mDestImage.stride[0] * i + j] & 0xff);
      float g0 = float((rgbData[mDestImage.stride[0] * i + j] >> 8) & 0xff);
      float b0 = float((rgbData[mDestImage.stride[0] * i + j] >> 16) & 0xff);

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

      yData[mDestYUV444Image.stride[0] * i + j] = uint8_t(y);
      uData[mDestYUV444Image.stride[1] * i + j] = uint8_t(u);
      vData[mDestYUV444Image.stride[2] * i + j] = uint8_t(v);
    }
  }
  writeFile("outyuv444.yuv", &mDestYUV444Image);
  return true;
}

bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
  const float* coeffs = BT2020RGBtoYUVMatrix;
  if (mP010Cg == UHDR_CG_BT_709) {
    coeffs = BT709RGBtoYUVMatrix;
  } else if (mP010Cg == UHDR_CG_BT_2100) {
    coeffs = BT2020RGBtoYUVMatrix;
  } else if (mP010Cg == UHDR_CG_DISPLAY_P3) {
    coeffs = BT601RGBtoYUVMatrix;
  } else {
    std::cerr << "color matrix not present for gamut " << mP010Cg << " using BT2020Matrix"
              << std::endl;
  }

  mDestYUV444Image.fmt = static_cast<uhdr_img_fmt_t>(UHDR_IMG_FMT_48bppYCbCr444);
  mDestYUV444Image.cg = mDestImage.cg;
  mDestYUV444Image.ct = mDestImage.ct;
  mDestYUV444Image.range = UHDR_CR_FULL_RANGE;
  mDestYUV444Image.w = mDestImage.w;
  mDestYUV444Image.h = mDestImage.h;
  mDestYUV444Image.planes[0] = malloc(mDestImage.w * mDestImage.h * 2);
  mDestYUV444Image.planes[1] = malloc(mDestImage.w * mDestImage.h * 2);
  mDestYUV444Image.planes[2] = malloc(mDestImage.w * mDestImage.h * 2);
  mDestYUV444Image.stride[0] = mWidth;
  mDestYUV444Image.stride[1] = mWidth;
  mDestYUV444Image.stride[2] = mWidth;

  uint32_t* rgbData = static_cast<uint32_t*>(mDestImage.planes[0]);

  uint16_t* yData = static_cast<uint16_t*>(mDestYUV444Image.planes[0]);
  uint16_t* uData = static_cast<uint16_t*>(mDestYUV444Image.planes[1]);
  uint16_t* vData = static_cast<uint16_t*>(mDestYUV444Image.planes[2]);

  for (size_t i = 0; i < mDestImage.h; i++) {
    for (size_t j = 0; j < mDestImage.w; j++) {
      float r0 = float(rgbData[mDestImage.stride[0] * i + j] & 0x3ff);
      float g0 = float((rgbData[mDestImage.stride[0] * i + j] >> 10) & 0x3ff);
      float b0 = float((rgbData[mDestImage.stride[0] * i + j] >> 20) & 0x3ff);

      r0 /= 1023.0f;
      g0 /= 1023.0f;
      b0 /= 1023.0f;

      float y = coeffs[0] * r0 + coeffs[1] * g0 + coeffs[2] * b0;
      float u = coeffs[3] * r0 + coeffs[4] * g0 + coeffs[5] * b0;
      float v = coeffs[6] * r0 + coeffs[7] * g0 + coeffs[8] * b0;

      y = (y * 876.0f) + 64.0f + 0.5f;
      u = (u * 896.0f) + 64.0f + 512.0f + 0.5f;
      v = (v * 896.0f) + 64.0f + 512.0f + 0.5f;

      y = CLIP3(y, 64.0f, 940.0f);
      u = CLIP3(u, 64.0f, 960.0f);
      v = CLIP3(v, 64.0f, 960.0f);

      yData[mDestYUV444Image.stride[0] * i + j] = uint16_t(y);
      uData[mDestYUV444Image.stride[1] * i + j] = uint16_t(u);
      vData[mDestYUV444Image.stride[2] * i + j] = uint16_t(v);
    }
  }
  writeFile("outyuv444.yuv", &mDestYUV444Image);
  return true;
}

void UltraHdrAppInput::computeRGBHdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA1010102) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }
  uint32_t* rgbDataSrc = static_cast<uint32_t*>(mRawRgba1010102Image.planes[0]);
  uint32_t* rgbDataDst = static_cast<uint32_t*>(mDestImage.planes[0]);
  if (rgbDataSrc == nullptr || rgbDataDst == nullptr) {
    std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
    return;
  }
  if (mOTf != mP010Tf) {
    std::cout << "input transfer function and output format are not compatible, psnr results "
                 "may be unreliable"
              << std::endl;
  }
  uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
  for (size_t i = 0; i < mRawP010Image.w * mRawP010Image.h; i++) {
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
  double meanSquareError = (double)rSqError / (mRawP010Image.w * mRawP010Image.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError = (double)gSqError / (mRawP010Image.w * mRawP010Image.h);
  mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError = (double)bSqError / (mRawP010Image.w * mRawP010Image.h);
  mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  std::cout << "psnr r :: " << mPsnr[0] << " psnr g :: " << mPsnr[1] << " psnr b :: " << mPsnr[2]
            << std::endl;
}

void UltraHdrAppInput::computeRGBSdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA8888) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }
  uint32_t* rgbDataSrc = static_cast<uint32_t*>(mRawRgba8888Image.planes[0]);
  uint32_t* rgbDataDst = static_cast<uint32_t*>(mDestImage.planes[0]);
  if (rgbDataSrc == nullptr || rgbDataDst == nullptr) {
    std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
    return;
  }

  uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
  for (size_t i = 0; i < mRawYuv420Image.w * mRawYuv420Image.h; i++) {
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
  double meanSquareError = (double)rSqError / (mRawYuv420Image.w * mRawYuv420Image.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError = (double)gSqError / (mRawYuv420Image.w * mRawYuv420Image.h);
  mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError = (double)bSqError / (mRawYuv420Image.w * mRawYuv420Image.h);
  mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  std::cout << "psnr r :: " << mPsnr[0] << " psnr g :: " << mPsnr[1] << " psnr b :: " << mPsnr[2]
            << std::endl;
}

void UltraHdrAppInput::computeYUVHdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA1010102) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }
  uint16_t* yDataSrc = static_cast<uint16_t*>(mRawP010Image.planes[0]);
  uint16_t* uDataSrc = static_cast<uint16_t*>(mRawP010Image.planes[1]);
  uint16_t* vDataSrc = uDataSrc + 1;

  uint16_t* yDataDst = static_cast<uint16_t*>(mDestYUV444Image.planes[0]);
  uint16_t* uDataDst = static_cast<uint16_t*>(mDestYUV444Image.planes[1]);
  uint16_t* vDataDst = static_cast<uint16_t*>(mDestYUV444Image.planes[2]);
  if (yDataSrc == nullptr || uDataSrc == nullptr || yDataDst == nullptr || uDataDst == nullptr ||
      vDataDst == nullptr) {
    std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
    return;
  }
  if (mOTf != mP010Tf) {
    std::cout << "input transfer function and output format are not compatible, psnr results "
                 "may be unreliable"
              << std::endl;
  }

  uint64_t ySqError = 0, uSqError = 0, vSqError = 0;
  for (size_t i = 0; i < mDestYUV444Image.h; i++) {
    for (size_t j = 0; j < mDestYUV444Image.w; j++) {
      int ySrc = (yDataSrc[mRawP010Image.stride[0] * i + j] >> 6) & 0x3ff;
      ySrc = CLIP3(ySrc, 64, 940);
      int yDst = yDataDst[mDestYUV444Image.stride[0] * i + j] & 0x3ff;
      ySqError += (ySrc - yDst) * (ySrc - yDst);

      if (i % 2 == 0 && j % 2 == 0) {
        int uSrc = (uDataSrc[mRawP010Image.stride[1] * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
        uSrc = CLIP3(uSrc, 64, 960);
        int uDst = uDataDst[mDestYUV444Image.stride[1] * i + j] & 0x3ff;
        uDst += uDataDst[mDestYUV444Image.stride[1] * i + j + 1] & 0x3ff;
        uDst += uDataDst[mDestYUV444Image.stride[1] * (i + 1) + j + 1] & 0x3ff;
        uDst += uDataDst[mDestYUV444Image.stride[1] * (i + 1) + j + 1] & 0x3ff;
        uDst = (uDst + 2) >> 2;
        uSqError += (uSrc - uDst) * (uSrc - uDst);

        int vSrc = (vDataSrc[mRawP010Image.stride[1] * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
        vSrc = CLIP3(vSrc, 64, 960);
        int vDst = vDataDst[mDestYUV444Image.stride[2] * i + j] & 0x3ff;
        vDst += vDataDst[mDestYUV444Image.stride[2] * i + j + 1] & 0x3ff;
        vDst += vDataDst[mDestYUV444Image.stride[2] * (i + 1) + j + 1] & 0x3ff;
        vDst += vDataDst[mDestYUV444Image.stride[2] * (i + 1) + j + 1] & 0x3ff;
        vDst = (vDst + 2) >> 2;
        vSqError += (vSrc - vDst) * (vSrc - vDst);
      }
    }
  }

  double meanSquareError = (double)ySqError / (mDestYUV444Image.w * mDestYUV444Image.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError = (double)uSqError / (mDestYUV444Image.w * mDestYUV444Image.h / 4);
  mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  meanSquareError = (double)vSqError / (mDestYUV444Image.w * mDestYUV444Image.h / 4);
  mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

  std::cout << "psnr y :: " << mPsnr[0] << " psnr u :: " << mPsnr[1] << " psnr v :: " << mPsnr[2]
            << std::endl;
}

void UltraHdrAppInput::computeYUVSdrPSNR() {
  if (mOfmt != UHDR_IMG_FMT_32bppRGBA8888) {
    std::cout << "psnr not supported for output format " << mOfmt << std::endl;
    return;
  }

  uint8_t* yDataSrc = static_cast<uint8_t*>(mRawYuv420Image.planes[0]);
  uint8_t* uDataSrc = static_cast<uint8_t*>(mRawYuv420Image.planes[1]);
  uint8_t* vDataSrc = static_cast<uint8_t*>(mRawYuv420Image.planes[2]);

  uint8_t* yDataDst = static_cast<uint8_t*>(mDestYUV444Image.planes[0]);
  uint8_t* uDataDst = static_cast<uint8_t*>(mDestYUV444Image.planes[1]);
  uint8_t* vDataDst = static_cast<uint8_t*>(mDestYUV444Image.planes[2]);

  uint64_t ySqError = 0, uSqError = 0, vSqError = 0;
  for (size_t i = 0; i < mDestYUV444Image.h; i++) {
    for (size_t j = 0; j < mDestYUV444Image.w; j++) {
      int ySrc = yDataSrc[mRawYuv420Image.stride[0] * i + j];
      int yDst = yDataDst[mDestYUV444Image.stride[0] * i + j];
      ySqError += (ySrc - yDst) * (ySrc - yDst);

      if (i % 2 == 0 && j % 2 == 0) {
        int uSrc = uDataSrc[mRawYuv420Image.stride[1] * (i / 2) + j / 2];
        int uDst = uDataDst[mDestYUV444Image.stride[1] * i + j];
        uDst += uDataDst[mDestYUV444Image.stride[1] * i + j + 1];
        uDst += uDataDst[mDestYUV444Image.stride[1] * (i + 1) + j];
        uDst += uDataDst[mDestYUV444Image.stride[1] * (i + 1) + j + 1];
        uDst = (uDst + 2) >> 2;
        uSqError += (uSrc - uDst) * (uSrc - uDst);

        int vSrc = vDataSrc[mRawYuv420Image.stride[2] * (i / 2) + j / 2];
        int vDst = vDataDst[mDestYUV444Image.stride[2] * i + j];
        vDst += vDataDst[mDestYUV444Image.stride[2] * i + j + 1];
        vDst += vDataDst[mDestYUV444Image.stride[2] * (i + 1) + j];
        vDst += vDataDst[mDestYUV444Image.stride[2] * (i + 1) + j + 1];
        vDst = (vDst + 2) >> 2;
        vSqError += (vSrc - vDst) * (vSrc - vDst);
      }
    }
  }
  double meanSquareError = (double)ySqError / (mDestYUV444Image.w * mDestYUV444Image.h);
  mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError = (double)uSqError / (mDestYUV444Image.w * mDestYUV444Image.h / 4);
  mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  meanSquareError = (double)vSqError / (mDestYUV444Image.w * mDestYUV444Image.h / 4);
  mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

  std::cout << "psnr y :: " << mPsnr[0] << " psnr  u:: " << mPsnr[1] << " psnr v :: " << mPsnr[2]
            << std::endl;
}

static void usage(const char* name) {
  fprintf(stderr, "\n## ultra hdr demo application.\nUsage : %s \n", name);
  fprintf(stderr, "    -m    mode of operation. [0:encode, 1:decode] \n");
  fprintf(stderr, "\n## encoder options : \n");
  fprintf(stderr, "    -p    raw 10 bit input resource in p010 color format, mandatory. \n");
  fprintf(stderr,
          "    -y    raw 8 bit input resource in yuv420, optional. \n"
          "          if not provided tonemapping happens internally. \n");
  fprintf(stderr, "    -i    compressed 8 bit jpeg file path, optional \n");
  fprintf(stderr, "    -w    input file width, mandatory. \n");
  fprintf(stderr, "    -h    input file height, mandatory. \n");
  fprintf(stderr, "    -C    10 bit input color gamut, optional. [0:bt709, 1:p3, 2:bt2100] \n");
  fprintf(stderr, "    -c    8 bit input color gamut, optional. [0:bt709, 1:p3, 2:bt2100] \n");
  fprintf(stderr, "    -t    10 bit input transfer function, optional. [0:linear, 1:hlg, 2:pq] \n");
  fprintf(stderr,
          "    -q    quality factor to be used while encoding 8 bit image, optional. [0-100].\n"
          "          gain map image does not use this quality factor. \n"
          "          for now gain map image quality factor is not configurable. \n");
  fprintf(stderr, "    -e    compute psnr, optional. [0:no, 1:yes] \n");
  fprintf(stderr, "\n## decoder options : \n");
  fprintf(stderr, "    -j    ultra hdr input resource, mandatory in decode mode. \n");
  fprintf(stderr,
          "    -o    output transfer function, optional. [0:linear, 1:hlg, 2:pq, 3:srgb] \n");
  fprintf(stderr,
          "    -O    output color format, optional. [3:rgba8888, 4:rgbahalffloat, 5:rgba1010102] \n"
          "It should be noted that not all combinations of output color format and output transfer "
          "function are supported. srgb output color transfer shall be paired with rgba8888 only. "
          "hlg, pq shall be paired with rgba1010102. linear shall be paired with rgbahalffloat");
  fprintf(stderr, "\n## examples of usage :\n");
  fprintf(stderr, "\n## encode api-0 :\n");
  fprintf(stderr, "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -C 1 -t 2\n");
  fprintf(stderr, "\n## encode api-1 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 "
          "-h 1080 -q 97\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 "
          "-h 1080 -q 97 -C 2 -c 1 -t 1\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 "
          "-h 1080 -q 97 -C 2 -c 1 -t 1 -e 1\n");
  fprintf(stderr, "\n## encode api-2 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -i "
          "cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -e 1\n");
  fprintf(stderr, "\n## encode api-3 :\n");
  fprintf(stderr,
          "    ultrahdr_app -m 0 -p cosmat_1920x1080_p010.yuv -i cosmat_1920x1080_420_8bit.jpg -w "
          "1920 -h 1080 -t 1 -o 1 -O 5 -e 1\n");
  fprintf(stderr, "\n## decode api :\n");
  fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg \n");
  fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg -o 3 -O 3\n");
  fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg -o 1 -O 5\n");
  fprintf(stderr, "\n");
}

int main(int argc, char* argv[]) {
  char opt_string[] = "p:y:i:w:h:C:c:t:q:o:O:m:j:e:";
  char *p010_file = nullptr, *yuv420_file = nullptr, *jpegr_file = nullptr,
       *yuv420_jpeg_file = nullptr;
  int width = 0, height = 0;
  uhdr_color_gamut_t p010Cg = UHDR_CG_BT_709;
  uhdr_color_gamut_t yuv420Cg = UHDR_CG_BT_709;
  uhdr_color_transfer_t p010Tf = UHDR_CT_HLG;
  int quality = 100;
  uhdr_color_transfer_t outTf = UHDR_CT_HLG;
  uhdr_img_fmt_t outFmt = UHDR_IMG_FMT_32bppRGBA1010102;
  int mode = 0;
  int compute_psnr = 0;
  int ch;
  while ((ch = getopt_s(argc, argv, opt_string)) != -1) {
    switch (ch) {
      case 'p':
        p010_file = optarg_s;
        break;
      case 'y':
        yuv420_file = optarg_s;
        break;
      case 'i':
        yuv420_jpeg_file = optarg_s;
        break;
      case 'w':
        width = atoi(optarg_s);
        break;
      case 'h':
        height = atoi(optarg_s);
        break;
      case 'C':
        p010Cg = static_cast<uhdr_color_gamut_t>(atoi(optarg_s));
        break;
      case 'c':
        yuv420Cg = static_cast<uhdr_color_gamut_t>(atoi(optarg_s));
        break;
      case 't':
        p010Tf = static_cast<uhdr_color_transfer_t>(atoi(optarg_s));
        break;
      case 'q':
        quality = atoi(optarg_s);
        break;
      case 'O':
        outFmt = static_cast<uhdr_img_fmt_t>(atoi(optarg_s));
        break;
      case 'o':
        outTf = static_cast<uhdr_color_transfer_t>(atoi(optarg_s));
        break;
      case 'm':
        mode = atoi(optarg_s);
        break;
      case 'j':
        jpegr_file = optarg_s;
        break;
      case 'e':
        compute_psnr = atoi(optarg_s);
        break;
      default:
        usage(argv[0]);
        return -1;
    }
  }
  if (mode == 0) {
    if (width <= 0 || height <= 0 || p010_file == nullptr) {
      usage(argv[0]);
      return -1;
    }
    UltraHdrAppInput appInput(p010_file, yuv420_file, yuv420_jpeg_file, width, height, p010Cg,
                              yuv420Cg, p010Tf, quality, outTf, outFmt);
    if (!appInput.encode()) return -1;
    if (compute_psnr == 1) {
      if (!appInput.decode()) return -1;
      if (outFmt == UHDR_IMG_FMT_32bppRGBA8888 && yuv420_file != nullptr) {
        appInput.convertYuv420ToRGBImage();
        appInput.computeRGBSdrPSNR();
        appInput.convertRgba8888ToYUV444Image();
        appInput.computeYUVSdrPSNR();
      } else if (outFmt == UHDR_IMG_FMT_32bppRGBA1010102) {
        appInput.convertP010ToRGBImage();
        appInput.computeRGBHdrPSNR();
        appInput.convertRgba1010102ToYUV444Image();
        appInput.computeYUVHdrPSNR();
      }
    }
  } else if (mode == 1) {
    if (jpegr_file == nullptr) {
      usage(argv[0]);
      return -1;
    }
    UltraHdrAppInput appInput(jpegr_file, outTf, outFmt);
    if (!appInput.decode()) return -1;
  } else {
    std::cerr << "unrecognized input mode " << mode << std::endl;
    usage(argv[0]);
    return -1;
  }

  return 0;
}
