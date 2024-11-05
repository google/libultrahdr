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

#include <fstream>
#include <iostream>
#include <cstring>

#include <benchmark/benchmark.h>

#include "ultrahdr_api.h"

#ifdef __ANDROID__
std::string kTestImagesPath = "/sdcard/test/UltrahdrBenchmarkTestRes-1.2/";

#ifdef LOG_NDEBUG
#include "android/log.h"

#ifndef LOG_TAG
#define LOG_TAG "UHDR_BENCHMARK"
#endif

#ifndef ALOGE
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif

#else
#define ALOGE(...) ((void)0)
#endif

#else
std::string kTestImagesPath = "./data/UltrahdrBenchmarkTestRes-1.2/";

#ifdef LOG_NDEBUG
#include <cstdio>

#define ALOGE(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)

#else
#define ALOGE(...) ((void)0)
#endif

#endif

std::vector<std::string> kDecodeAPITestImages = {
    "mountains_singlechannelgainmap.jpg",
    "mountains_multichannelgainmap.jpg",
    "mountains_singlechannelgamma.jpg",
    "mountains_multichannelgamma.jpg",
};

std::vector<std::string> kEncodeApi0TestImages12MpName = {
    "mountains_rgba1010102.raw",
    "mountains_rgba16F.raw",
    "mountains_p010.p010",
};

std::vector<std::pair<std::string, std::string>> kEncodeApi1TestImages12MpName = {
    {"mountains_rgba1010102.raw", "mountains_rgba8888.raw"},
    {"mountains_rgba16F.raw", "mountains_rgba8888.raw"},
    {"mountains_p010.p010", "mountains_yuv420.yuv"},
};

using TestParamsDecodeAPI = std::tuple<std::string, uhdr_color_transfer_t, uhdr_img_fmt_t, bool>;
using TestParamsEncoderAPI0 =
    std::tuple<std::string, int, int, uhdr_color_gamut_t, uhdr_color_transfer_t, int, float>;
using TestParamsEncoderAPI1 =
    std::tuple<std::string, std::string, int, int, uhdr_color_gamut_t, uhdr_color_transfer_t,
               uhdr_color_gamut_t, int, float, uhdr_enc_preset_t>;

std::vector<TestParamsDecodeAPI> testParamsDecodeAPI;
std::vector<TestParamsEncoderAPI0> testParamsAPI0;
std::vector<TestParamsEncoderAPI1> testParamsAPI1;

std::string imgFmtToString(const uhdr_img_fmt of) {
  switch (of) {
    case UHDR_IMG_FMT_32bppRGBA8888:
      return "rgba8888";
    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
      return "64rgbaHalftoFloat";
    case UHDR_IMG_FMT_32bppRGBA1010102:
      return "rgba1010102";
    default:
      return "Unknown";
  }
}

std::string colorGamutToString(const uhdr_color_gamut_t cg) {
  switch (cg) {
    case UHDR_CG_BT_709:
      return "bt709";
    case UHDR_CG_DISPLAY_P3:
      return "p3";
    case UHDR_CG_BT_2100:
      return "bt2100";
    default:
      return "Unknown";
  }
}

std::string tfToString(const uhdr_color_transfer_t of) {
  switch (of) {
    case UHDR_CT_LINEAR:
      return "linear";
    case UHDR_CT_HLG:
      return "hlg";
    case UHDR_CT_PQ:
      return "pq";
    case UHDR_CT_SRGB:
      return "srgb";
    default:
      return "Unknown";
  }
}

#define READ_BYTES(DESC, ADDR, LEN)                                         \
  DESC.read(static_cast<char*>(ADDR), (LEN));                               \
  if (DESC.gcount() != (LEN)) {                                             \
    ALOGE("Failed to read: %u bytes, read: %zu bytes", LEN, DESC.gcount()); \
    return false;                                                           \
  }

static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
  std::ifstream ifd(filename, std::ios::binary);
  if (ifd.good()) {
    if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      const int bpp = 2;
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], handle->w * handle->h * bpp)
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_UV], (handle->w / 2) * (handle->h / 2) * bpp * 2)
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
               handle->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
               handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
      const int bpp = handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], handle->w * handle->h * bpp)
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], handle->w * handle->h)
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_U], (handle->w / 2) * (handle->h / 2))
      READ_BYTES(ifd, handle->planes[UHDR_PLANE_V], (handle->w / 2) * (handle->h / 2))
      return true;
    }
    return false;
  }
  ALOGE("Unable to open file: %s", filename);
  return false;
}

static bool loadFile(const char* filename, void*& result, int length) {
  std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int size = ifd.tellg();
    if (size < length) {
      ALOGE("Requested to read %d bytes from file: %s, file contains only %d bytes", length,
            filename, size);
      return false;
    }
    ifd.seekg(0, std::ios::beg);
    result = malloc(length);
    if (result == nullptr) {
      ALOGE("Failed to allocate memory to store contents of file: %s", filename);
      return false;
    }
    READ_BYTES(ifd, result, length)
    return true;
  }
  ALOGE("Unable to open file: %s", filename);
  return false;
}

class DecBenchmark {
 public:
  std::string mUhdrFile;
  uhdr_color_transfer_t mTf;
  uhdr_img_fmt_t mOfmt;
  bool mEnableGLES;

  uhdr_compressed_image_t mUhdrImg{};

  DecBenchmark(TestParamsDecodeAPI testParams) {
    mUhdrFile = std::get<0>(testParams);
    mTf = std::get<1>(testParams);
    mOfmt = std::get<2>(testParams);
    mEnableGLES = std::get<3>(testParams);
  }
  ~DecBenchmark() {
    if (mUhdrImg.data) {
      free(mUhdrImg.data);
      mUhdrImg.data = nullptr;
    }
  }

  bool fillJpegImageHandle(uhdr_compressed_image_t* uhdrImg, std::string mUhdrFile);
};

bool DecBenchmark::fillJpegImageHandle(uhdr_compressed_image_t* uhdrImg, std::string filename) {
  std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int size = ifd.tellg();
    uhdrImg->capacity = size;
    uhdrImg->data_sz = size;
    uhdrImg->data = nullptr;
    uhdrImg->cg = UHDR_CG_UNSPECIFIED;
    uhdrImg->ct = UHDR_CT_UNSPECIFIED;
    uhdrImg->range = UHDR_CR_UNSPECIFIED;
    ifd.close();
    return loadFile(filename.c_str(), uhdrImg->data, size);
  }
  return false;
}

class EncBenchmark {
 public:
  std::string mHdrFile, mSdrFile;
  uhdr_color_gamut_t mHdrCg, mSdrCg;
  uhdr_img_fmt_t mHdrCf, mSdrCf;
  int mWidth, mHeight;
  uhdr_color_transfer_t mHdrCt, mSdrCt = UHDR_CT_SRGB;
  int mUseMultiChannelGainMap;
  int mMapDimensionScaleFactor = 1;
  float mGamma;
  uhdr_enc_preset_t mEncPreset;

  uhdr_raw_image_t mHdrImg{}, mSdrImg{};

  EncBenchmark(TestParamsEncoderAPI0 testParams) {
    mHdrFile = std::get<0>(testParams);
    mWidth = std::get<1>(testParams);
    mHeight = std::get<2>(testParams);
    mHdrCg = std::get<3>(testParams);
    mHdrCt = std::get<4>(testParams);
    mUseMultiChannelGainMap = std::get<5>(testParams);
    mGamma = std::get<6>(testParams);
  };

  EncBenchmark(TestParamsEncoderAPI1 testParams) {
    mHdrFile = std::get<0>(testParams);
    mSdrFile = std::get<1>(testParams);
    mWidth = std::get<2>(testParams);
    mHeight = std::get<3>(testParams);
    mHdrCg = std::get<4>(testParams);
    mHdrCt = std::get<5>(testParams);
    mSdrCg = std::get<6>(testParams);
    mUseMultiChannelGainMap = std::get<7>(testParams);
    mGamma = std::get<8>(testParams);
    mEncPreset = std::get<9>(testParams);
  }

  ~EncBenchmark() {
    int count = sizeof mHdrImg.planes / sizeof mHdrImg.planes[0];
    for (int i = 0; i < count; i++) {
      if (mHdrImg.planes[i]) {
        free(mHdrImg.planes[i]);
        mHdrImg.planes[i] = nullptr;
      }
      if (mSdrImg.planes[i]) {
        free(mSdrImg.planes[i]);
        mSdrImg.planes[i] = nullptr;
      }
    }
  }

  bool fillRawImageHandle(uhdr_raw_image_t* rawImg, int width, int height, std::string file,
                          uhdr_img_fmt_t cf, uhdr_color_gamut_t cg, uhdr_color_transfer_t ct);
};

bool EncBenchmark::fillRawImageHandle(uhdr_raw_image_t* rawImg, int width, int height,
                                      std::string file, uhdr_img_fmt_t cf, uhdr_color_gamut_t cg,
                                      uhdr_color_transfer_t ct) {
  rawImg->fmt = cf;
  rawImg->cg = cg;
  rawImg->ct = ct;
  rawImg->w = width;
  rawImg->h = height;
  if (cf == UHDR_IMG_FMT_24bppYCbCrP010) {
    const int bpp = 2;
    rawImg->range = std::rand() % 2 ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE;
    rawImg->planes[UHDR_PLANE_Y] = malloc(width * height * bpp);
    rawImg->planes[UHDR_PLANE_UV] = malloc((width / 2) * (height / 2) * bpp * 2);
    rawImg->planes[UHDR_PLANE_V] = nullptr;
    rawImg->stride[UHDR_PLANE_Y] = width;
    rawImg->stride[UHDR_PLANE_UV] = width;
    rawImg->stride[UHDR_PLANE_V] = 0;
    return loadFile(file.c_str(), rawImg);
  } else if (cf == UHDR_IMG_FMT_32bppRGBA1010102 || cf == UHDR_IMG_FMT_32bppRGBA8888 ||
             cf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    const int bpp = cf == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
    rawImg->range = UHDR_CR_FULL_RANGE;
    rawImg->planes[UHDR_PLANE_PACKED] = malloc(width * height * bpp);
    rawImg->planes[UHDR_PLANE_UV] = nullptr;
    rawImg->planes[UHDR_PLANE_V] = nullptr;
    rawImg->stride[UHDR_PLANE_PACKED] = width;
    rawImg->stride[UHDR_PLANE_UV] = 0;
    rawImg->stride[UHDR_PLANE_V] = 0;
    return loadFile(file.c_str(), rawImg);
  } else if (cf == UHDR_IMG_FMT_12bppYCbCr420) {
    rawImg->range = UHDR_CR_FULL_RANGE;
    rawImg->planes[UHDR_PLANE_Y] = malloc(width * height);
    rawImg->planes[UHDR_PLANE_U] = malloc((width / 2) * (height / 2));
    rawImg->planes[UHDR_PLANE_V] = malloc((width / 2) * (height / 2));
    rawImg->stride[UHDR_PLANE_Y] = width;
    rawImg->stride[UHDR_PLANE_U] = width / 2;
    rawImg->stride[UHDR_PLANE_V] = width / 2;
    return loadFile(file.c_str(), rawImg);
  }
  return false;
}

static void BM_UHDRDecode(benchmark::State& s, TestParamsDecodeAPI testVectors) {
  DecBenchmark benchmark(testVectors);

  s.SetLabel(benchmark.mUhdrFile + ", OutputFormat: " + imgFmtToString(benchmark.mOfmt) +
             ", ColorTransfer: " + tfToString(benchmark.mTf) +
             ", enableGLES: " + (benchmark.mEnableGLES ? "true" : "false"));

  benchmark.mUhdrFile = kTestImagesPath + "jpegr/" + benchmark.mUhdrFile;

  if (!benchmark.fillJpegImageHandle(&benchmark.mUhdrImg, benchmark.mUhdrFile)) {
    s.SkipWithError("unable to load file : " + benchmark.mUhdrFile);
    return;
  }

#define RET_IF_ERR(x)                                                       \
  {                                                                         \
    uhdr_error_info_t status = (x);                                         \
    if (status.error_code != UHDR_CODEC_OK) {                               \
      uhdr_release_decoder(decHandle);                                      \
      s.SkipWithError(status.has_detail ? status.detail : "Unknown error"); \
      return;                                                               \
    }                                                                       \
  }

  uhdr_codec_private_t* decHandle = uhdr_create_decoder();
  for (auto _ : s) {
    RET_IF_ERR(uhdr_dec_set_image(decHandle, &benchmark.mUhdrImg))
    RET_IF_ERR(uhdr_dec_set_out_color_transfer(decHandle, benchmark.mTf))
    RET_IF_ERR(uhdr_dec_set_out_img_format(decHandle, benchmark.mOfmt))
    RET_IF_ERR(uhdr_enable_gpu_acceleration(decHandle, benchmark.mEnableGLES))
    RET_IF_ERR(uhdr_decode(decHandle))
    uhdr_reset_decoder(decHandle);
  }
  uhdr_release_decoder(decHandle);
#undef RET_IF_ERR
}

#define RET_IF_ERR(x)                                                       \
  {                                                                         \
    uhdr_error_info_t status = (x);                                         \
    if (status.error_code != UHDR_CODEC_OK) {                               \
      uhdr_release_encoder(encHandle);                                      \
      s.SkipWithError(status.has_detail ? status.detail : "Unknown error"); \
      return;                                                               \
    }                                                                       \
  }

static void BM_UHDREncode_Api0(benchmark::State& s, TestParamsEncoderAPI0 testVectors) {
  EncBenchmark benchmark(testVectors);

  s.SetLabel(
      benchmark.mHdrFile + ", " + std::to_string(benchmark.mWidth) + "x" +
      std::to_string(benchmark.mHeight) + ", " + colorGamutToString(benchmark.mHdrCg) + ", " +
      (benchmark.mHdrFile.find("rgba16F") != std::string::npos ? "linear"
                                                               : tfToString(benchmark.mHdrCt)) +
      ", " +
      (benchmark.mUseMultiChannelGainMap == 0 ? "singlechannelgainmap" : "multichannelgainmap") +
      ", gamma: " + std::to_string(benchmark.mGamma));

  if (benchmark.mHdrFile.find("p010") != std::string::npos) {
    benchmark.mHdrFile = kTestImagesPath + "p010/" + benchmark.mHdrFile;
    benchmark.mHdrCf = UHDR_IMG_FMT_24bppYCbCrP010;
  } else if (benchmark.mHdrFile.find("rgba1010102") != std::string::npos) {
    benchmark.mHdrFile = kTestImagesPath + "rgba1010102/" + benchmark.mHdrFile;
    benchmark.mHdrCf = UHDR_IMG_FMT_32bppRGBA1010102;
  } else if (benchmark.mHdrFile.find("rgba16F") != std::string::npos) {
    benchmark.mHdrFile = kTestImagesPath + "rgba16F/" + benchmark.mHdrFile;
    benchmark.mHdrCf = UHDR_IMG_FMT_64bppRGBAHalfFloat;
    benchmark.mHdrCt = UHDR_CT_LINEAR;
  } else {
    s.SkipWithError("Invalid file format : " + benchmark.mHdrFile);
    return;
  }

  if (!benchmark.fillRawImageHandle(&benchmark.mHdrImg, benchmark.mWidth, benchmark.mHeight,
                                    benchmark.mHdrFile, benchmark.mHdrCf, benchmark.mHdrCg,
                                    benchmark.mHdrCt)) {
    s.SkipWithError("unable to load file : " + benchmark.mHdrFile);
    return;
  }

  uhdr_codec_private_t* encHandle = uhdr_create_encoder();
  for (auto _ : s) {
    RET_IF_ERR(uhdr_enc_set_raw_image(encHandle, &benchmark.mHdrImg, UHDR_HDR_IMG))
    RET_IF_ERR(
        uhdr_enc_set_using_multi_channel_gainmap(encHandle, benchmark.mUseMultiChannelGainMap))
    RET_IF_ERR(uhdr_enc_set_gainmap_scale_factor(encHandle, benchmark.mMapDimensionScaleFactor))
    RET_IF_ERR(uhdr_enc_set_gainmap_gamma(encHandle, benchmark.mGamma))
    RET_IF_ERR(uhdr_encode(encHandle))
    uhdr_reset_encoder(encHandle);
  }
  uhdr_release_encoder(encHandle);
}

static void BM_UHDREncode_Api1(benchmark::State& s, TestParamsEncoderAPI1 testVectors) {
  EncBenchmark benchmark(testVectors);

  s.SetLabel(
      benchmark.mHdrFile + ", " + benchmark.mSdrFile + ", " + std::to_string(benchmark.mWidth) +
      "x" + std::to_string(benchmark.mHeight) + ", hdrCg: " + colorGamutToString(benchmark.mHdrCg) +
      ", hdrCt: " +
      (benchmark.mHdrFile.find("rgba16F") != std::string::npos ? "linear"
                                                               : tfToString(benchmark.mHdrCt)) +
      ", sdrCg: " + colorGamutToString(benchmark.mSdrCg) + ", " +
      (benchmark.mUseMultiChannelGainMap == 0 ? "singlechannelgainmap" : "multichannelgainmap") +
      ", gamma: " + std::to_string(benchmark.mGamma) + ", " +
      (benchmark.mEncPreset == UHDR_USAGE_BEST_QUALITY ? "best_quality" : "realtime"));

  if (benchmark.mHdrFile.find("p010") != std::string::npos) {
    benchmark.mHdrFile = kTestImagesPath + "p010/" + benchmark.mHdrFile;
    benchmark.mHdrCf = UHDR_IMG_FMT_24bppYCbCrP010;
  } else if (benchmark.mHdrFile.find("rgba1010102") != std::string::npos) {
    benchmark.mHdrFile = kTestImagesPath + "rgba1010102/" + benchmark.mHdrFile;
    benchmark.mHdrCf = UHDR_IMG_FMT_32bppRGBA1010102;
  } else if (benchmark.mHdrFile.find("rgba16F") != std::string::npos) {
    benchmark.mHdrFile = kTestImagesPath + "rgba16F/" + benchmark.mHdrFile;
    benchmark.mHdrCf = UHDR_IMG_FMT_64bppRGBAHalfFloat;
    benchmark.mHdrCt = UHDR_CT_LINEAR;
  } else {
    s.SkipWithError("Invalid hdr file format : " + benchmark.mHdrFile);
    return;
  }

  if (benchmark.mSdrFile.find("yuv420") != std::string::npos) {
    benchmark.mSdrFile = kTestImagesPath + "yuv420/" + benchmark.mSdrFile;
    benchmark.mSdrCf = UHDR_IMG_FMT_12bppYCbCr420;
  } else if (benchmark.mSdrFile.find("rgba8888") != std::string::npos) {
    benchmark.mSdrFile = kTestImagesPath + "rgba8888/" + benchmark.mSdrFile;
    benchmark.mSdrCf = UHDR_IMG_FMT_32bppRGBA8888;
  } else {
    s.SkipWithError("Invalid sdr file format : " + benchmark.mSdrFile);
    return;
  }

  if (!benchmark.fillRawImageHandle(&benchmark.mHdrImg, benchmark.mWidth, benchmark.mHeight,
                                    benchmark.mHdrFile, benchmark.mHdrCf, benchmark.mHdrCg,
                                    benchmark.mHdrCt)) {
    s.SkipWithError("unable to load file : " + benchmark.mHdrFile);
    return;
  }
  if (!benchmark.fillRawImageHandle(&benchmark.mSdrImg, benchmark.mWidth, benchmark.mHeight,
                                    benchmark.mSdrFile, benchmark.mSdrCf, benchmark.mSdrCg,
                                    benchmark.mSdrCt)) {
    s.SkipWithError("unable to load sdr file : " + benchmark.mSdrFile);
    return;
  }

  uhdr_codec_private_t* encHandle = uhdr_create_encoder();
  for (auto _ : s) {
    RET_IF_ERR(uhdr_enc_set_raw_image(encHandle, &benchmark.mHdrImg, UHDR_HDR_IMG))
    RET_IF_ERR(uhdr_enc_set_raw_image(encHandle, &benchmark.mSdrImg, UHDR_SDR_IMG))
    RET_IF_ERR(
        uhdr_enc_set_using_multi_channel_gainmap(encHandle, benchmark.mUseMultiChannelGainMap))
    RET_IF_ERR(uhdr_enc_set_gainmap_scale_factor(encHandle, benchmark.mMapDimensionScaleFactor))
    RET_IF_ERR(uhdr_enc_set_gainmap_gamma(encHandle, benchmark.mGamma))
    RET_IF_ERR(uhdr_enc_set_preset(encHandle, benchmark.mEncPreset))
    RET_IF_ERR(uhdr_encode(encHandle))
    uhdr_reset_encoder(encHandle);
  }
  uhdr_release_encoder(encHandle);
}

void addTestVectors() {
  for (const auto& uhdrFile : kDecodeAPITestImages) {
    /* Decode API - uhdrFile, colorTransfer, imgFormat, enableGLES */
    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_HLG, UHDR_IMG_FMT_32bppRGBA1010102, false});
    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_PQ, UHDR_IMG_FMT_32bppRGBA1010102, false});
    testParamsDecodeAPI.push_back(
        {uhdrFile, UHDR_CT_LINEAR, UHDR_IMG_FMT_64bppRGBAHalfFloat, false});
    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_HLG, UHDR_IMG_FMT_32bppRGBA1010102, true});
    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_PQ, UHDR_IMG_FMT_32bppRGBA1010102, true});
    testParamsDecodeAPI.push_back(
        {uhdrFile, UHDR_CT_LINEAR, UHDR_IMG_FMT_64bppRGBAHalfFloat, true});
    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_SRGB, UHDR_IMG_FMT_32bppRGBA8888, false});
  }

  for (const auto& hdrFile : kEncodeApi0TestImages12MpName) {
    /* Encode API 0 - hdrFile, width, height, hdrColorGamut, hdrColorTransfer,
       useMultiChannelGainmap, gamma */
    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 0, 1.0f});
    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 1, 1.0f});
    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 0, 1.571f});
    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 1, 1.616f});
  }

  for (const auto& inputFiles : kEncodeApi1TestImages12MpName) {
    /* Encode API 1 - hdrFile, sdrFile, width, height, hdrColorGamut, hdrColorTransfer,
       sdrColorGamut, useMultiChannelGainmap, gamma, encPreset */
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.0f, UHDR_USAGE_REALTIME});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.0f, UHDR_USAGE_REALTIME});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.571f, UHDR_USAGE_REALTIME});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.0f, UHDR_USAGE_BEST_QUALITY});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.571f, UHDR_USAGE_REALTIME});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.0f, UHDR_USAGE_BEST_QUALITY});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.571f, UHDR_USAGE_BEST_QUALITY});
    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.571f, UHDR_USAGE_BEST_QUALITY});
  }
}

void registerBenchmarks() {
  for (auto& param : testParamsDecodeAPI) {
    benchmark::RegisterBenchmark("BM_UHDRDecode", BM_UHDRDecode, param)
        ->Unit(benchmark::kMillisecond);
  }
  for (auto& param : testParamsAPI0) {
    benchmark::RegisterBenchmark("BM_UHDREncode_Api0", BM_UHDREncode_Api0, param)
        ->Unit(benchmark::kMillisecond);
  }
  for (auto& param : testParamsAPI1) {
    benchmark::RegisterBenchmark("BM_UHDREncode_Api1", BM_UHDREncode_Api1, param)
        ->Unit(benchmark::kMillisecond);
  }
}

int main(int argc, char** argv) {
  addTestVectors();
  registerBenchmarks();
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks(nullptr, nullptr);
  benchmark::Shutdown();
  return 0;
}
