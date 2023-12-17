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

#include <benchmark/benchmark.h>

#include "ultrahdr/jpegrutils.h"

using namespace ultrahdr;

#ifdef __ANDROID__
std::string kTestImagesPath = "/sdcard/test/UltrahdrBenchmarkTestRes-1.0/";
#else
std::string kTestImagesPath = "./data/UltrahdrBenchmarkTestRes-1.0/";
#endif

std::vector<std::string> kDecodeAPITestImages{
    // 12mp test vectors
    "mountains.jpg",
    "mountain_lake.jpg",
    "desert_wanda.jpg",
    // 3mp test vectors
    "mountains_3mp.jpg",
    "mountain_lake_3mp.jpg",
    "desert_wanda_3mp.jpg",
};

std::vector<std::string> kEncodeApi0TestImages12MpName{
    // 12mp test vectors
    "mountains.p010",
    "mountain_lake.p010",
};

std::vector<std::string> kEncodeApi0TestImages3MpName{
    // 3mp test vectors
    "mountains_3mp.p010",
    "mountain_lake_3mp.p010",
};

std::vector<std::pair<std::string, std::string>> kEncodeApi1TestImages12MpName{
    // 12mp test vectors
    {"mountains.p010", "mountains.yuv"},
    {"mountain_lake.p010", "mountain_lake.yuv"},
};

std::vector<std::pair<std::string, std::string>> kEncodeApi1TestImages3MpName{
    // 3mp test vectors
    {"mountains_3mp.p010", "mountains_3mp.yuv"},
    {"mountain_lake_3mp.p010", "mountain_lake_3mp.yuv"},
};

std::vector<std::tuple<std::string, std::string, std::string>> kEncodeApi2TestImages12MpName{
    // 12mp test vectors
    {"mountains.p010", "mountains.yuv", "mountains.jpg"},
    {"mountain_lake.p010", "mountain_lake.yuv", "mountain_lake.jpg"},
};

std::vector<std::tuple<std::string, std::string, std::string>> kEncodeApi2TestImages3MpName{
    // 3mp test vectors
    {"mountains_3mp.p010", "mountains_3mp.yuv", "mountains_3mp.jpg"},
    {"mountain_lake_3mp.p010", "mountain_lake_3mp.yuv", "mountain_lake_3mp.jpg"},
};

std::vector<std::pair<std::string, std::string>> kEncodeApi3TestImages12MpName{
    // 12mp test vectors
    {"mountains.p010", "mountains.jpg"},
    {"mountain_lake.p010", "mountain_lake.jpg"},
};

std::vector<std::pair<std::string, std::string>> kEncodeApi3TestImages3MpName{
    // 3mp test vectors
    {"mountains_3mp.p010", "mountains_3mp.jpg"},
    {"mountain_lake_3mp.p010", "mountain_lake_3mp.jpg"},
};

std::vector<std::string> kEncodeApi4TestImages12MpName{
    // 12mp test vectors
    "mountains.jpg",
    "mountain_lake.jpg",
    "desert_wanda.jpg",
};

std::vector<std::string> kEncodeApi4TestImages3MpName{
    // 3mp test vectors
    "mountains_3mp.jpg",
    "mountain_lake_3mp.jpg",
    "desert_wanda_3mp.jpg",
};

std::string ofToString(const ultrahdr_output_format of) {
  switch (of) {
    case ULTRAHDR_OUTPUT_SDR:
      return "sdr";
    case ULTRAHDR_OUTPUT_HDR_LINEAR:
      return "hdr linear";
    case ULTRAHDR_OUTPUT_HDR_PQ:
      return "hdr pq";
    case ULTRAHDR_OUTPUT_HDR_HLG:
      return "hdr hlg";
    default:
      return "Unknown";
  }
}

std::string colorGamutToString(const ultrahdr_color_gamut cg) {
  switch (cg) {
    case ULTRAHDR_COLORGAMUT_BT709:
      return "bt709";
    case ULTRAHDR_COLORGAMUT_P3:
      return "p3";
    case ULTRAHDR_COLORGAMUT_BT2100:
      return "bt2100";
    default:
      return "Unknown";
  }
}

std::string tfToString(const ultrahdr_transfer_function of) {
  switch (of) {
    case ULTRAHDR_TF_LINEAR:
      return "linear";
    case ULTRAHDR_TF_HLG:
      return "hlg";
    case ULTRAHDR_TF_PQ:
      return "pq";
    case ULTRAHDR_TF_SRGB:
      return "srgb";
    default:
      return "Unknown";
  }
}

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
    result = new uint8_t[length];
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

bool fillRawImageHandle(jpegr_uncompressed_struct* rawImage, int width, int height,
                        std::string file, ultrahdr_color_gamut cg, bool isP010) {
  const int bpp = isP010 ? 2 : 1;
  int imgSize = width * height * bpp * 1.5;
  rawImage->width = width;
  rawImage->height = height;
  rawImage->colorGamut = cg;
  return loadFile(file.c_str(), rawImage->data, imgSize);
}

bool fillJpgImageHandle(jpegr_compressed_struct* jpgImg, std::string file,
                        ultrahdr_color_gamut colorGamut) {
  std::ifstream ifd(file.c_str(), std::ios::binary | std::ios::ate);
  if (!ifd.good()) {
    return false;
  }
  int size = ifd.tellg();
  jpgImg->length = size;
  jpgImg->maxLength = size;
  jpgImg->data = nullptr;
  jpgImg->colorGamut = colorGamut;
  ifd.close();
  return loadFile(file.c_str(), jpgImg->data, size);
}

static void BM_Decode(benchmark::State& s) {
  std::string srcFileName = kTestImagesPath + "jpegr/" + kDecodeAPITestImages[s.range(0)];
  ultrahdr_output_format of = static_cast<ultrahdr_output_format>(s.range(1));

  std::ifstream ifd(srcFileName.c_str(), std::ios::binary | std::ios::ate);
  if (!ifd.good()) {
    s.SkipWithError("unable to open file " + srcFileName);
    return;
  }
  int size = ifd.tellg();

  jpegr_compressed_struct jpegImgR{};
  jpegImgR.length = size;
  jpegImgR.maxLength = size;
  jpegImgR.data = nullptr;
  jpegImgR.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  ifd.close();
  if (!loadFile(srcFileName.c_str(), jpegImgR.data, size)) {
    s.SkipWithError("unable to load file " + srcFileName);
    return;
  }

  std::unique_ptr<uint8_t[]> compData;
  compData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));

  JpegR jpegHdr;
  jpegr_info_struct info{};
  status_t status = jpegHdr.getJPEGRInfo(&jpegImgR, &info);
  if (JPEGR_NO_ERROR != status) {
    s.SkipWithError("getJPEGRInfo returned with error " + std::to_string(status));
    return;
  }

  size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(outSize);
  jpegr_uncompressed_struct destImage{};
  destImage.data = data.get();
  for (auto _ : s) {
    status = jpegHdr.decodeJPEGR(&jpegImgR, &destImage, FLT_MAX, nullptr, of);
    if (JPEGR_NO_ERROR != status) {
      s.SkipWithError("decodeJPEGR returned with error " + std::to_string(status));
      return;
    }
  }
  if (info.width != destImage.width || info.height != destImage.height) {
    s.SkipWithError("received unexpected width/height");
    return;
  }

  s.SetLabel(srcFileName + ", OutputFormat: " + ofToString(of) + ", " + std::to_string(info.width) +
             "x" + std::to_string(info.height));
}

static void BM_Encode_Api0(benchmark::State& s, std::vector<std::string> testVectors) {
  int width = s.range(1);
  int height = s.range(2);
  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(4));

  s.SetLabel(testVectors[s.range(0)] + ", " + colorGamutToString(p010Cg) + ", " + tfToString(tf) +
             ", " + std::to_string(width) + "x" + std::to_string(height));

  std::string p010File{kTestImagesPath + "p010/" + testVectors[s.range(0)]};

  jpegr_uncompressed_struct rawP010Image{};
  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
    s.SkipWithError("unable to load file : " + p010File);
    return;
  }
  std::unique_ptr<uint8_t[]> rawP010ImgData;
  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));

  jpegr_compressed_struct jpegImgR{};
  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
                                  rawP010Image.width * rawP010Image.height * 3 * 2);
  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
  if (jpegImgR.data == nullptr) {
    s.SkipWithError("unable to allocate memory to store compressed image");
    return;
  }
  std::unique_ptr<uint8_t[]> jpegImgRData;
  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));

  JpegR jpegHdr;
  for (auto _ : s) {
    status_t status = jpegHdr.encodeJPEGR(&rawP010Image, tf, &jpegImgR, 95, nullptr);
    if (JPEGR_NO_ERROR != status) {
      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
      return;
    }
  }
}

static void BM_Encode_Api1(benchmark::State& s,
                           std::vector<std::pair<std::string, std::string>> testVectors) {
  int width = s.range(1);
  int height = s.range(2);
  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
  ultrahdr_color_gamut yuv420Cg = static_cast<ultrahdr_color_gamut>(s.range(4));
  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(5));

  s.SetLabel(testVectors[s.range(0)].first + ", " + testVectors[s.range(0)].second + ", " +
             "p010_" + colorGamutToString(p010Cg) + ", " + "yuv420_" +
             colorGamutToString(yuv420Cg) + ", " + tfToString(tf) + ", " + std::to_string(width) +
             "x" + std::to_string(height));

  std::string p010File{kTestImagesPath + "p010/" + testVectors[s.range(0)].first};

  jpegr_uncompressed_struct rawP010Image{};
  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
    s.SkipWithError("unable to load file : " + p010File);
    return;
  }
  std::unique_ptr<uint8_t[]> rawP010ImgData;
  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));

  std::string yuv420File{kTestImagesPath + "yuv420/" + testVectors[s.range(0)].second};

  jpegr_uncompressed_struct rawYuv420Image{};
  if (!fillRawImageHandle(&rawYuv420Image, width, height, yuv420File, yuv420Cg, false)) {
    s.SkipWithError("unable to load file : " + yuv420File);
    return;
  }
  std::unique_ptr<uint8_t[]> rawYuv420ImgData;
  rawYuv420ImgData.reset(reinterpret_cast<uint8_t*>(rawYuv420Image.data));

  jpegr_compressed_struct jpegImgR{};
  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
                                  rawP010Image.width * rawP010Image.height * 3 * 2);
  jpegImgR.data = new uint8_t[jpegImgR.maxLength];

  std::unique_ptr<uint8_t[]> jpegImgRData;
  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));

  JpegR jpegHdr;
  for (auto _ : s) {
    status_t status =
        jpegHdr.encodeJPEGR(&rawP010Image, &rawYuv420Image, tf, &jpegImgR, 95, nullptr);
    if (JPEGR_NO_ERROR != status) {
      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
      return;
    }
  }
}

static void BM_Encode_Api2(
    benchmark::State& s,
    std::vector<std::tuple<std::string, std::string, std::string>> testVectors) {
  int width = s.range(1);
  int height = s.range(2);
  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(4));

  s.SetLabel(std::get<0>(testVectors[s.range(0)]) + ", " + std::get<1>(testVectors[s.range(0)]) +
             ", " + std::get<2>(testVectors[s.range(0)]) + ", " + colorGamutToString(p010Cg) +
             ", " + tfToString(tf) + ", " + std::to_string(width) + "x" + std::to_string(height));

  std::string p010File{kTestImagesPath + "p010/" + std::get<0>(testVectors[s.range(0)])};

  jpegr_uncompressed_struct rawP010Image{};
  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
    s.SkipWithError("unable to load file : " + p010File);
    return;
  }
  std::unique_ptr<uint8_t[]> rawP010ImgData;
  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));

  std::string yuv420File{kTestImagesPath + "yuv420/" + std::get<1>(testVectors[s.range(0)])};

  jpegr_uncompressed_struct rawYuv420Image{};
  if (!fillRawImageHandle(&rawYuv420Image, width, height, yuv420File, ULTRAHDR_COLORGAMUT_P3,
                          false)) {
    s.SkipWithError("unable to load file : " + yuv420File);
    return;
  }
  std::unique_ptr<uint8_t[]> rawYuv420ImgData;
  rawYuv420ImgData.reset(reinterpret_cast<uint8_t*>(rawYuv420Image.data));

  std::string yuv420JpegFile{
      (kTestImagesPath + "yuv420jpeg/" + std::get<2>(testVectors[s.range(0)]))};

  jpegr_compressed_struct yuv420JpegImage{};
  if (!fillJpgImageHandle(&yuv420JpegImage, yuv420JpegFile, ULTRAHDR_COLORGAMUT_P3)) {
    s.SkipWithError("unable to load file : " + yuv420JpegFile);
    return;
  }
  std::unique_ptr<uint8_t[]> yuv420jpegImgData;
  yuv420jpegImgData.reset(reinterpret_cast<uint8_t*>(yuv420JpegImage.data));

  jpegr_compressed_struct jpegImgR{};
  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
                                  rawP010Image.width * rawP010Image.height * 3 * 2);
  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
  if (jpegImgR.data == nullptr) {
    s.SkipWithError("unable to allocate memory to store compressed image");
    return;
  }
  std::unique_ptr<uint8_t[]> jpegImgRData;
  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));

  JpegR jpegHdr;
  for (auto _ : s) {
    status_t status =
        jpegHdr.encodeJPEGR(&rawP010Image, &rawYuv420Image, &yuv420JpegImage, tf, &jpegImgR);
    if (JPEGR_NO_ERROR != status) {
      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
      return;
    }
  }
}

static void BM_Encode_Api3(benchmark::State& s,
                           std::vector<std::pair<std::string, std::string>> testVectors) {
  int width = s.range(1);
  int height = s.range(2);
  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(4));

  s.SetLabel(testVectors[s.range(0)].first + ", " + testVectors[s.range(0)].second + ", " +
             colorGamutToString(p010Cg) + ", " + tfToString(tf) + ", " + std::to_string(width) +
             "x" + std::to_string(height));

  std::string p010File{kTestImagesPath + "p010/" + testVectors[s.range(0)].first};

  jpegr_uncompressed_struct rawP010Image{};
  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
    s.SkipWithError("unable to load file : " + p010File);
    return;
  }
  std::unique_ptr<uint8_t[]> rawP010ImgData;
  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));

  std::string yuv420JpegFile{(kTestImagesPath + "yuv420jpeg/" + testVectors[s.range(0)].second)};

  jpegr_compressed_struct yuv420JpegImage{};
  if (!fillJpgImageHandle(&yuv420JpegImage, yuv420JpegFile, ULTRAHDR_COLORGAMUT_P3)) {
    s.SkipWithError("unable to load file : " + yuv420JpegFile);
    return;
  }
  std::unique_ptr<uint8_t[]> yuv420jpegImgData;
  yuv420jpegImgData.reset(reinterpret_cast<uint8_t*>(yuv420JpegImage.data));

  jpegr_compressed_struct jpegImgR{};
  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
                                  rawP010Image.width * rawP010Image.height * 3 * 2);
  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
  if (jpegImgR.data == nullptr) {
    s.SkipWithError("unable to allocate memory to store compressed image");
    return;
  }
  std::unique_ptr<uint8_t[]> jpegImgRData;
  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));

  JpegR jpegHdr;
  for (auto _ : s) {
    status_t status = jpegHdr.encodeJPEGR(&rawP010Image, &yuv420JpegImage, tf, &jpegImgR);
    if (JPEGR_NO_ERROR != status) {
      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
      return;
    }
  }
}

static void BM_Encode_Api4(benchmark::State& s) {
  std::string srcFileName = kTestImagesPath + "jpegr/" + kDecodeAPITestImages[s.range(0)];

  std::ifstream ifd(srcFileName.c_str(), std::ios::binary | std::ios::ate);
  if (!ifd.good()) {
    s.SkipWithError("unable to open file " + srcFileName);
    return;
  }
  int size = ifd.tellg();

  jpegr_compressed_struct inpJpegImgR{};
  inpJpegImgR.length = size;
  inpJpegImgR.maxLength = size;
  inpJpegImgR.data = nullptr;
  inpJpegImgR.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  ifd.close();
  if (!loadFile(srcFileName.c_str(), inpJpegImgR.data, size)) {
    s.SkipWithError("unable to load file " + srcFileName);
    return;
  }
  std::unique_ptr<uint8_t[]> inpJpegImgRData;
  inpJpegImgRData.reset(reinterpret_cast<uint8_t*>(inpJpegImgR.data));

  JpegR jpegHdr;
  jpeg_info_struct primaryImgInfo;
  jpeg_info_struct gainmapImgInfo;
  jpegr_info_struct info{};
  info.primaryImgInfo = &primaryImgInfo;
  info.gainmapImgInfo = &gainmapImgInfo;
  status_t status = jpegHdr.getJPEGRInfo(&inpJpegImgR, &info);
  if (JPEGR_NO_ERROR != status) {
    s.SkipWithError("getJPEGRInfo returned with error " + std::to_string(status));
    return;
  }

  jpegr_compressed_struct jpegImgR{};
  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
                                  info.width * info.height * 3 * 2);
  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
  if (jpegImgR.data == nullptr) {
    s.SkipWithError("unable to allocate memory to store compressed image");
    return;
  }
  std::unique_ptr<uint8_t[]> jpegImgRData;
  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));

  jpegr_compressed_struct primaryImg;
  primaryImg.data = primaryImgInfo.imgData.data();
  primaryImg.maxLength = primaryImg.length = primaryImgInfo.imgData.size();
  primaryImg.colorGamut = static_cast<ultrahdr_color_gamut>(s.range(1));
  jpegr_compressed_struct gainmapImg;
  gainmapImg.data = gainmapImgInfo.imgData.data();
  gainmapImg.maxLength = gainmapImg.length = gainmapImgInfo.imgData.size();
  gainmapImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  ultrahdr_metadata_struct uhdr_metadata;
  if (!getMetadataFromXMP(gainmapImgInfo.xmpData.data(), gainmapImgInfo.xmpData.size(),
                          &uhdr_metadata)) {
    s.SkipWithError("getMetadataFromXMP returned with error");
    return;
  }
  for (auto _ : s) {
    status = jpegHdr.encodeJPEGR(&primaryImg, &gainmapImg, &uhdr_metadata, &jpegImgR);
    if (JPEGR_NO_ERROR != status) {
      s.SkipWithError("encodeJPEGR returned with error " + std::to_string(status));
      return;
    }
  }

  s.SetLabel(srcFileName + ", " + std::to_string(info.width) + "x" + std::to_string(info.height));
}

BENCHMARK(BM_Decode)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kDecodeAPITestImages.size() - 1, 1)},
                   {ULTRAHDR_OUTPUT_HDR_HLG, ULTRAHDR_OUTPUT_HDR_PQ, ULTRAHDR_OUTPUT_SDR}})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api0, TestVectorName, kEncodeApi0TestImages12MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi0TestImages12MpName.size() - 1, 1)},
                   {4080},
                   {3072},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api0, TestVectorName, kEncodeApi0TestImages3MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi0TestImages3MpName.size() - 1, 1)},
                   {2048},
                   {1536},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api1, TestVectorName, kEncodeApi1TestImages12MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi1TestImages12MpName.size() - 1, 1)},
                   {4080},
                   {3072},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api1, TestVectorName, kEncodeApi1TestImages3MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi1TestImages3MpName.size() - 1, 1)},
                   {2048},
                   {1536},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api2, TestVectorName, kEncodeApi2TestImages12MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi2TestImages12MpName.size() - 1, 1)},
                   {4080},
                   {3072},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api2, TestVectorName, kEncodeApi2TestImages3MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi2TestImages3MpName.size() - 1, 1)},
                   {2048},
                   {1536},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api3, TestVectorName, kEncodeApi3TestImages12MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi3TestImages12MpName.size() - 1, 1)},
                   {4080},
                   {3072},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_CAPTURE(BM_Encode_Api3, TestVectorName, kEncodeApi3TestImages3MpName)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi3TestImages3MpName.size() - 1, 1)},
                   {2048},
                   {1536},
                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
                   {
                       ULTRAHDR_TF_HLG,
                       ULTRAHDR_TF_PQ,
                   }})
    ->Unit(benchmark::kMillisecond);

BENCHMARK(BM_Encode_Api4)
    ->ArgsProduct({
        {benchmark::CreateDenseRange(0, kEncodeApi4TestImages12MpName.size() - 1, 1)},
        {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
    })
    ->Unit(benchmark::kMillisecond);

BENCHMARK(BM_Encode_Api4)
    ->ArgsProduct({
        {benchmark::CreateDenseRange(0, kEncodeApi4TestImages3MpName.size() - 1, 1)},
        {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
    })
    ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
