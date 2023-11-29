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

#include "ultrahdr/jpegr.h"

using namespace ultrahdr;

const std::string kDecTestVectors[] = {
    "./data/city_night.jpg",    "./data/desert_sunset.jpg", "./data/lamps.jpg",
    "./data/mountains.jpg",     "./data/desert_wanda.jpg",  "./data/grand_canyon.jpg",
    "./data/mountain_lake.jpg",
};

const size_t kNumDecTestVectors = std::size(kDecTestVectors);

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

static void BM_Decode(benchmark::State& s) {
  std::string srcFileName = kDecTestVectors[s.range(0)];
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
  std::vector<uint8_t> iccData(0);
  std::vector<uint8_t> exifData(0);
  jpegr_info_struct info{0, 0, &iccData, &exifData};
  if (JPEGR_NO_ERROR != jpegHdr.getJPEGRInfo(&jpegImgR, &info)) {
    s.SkipWithError("getJPEGRInfo returned with error ");
    return;
  }

  size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(outSize);
  jpegr_uncompressed_struct destImage{};
  destImage.data = data.get();
  for (auto _ : s) {
    if (JPEGR_NO_ERROR != jpegHdr.decodeJPEGR(&jpegImgR, &destImage, FLT_MAX, nullptr, of)) {
      s.SkipWithError("decodeJPEGR returned with error ");
      return;
    }
  }
  if (info.width != destImage.width || info.height != destImage.height) {
    s.SkipWithError("received unexpected width/height");
    return;
  }

  s.SetLabel(srcFileName + ", " + ofToString(of) + ", " + std::to_string(info.width) + "x" +
             std::to_string(info.height));
}

BENCHMARK(BM_Decode)
    ->ArgsProduct({{benchmark::CreateDenseRange(0, kNumDecTestVectors - 1, 1)},
                   {ULTRAHDR_OUTPUT_HDR_HLG, ULTRAHDR_OUTPUT_HDR_PQ, ULTRAHDR_OUTPUT_HDR_LINEAR,
                    ULTRAHDR_OUTPUT_SDR}})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
