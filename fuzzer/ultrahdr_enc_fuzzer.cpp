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

#include <fuzzer/FuzzedDataProvider.h>
#include <algorithm>
#include <iostream>
#include <memory>
#include <random>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"

using namespace ultrahdr;

// Color gamuts for image data, sync with ultrahdr_api.h
constexpr int kCgMin = UHDR_CG_UNSPECIFIED + 1;
constexpr int kCgMax = UHDR_CG_BT_2100;

// Transfer functions for image data, sync with ultrahdr_api.h
constexpr int kTfMin = UHDR_CT_UNSPECIFIED + 1;
constexpr int kTfMax = UHDR_CT_PQ;

// quality factor
constexpr int kQfMin = 0;
constexpr int kQfMax = 100;

class UltraHdrEncFuzzer {
 public:
  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
  void process();
  template <typename T>
  void fillBuffer(T* data, int width, int height, int stride);

 private:
  FuzzedDataProvider mFdp;
};

template <typename T>
void UltraHdrEncFuzzer::fillBuffer(T* data, int width, int height, int stride) {
  T* tmp = data;
  std::vector<T> buffer(16);
  for (int i = 0; i < buffer.size(); i++) {
    buffer[i] = (mFdp.ConsumeIntegralInRange<int>(0, (1 << 10) - 1)) << 6;
  }
  for (int j = 0; j < height; j++) {
    for (int i = 0; i < width; i += buffer.size()) {
      memcpy(tmp + i, buffer.data(), std::min((int)buffer.size(), (width - i)) * sizeof(*data));
      std::shuffle(buffer.begin(), buffer.end(),
                   std::default_random_engine(std::random_device{}()));
    }
    tmp += stride;
  }
}

void UltraHdrEncFuzzer::process() {
  while (mFdp.remaining_bytes()) {
    struct uhdr_raw_image hdrImg {};
    struct uhdr_raw_image sdrImg {};
    struct uhdr_raw_image gainmapImg {};

    // which encode api to select
    int muxSwitch = mFdp.ConsumeIntegralInRange<int>(0, 4);

    // base quality factor
    int base_quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);

    // gain_map quality factor
    int gainmap_quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);

    // hdr_tf
    auto tf = static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));

    // hdr Cg
    auto hdr_cg = static_cast<uhdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));

    // sdr Cg
    auto sdr_cg = static_cast<uhdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));

    // color range
    auto color_range = mFdp.ConsumeBool() ? UHDR_CR_LIMITED_RANGE : UHDR_CR_FULL_RANGE;

    // hdr_img_fmt
    auto hdr_img_fmt =
        mFdp.ConsumeBool() ? UHDR_IMG_FMT_24bppYCbCrP010 : UHDR_IMG_FMT_32bppRGBA1010102;

    // sdr_img_fmt
    auto sdr_img_fmt = mFdp.ConsumeBool() ? UHDR_IMG_FMT_12bppYCbCr420 : UHDR_IMG_FMT_32bppRGBA8888;
    if (muxSwitch > 1) sdr_img_fmt = UHDR_IMG_FMT_12bppYCbCr420;

    // multi channel gainmap
    auto multi_channel_gainmap = mFdp.ConsumeBool();

    int width = mFdp.ConsumeIntegralInRange<int>(kMinWidth, kMaxWidth);
    width = (width >> 1) << 1;

    int height = mFdp.ConsumeIntegralInRange<int>(kMinHeight, kMaxHeight);
    height = (height >> 1) << 1;

    // gainmap scale factor
    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int>(1, 128);

    std::unique_ptr<uint32_t[]> bufferHdr = nullptr;
    std::unique_ptr<uint16_t[]> bufferYHdr = nullptr;
    std::unique_ptr<uint16_t[]> bufferUVHdr = nullptr;
    std::unique_ptr<uint8_t[]> bufferYSdr = nullptr;
    std::unique_ptr<uint8_t[]> bufferUVSdr = nullptr;
    std::unique_ptr<uint8_t[]> gainMapImageRaw = nullptr;
    uhdr_codec_private_t* enc_handle = uhdr_create_encoder();
    if (!enc_handle) {
      ALOGE("Failed to create encoder");
      continue;
    }

#define ON_ERR(x)                              \
  {                                            \
    uhdr_error_info_t status_ = (x);           \
    if (status_.error_code != UHDR_CODEC_OK) { \
      if (status_.has_detail) {                \
        ALOGE("%s", status_.detail);           \
      }                                        \
    }                                          \
  }
    if (muxSwitch != 4) {
      // init p010/rgba1010102 image
      bool hasStride = mFdp.ConsumeBool();
      int yStride = hasStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
      hdrImg.w = width;
      hdrImg.h = height;
      hdrImg.cg = hdr_cg;
      hdrImg.fmt = hdr_img_fmt;
      hdrImg.ct = tf;
      hdrImg.range = color_range;
      hdrImg.stride[UHDR_PLANE_Y] = yStride;
      if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
        bool isUVContiguous = mFdp.ConsumeBool();
        if (isUVContiguous) {
          size_t p010Size = yStride * height * 3 / 2;
          bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
          hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yStride);
          fillBuffer<uint16_t>(bufferYHdr.get() + yStride * height, width, height / 2, yStride);
          hdrImg.planes[UHDR_PLANE_UV] = bufferYHdr.get() + yStride * height;
          hdrImg.stride[UHDR_PLANE_UV] = yStride;
        } else {
          int uvStride = mFdp.ConsumeIntegralInRange<int>(width, width + 128);
          size_t p010Size = yStride * height;
          bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
          hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yStride);
          size_t p010UVSize = uvStride * hdrImg.h / 2;
          bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
          hdrImg.planes[UHDR_PLANE_UV] = bufferUVHdr.get();
          hdrImg.stride[UHDR_PLANE_UV] = uvStride;
          fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvStride);
        }
      } else if (hdr_img_fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
        size_t rgba1010102Size = yStride * height;
        bufferHdr = std::make_unique<uint32_t[]>(rgba1010102Size);
        hdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yStride);
        hdrImg.planes[UHDR_PLANE_U] = nullptr;
        hdrImg.stride[UHDR_PLANE_U] = 0;
      }
      hdrImg.planes[UHDR_PLANE_V] = nullptr;
      hdrImg.stride[UHDR_PLANE_V] = 0;
      ON_ERR(uhdr_enc_set_raw_image(enc_handle, &hdrImg, UHDR_HDR_IMG))
    } else {
      size_t map_width = width / gm_scale_factor;
      size_t map_height = height / gm_scale_factor;
      gainmapImg.fmt = UHDR_IMG_FMT_8bppYCbCr400;
      gainmapImg.w = map_width;
      gainmapImg.h = map_height;
      gainmapImg.cg = UHDR_CG_UNSPECIFIED;
      gainmapImg.ct = UHDR_CT_UNSPECIFIED;
      gainmapImg.range = UHDR_CR_FULL_RANGE;
      const size_t graySize = map_width * map_height;
      gainMapImageRaw = std::make_unique<uint8_t[]>(graySize);
      gainmapImg.planes[UHDR_PLANE_Y] = gainMapImageRaw.get();
      gainmapImg.stride[UHDR_PLANE_Y] = map_width;
      gainmapImg.planes[UHDR_PLANE_U] = nullptr;
      gainmapImg.planes[UHDR_PLANE_V] = nullptr;
      gainmapImg.stride[UHDR_PLANE_U] = 0;
      gainmapImg.stride[UHDR_PLANE_V] = 0;
      fillBuffer<uint8_t>(gainMapImageRaw.get(), map_width, map_height, map_width);
    }

    if (muxSwitch > 0) {
      bool hasStride = mFdp.ConsumeBool();
      int yStride = hasStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
      // init yuv420 Image
      if (sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
        bool isUVContiguous = mFdp.ConsumeBool();
        sdrImg.w = width;
        sdrImg.h = height;
        sdrImg.cg = sdr_cg;
        sdrImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
        sdrImg.ct = UHDR_CT_SRGB;
        sdrImg.range = UHDR_CR_FULL_RANGE;
        sdrImg.stride[UHDR_PLANE_Y] = yStride;
        if (isUVContiguous) {
          size_t yuv420Size = yStride * height * 3 / 2;
          bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
          sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
          sdrImg.planes[UHDR_PLANE_U] = bufferYSdr.get() + yStride * height;
          sdrImg.planes[UHDR_PLANE_V] = bufferYSdr.get() + yStride * height * 5 / 4;
          sdrImg.stride[UHDR_PLANE_U] = yStride / 2;
          sdrImg.stride[UHDR_PLANE_V] = yStride / 2;
          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yStride);
          fillBuffer<uint8_t>(bufferYSdr.get() + yStride * height, width / 2, height / 2,
                              yStride / 2);
          fillBuffer<uint8_t>(bufferYSdr.get() + yStride * height * 5 / 4, width / 2, height / 2,
                              yStride / 2);
        } else {
          int uvStride = mFdp.ConsumeIntegralInRange<int>(width / 2, width / 2 + 128);
          size_t yuv420YSize = yStride * height;
          bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
          sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yStride);
          size_t yuv420UVSize = uvStride * sdrImg.h / 2 * 2;
          bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
          sdrImg.planes[UHDR_PLANE_U] = bufferUVSdr.get();
          sdrImg.stride[UHDR_PLANE_U] = uvStride;
          fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvStride);
          fillBuffer<uint8_t>(bufferUVSdr.get() + uvStride * height / 2, width / 2, height / 2,
                              uvStride);
          sdrImg.planes[UHDR_PLANE_V] = bufferUVSdr.get() + uvStride * height / 2;
          sdrImg.stride[UHDR_PLANE_V] = uvStride;
        }
      } else if (sdr_img_fmt == UHDR_IMG_FMT_32bppRGBA8888) {
        sdrImg.w = width;
        sdrImg.h = height;
        sdrImg.cg = sdr_cg;
        sdrImg.fmt = UHDR_IMG_FMT_32bppRGBA8888;
        sdrImg.ct = UHDR_CT_SRGB;
        sdrImg.range = UHDR_CR_FULL_RANGE;
        sdrImg.stride[UHDR_PLANE_PACKED] = yStride;
        size_t rgba8888Size = yStride * height;
        bufferHdr = std::make_unique<uint32_t[]>(rgba8888Size);
        sdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yStride);
        sdrImg.planes[UHDR_PLANE_U] = nullptr;
        sdrImg.planes[UHDR_PLANE_V] = nullptr;
        sdrImg.stride[UHDR_PLANE_U] = 0;
        sdrImg.stride[UHDR_PLANE_V] = 0;
      }
    }
    if (muxSwitch == 1 || muxSwitch == 2) {
      ON_ERR(uhdr_enc_set_raw_image(enc_handle, &sdrImg, UHDR_SDR_IMG))
    }
    ON_ERR(uhdr_enc_set_quality(enc_handle, base_quality, UHDR_BASE_IMG))
    ON_ERR(uhdr_enc_set_quality(enc_handle, gainmap_quality, UHDR_GAIN_MAP_IMG))
    ON_ERR(uhdr_enc_set_gainmap_scale_factor(enc_handle, gm_scale_factor))
    ON_ERR(uhdr_enc_set_using_multi_channel_gainmap(enc_handle, multi_channel_gainmap))

    uhdr_error_info_t status = {UHDR_CODEC_OK, 0, ""};
    if (muxSwitch == 0 || muxSwitch == 1) {  // api 0 or api 1
      status = uhdr_encode(enc_handle);
    } else {
      // compressed img
      JpegEncoderHelper encoder;
      if (encoder.compressImage(&sdrImg, base_quality, nullptr, 0).error_code == UHDR_CODEC_OK) {
        struct uhdr_compressed_image jpegImg = encoder.getCompressedImage();
        jpegImg.cg = sdr_cg;
        if (muxSwitch != 4) {
          // for api 4 compressed image will be set with UHDR_BASE_IMG intent
          uhdr_enc_set_compressed_image(enc_handle, &jpegImg, UHDR_SDR_IMG);
        }
        if (muxSwitch == 2 || muxSwitch == 3) {  // api 2 or api 3
          status = uhdr_encode(enc_handle);
        } else if (muxSwitch == 4) {  // api 4
          JpegEncoderHelper gainMapEncoder;
          if (gainMapEncoder.compressImage(&gainmapImg, gainmap_quality, nullptr, 0).error_code ==
              UHDR_CODEC_OK) {
            struct uhdr_compressed_image jpegGainMap = gainMapEncoder.getCompressedImage();
            uhdr_gainmap_metadata metadata;
            metadata.max_content_boost = 17.0f;
            metadata.min_content_boost = 1.0f;
            metadata.gamma = 1.0f;
            metadata.offset_sdr = 0.0f;
            metadata.offset_hdr = 0.0f;
            metadata.hdr_capacity_min = 1.0f;
            metadata.hdr_capacity_max = metadata.max_content_boost;
            ON_ERR(uhdr_enc_set_compressed_image(enc_handle, &jpegImg, UHDR_BASE_IMG))
            ON_ERR(uhdr_enc_set_gainmap_image(enc_handle, &jpegGainMap, &metadata))
            status = uhdr_encode(enc_handle);
          }
        }
      }
    }
    if (status.error_code == UHDR_CODEC_OK) {
      auto output = uhdr_get_encoded_stream(enc_handle);
      if (output != nullptr) {
        uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
        if (dec_handle) {
          ON_ERR(uhdr_dec_set_image(dec_handle, output))
          ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, tf))
          if (tf == UHDR_CT_LINEAR)
            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
          else if (tf == UHDR_CT_SRGB)
            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
          else
            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
          ON_ERR(uhdr_decode(dec_handle))
          uhdr_release_decoder(dec_handle);
        }
      }
      uhdr_release_encoder(enc_handle);
    } else {
      uhdr_release_encoder(enc_handle);
      ON_ERR(status);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UltraHdrEncFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
