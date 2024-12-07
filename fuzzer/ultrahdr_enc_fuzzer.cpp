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
#include <random>
#include <type_traits>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"

using namespace ultrahdr;

// Color gamuts for image data, sync with ultrahdr_api.h
constexpr int kCgMin = UHDR_CG_UNSPECIFIED;
constexpr int kCgMax = UHDR_CG_BT_2100;

// Color ranges for image data, sync with ultrahdr_api.h
constexpr int kCrMin = UHDR_CR_UNSPECIFIED;
constexpr int kCrMax = UHDR_CR_FULL_RANGE;

// Transfer functions for image data, sync with ultrahdr_api.h
constexpr int kTfMin = UHDR_CT_UNSPECIFIED;
constexpr int kTfMax = UHDR_CT_SRGB;

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
  if (!mFdp.remaining_bytes()) return;

  T* tmp = data;
  std::vector<T> buffer(width);
  for (int i = 0; i < buffer.size(); i++) {
    buffer[i] = mFdp.ConsumeIntegral<T>();
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
  if (mFdp.remaining_bytes()) {
    struct uhdr_raw_image hdrImg {};
    struct uhdr_raw_image sdrImg {};
    struct uhdr_raw_image gainmapImg {};

    float maxBoost[3], minBoost[3], gamma[3], offsetSdr[3], offsetHdr[3];

    // which encode api to select
    int muxSwitch = mFdp.ConsumeIntegralInRange<int8_t>(0, 4);

    // hdr_img_fmt
    uhdr_img_fmt_t hdr_img_fmt =
        mFdp.PickValueInArray({UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_32bppRGBA1010102,
                               UHDR_IMG_FMT_64bppRGBAHalfFloat});

    // sdr_img_fmt
    uhdr_img_fmt_t sdr_img_fmt =
        mFdp.ConsumeBool() ? UHDR_IMG_FMT_12bppYCbCr420 : UHDR_IMG_FMT_32bppRGBA8888;
    if (muxSwitch > 1) sdr_img_fmt = UHDR_IMG_FMT_12bppYCbCr420;

    // width
    int width = mFdp.ConsumeIntegralInRange<uint16_t>(kMinWidth, kMaxWidth);
    if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010 || sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      width = (width >> 1) << 1;
    }

    // height
    int height = mFdp.ConsumeIntegralInRange<uint16_t>(kMinHeight, kMaxHeight);
    if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010 || sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      height = (height >> 1) << 1;
    }

    // hdr Ct
    auto hdr_ct =
        static_cast<uhdr_color_transfer_t>(mFdp.ConsumeIntegralInRange<int8_t>(kTfMin, kTfMax));

    // hdr Cg
    auto hdr_cg =
        static_cast<uhdr_color_gamut_t>(mFdp.ConsumeIntegralInRange<int8_t>(kCgMin, kCgMax));

    // sdr Cg
    auto sdr_cg =
        static_cast<uhdr_color_gamut_t>(mFdp.ConsumeIntegralInRange<int8_t>(kCgMin, kCgMax));

    // color range
    auto hdr_cr =
        static_cast<uhdr_color_range_t>(mFdp.ConsumeIntegralInRange<int8_t>(kCrMin, kCrMax));

    // base quality factor
    auto base_quality = mFdp.ConsumeIntegral<int8_t>();

    // gain_map quality factor
    auto gainmap_quality = mFdp.ConsumeIntegral<int8_t>();

    // multi channel gainmap
    auto multi_channel_gainmap = mFdp.ConsumeIntegral<int8_t>();

    // gainmap scale factor
    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int16_t>(-32, 192);

    // encoding speed preset
    auto enc_preset = mFdp.ConsumeBool() ? UHDR_USAGE_REALTIME : UHDR_USAGE_BEST_QUALITY;

    bool are_all_channels_identical = mFdp.ConsumeBool();

    // gainmap metadata
    if (are_all_channels_identical) {
      minBoost[0] = minBoost[1] = minBoost[2] =
          mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
      maxBoost[0] = maxBoost[1] = maxBoost[2] =
          mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
      gamma[0] = gamma[1] = gamma[2] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
      offsetSdr[0] = offsetSdr[1] = offsetSdr[2] =
          mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
      offsetHdr[0] = offsetHdr[1] = offsetHdr[2] =
          mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
    } else {
      for (int i = 0; i < 3; i++) {
        minBoost[i] = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
        maxBoost[i] = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
        gamma[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
        offsetSdr[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
        offsetHdr[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
      }
    }
    auto minCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
    auto maxCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
    auto useBaseCg = mFdp.ConsumeBool();

    // target display peak brightness
    auto targetDispPeakBrightness = mFdp.ConsumeFloatingPointInRange<float>(100.0f, 10500.0f);

    // raw buffer config
    bool hasHdrStride = mFdp.ConsumeBool();
    size_t yHdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
    if (!hasHdrStride) yHdrStride = width;
    bool isHdrUVContiguous = mFdp.ConsumeBool();
    bool hasHdrUVStride = mFdp.ConsumeBool();
    size_t uvHdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
    if (!hasHdrUVStride) uvHdrStride = width;

    bool hasSdrStride = mFdp.ConsumeBool();
    size_t ySdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
    if (!hasSdrStride) ySdrStride = width;
    bool isSdrUVContiguous = mFdp.ConsumeBool();
    bool hasSdrUVStride = mFdp.ConsumeBool();
    size_t uvSdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width / 2, width / 2 + 128);
    if (!hasSdrUVStride) uvSdrStride = width / 2;

    // editing effects
    auto applyMirror = mFdp.ConsumeBool();
    uhdr_mirror_direction_t direction =
        mFdp.ConsumeBool() ? UHDR_MIRROR_VERTICAL : UHDR_MIRROR_HORIZONTAL;

    auto applyRotate = mFdp.ConsumeBool();
    int degrees = degrees = mFdp.PickValueInArray({-90, 0, 90, 180, 270});

    auto applyCrop = mFdp.ConsumeBool();
    int left = mFdp.ConsumeIntegral<int16_t>();
    int right = mFdp.ConsumeIntegral<int16_t>();
    int top = mFdp.ConsumeIntegral<int16_t>();
    int bottom = mFdp.ConsumeIntegral<int16_t>();

    auto applyResize = mFdp.ConsumeBool();
    int resizeWidth = mFdp.ConsumeIntegralInRange<int32_t>(-32, kMaxWidth + 128);
    int resizeHeight = mFdp.ConsumeIntegralInRange<int32_t>(-32, kMaxHeight + 128);

    // exif
    char greeting[] = "Exif says hello world";
    uhdr_mem_block_t exif{greeting, mFdp.ConsumeIntegralInRange<uint8_t>(0, sizeof greeting * 2),
                          sizeof greeting};

    ALOGV("encoding configuration options : ");
    ALOGV("encoding api - %d ", (int)muxSwitch);
    ALOGV("image dimensions %d x %d ", (int)width, (int)height);
    ALOGV("hdr intent color aspects: gamut %d, transfer %d, range %d, format %d ", (int)hdr_cg,
          (int)hdr_ct, (int)hdr_cr, (int)hdr_img_fmt);
    ALOGV("sdr intent color aspects: gamut %d, format %d ", (int)sdr_cg, (int)sdr_img_fmt);
    ALOGV(
        "gainmap img config: scale factor %d, enabled multichannel gainmap %s, gainmap quality %d ",
        (int)gm_scale_factor, (int)multi_channel_gainmap ? "Yes" : "No", (int)gainmap_quality);
    ALOGV("base image quality %d ", (int)base_quality);
    ALOGV("encoding preset %d ", (int)enc_preset);
    ALOGV(
        "gainmap metadata: min content boost %f %f %f, max content boost %f %f %f, gamma %f %f %f, "
        "offset sdr %f %f %f, offset hdr %f %f %f, hdr min capacity %f, hdr max capacity %f, "
        "useBaseCg %d",
        (float)minBoost[0], (float)minBoost[1], (float)minBoost[2], (float)maxBoost[0],
        (float)maxBoost[1], (float)maxBoost[2], (float)gamma[0], (float)gamma[1], (float)gamma[2],
        (float)offsetSdr[0], (float)offsetSdr[1], offsetSdr[2], (float)offsetHdr[0],
        (float)offsetHdr[1], (float)offsetHdr[2], (float)minCapacity, (float)maxCapacity,
        (int)useBaseCg);
    ALOGV("hdr intent luma stride %d, chroma stride %d", yHdrStride, uvHdrStride);
    ALOGV("sdr intent luma stride %d, chroma stride %d", ySdrStride, uvSdrStride);
    if (applyMirror) ALOGV("added mirror effect, direction %d", (int)direction);
    if (applyRotate) ALOGV("added rotate effect, degrees %d", (int)degrees);
    if (applyCrop)
      ALOGV("added crop effect, crop-left %d, crop-right %d, crop-top %d, crop-bottom %d", left,
            right, top, bottom);
    if (applyResize)
      ALOGV("added resize effect, resize wd %d, resize ht %d", resizeWidth, resizeHeight);

    std::unique_ptr<uint64_t[]> bufferFpHdr = nullptr;
    std::unique_ptr<uint32_t[]> bufferHdr = nullptr;
    std::unique_ptr<uint16_t[]> bufferYHdr = nullptr;
    std::unique_ptr<uint16_t[]> bufferUVHdr = nullptr;
    std::unique_ptr<uint8_t[]> bufferYSdr = nullptr;
    std::unique_ptr<uint8_t[]> bufferUVSdr = nullptr;
    std::unique_ptr<uint8_t[]> gainMapImageRaw = nullptr;
    uhdr_codec_private_t* enc_handle = uhdr_create_encoder();
    if (!enc_handle) {
      ALOGE("Failed to create encoder");
      return;
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
      hdrImg.w = width;
      hdrImg.h = height;
      hdrImg.cg = hdr_cg;
      hdrImg.fmt = hdr_img_fmt;
      hdrImg.ct = hdr_ct;
      hdrImg.range = hdr_cr;
      hdrImg.stride[UHDR_PLANE_Y] = yHdrStride;
      if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
        if (isHdrUVContiguous) {
          size_t p010Size = yHdrStride * height * 3 / 2;
          bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
          hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yHdrStride);
          fillBuffer<uint16_t>(bufferYHdr.get() + yHdrStride * height, width, height / 2,
                               yHdrStride);
          hdrImg.planes[UHDR_PLANE_UV] = bufferYHdr.get() + yHdrStride * height;
          hdrImg.stride[UHDR_PLANE_UV] = yHdrStride;
        } else {
          size_t p010Size = yHdrStride * height;
          bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
          hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yHdrStride);
          size_t p010UVSize = uvHdrStride * hdrImg.h / 2;
          bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
          hdrImg.planes[UHDR_PLANE_UV] = bufferUVHdr.get();
          hdrImg.stride[UHDR_PLANE_UV] = uvHdrStride;
          fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvHdrStride);
        }
      } else if (hdr_img_fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
        size_t rgba1010102Size = yHdrStride * height;
        bufferHdr = std::make_unique<uint32_t[]>(rgba1010102Size);
        hdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yHdrStride);
        hdrImg.planes[UHDR_PLANE_U] = nullptr;
        hdrImg.stride[UHDR_PLANE_U] = 0;
      } else if (hdr_img_fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
        size_t rgbafp16Size = yHdrStride * height;
        bufferFpHdr = std::make_unique<uint64_t[]>(rgbafp16Size);
        hdrImg.planes[UHDR_PLANE_PACKED] = bufferFpHdr.get();
        fillBuffer<uint64_t>(bufferFpHdr.get(), width, height, yHdrStride);
        hdrImg.planes[UHDR_PLANE_U] = nullptr;
        hdrImg.stride[UHDR_PLANE_U] = 0;
      }
      hdrImg.planes[UHDR_PLANE_V] = nullptr;
      hdrImg.stride[UHDR_PLANE_V] = 0;
      ON_ERR(uhdr_enc_set_raw_image(enc_handle, &hdrImg, UHDR_HDR_IMG))
    } else {
      size_t map_width = width / ((gm_scale_factor <= 0) ? 1 : gm_scale_factor);
      size_t map_height = height / ((gm_scale_factor <= 0) ? 1 : gm_scale_factor);
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
      // init yuv420 Image
      if (sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
        sdrImg.w = width;
        sdrImg.h = height;
        sdrImg.cg = sdr_cg;
        sdrImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
        sdrImg.ct = UHDR_CT_SRGB;
        sdrImg.range = UHDR_CR_FULL_RANGE;
        sdrImg.stride[UHDR_PLANE_Y] = ySdrStride;
        if (isSdrUVContiguous) {
          size_t yuv420Size = ySdrStride * height * 3 / 2;
          bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
          sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
          sdrImg.planes[UHDR_PLANE_U] = bufferYSdr.get() + ySdrStride * height;
          sdrImg.planes[UHDR_PLANE_V] = bufferYSdr.get() + ySdrStride * height * 5 / 4;
          sdrImg.stride[UHDR_PLANE_U] = ySdrStride / 2;
          sdrImg.stride[UHDR_PLANE_V] = ySdrStride / 2;
          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, ySdrStride);
          fillBuffer<uint8_t>(bufferYSdr.get() + ySdrStride * height, width / 2, height / 2,
                              ySdrStride / 2);
          fillBuffer<uint8_t>(bufferYSdr.get() + ySdrStride * height * 5 / 4, width / 2, height / 2,
                              ySdrStride / 2);
        } else {
          size_t yuv420YSize = ySdrStride * height;
          bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
          sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, ySdrStride);
          size_t yuv420UVSize = uvSdrStride * sdrImg.h / 2 * 2;
          bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
          sdrImg.planes[UHDR_PLANE_U] = bufferUVSdr.get();
          sdrImg.stride[UHDR_PLANE_U] = uvSdrStride;
          fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvSdrStride);
          fillBuffer<uint8_t>(bufferUVSdr.get() + uvSdrStride * height / 2, width / 2, height / 2,
                              uvSdrStride);
          sdrImg.planes[UHDR_PLANE_V] = bufferUVSdr.get() + uvSdrStride * height / 2;
          sdrImg.stride[UHDR_PLANE_V] = uvSdrStride;
        }
      } else if (sdr_img_fmt == UHDR_IMG_FMT_32bppRGBA8888) {
        sdrImg.w = width;
        sdrImg.h = height;
        sdrImg.cg = sdr_cg;
        sdrImg.fmt = UHDR_IMG_FMT_32bppRGBA8888;
        sdrImg.ct = UHDR_CT_SRGB;
        sdrImg.range = UHDR_CR_FULL_RANGE;
        sdrImg.stride[UHDR_PLANE_PACKED] = ySdrStride;
        size_t rgba8888Size = ySdrStride * height;
        bufferHdr = std::make_unique<uint32_t[]>(rgba8888Size);
        sdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
        fillBuffer<uint32_t>(bufferHdr.get(), width, height, ySdrStride);
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
    ON_ERR(uhdr_enc_set_exif_data(enc_handle, &exif))
    ON_ERR(uhdr_enc_set_using_multi_channel_gainmap(enc_handle, multi_channel_gainmap))
    ON_ERR(uhdr_enc_set_gainmap_scale_factor(enc_handle, gm_scale_factor))
    ON_ERR(uhdr_enc_set_gainmap_gamma(enc_handle, gamma[0]))
    ON_ERR(uhdr_enc_set_min_max_content_boost(enc_handle, minBoost[0], maxBoost[0]))
    ON_ERR(uhdr_enc_set_target_display_peak_brightness(enc_handle, targetDispPeakBrightness))
    ON_ERR(uhdr_enc_set_preset(enc_handle, enc_preset))
    ON_ERR(uhdr_enable_gpu_acceleration(enc_handle, 1))
    if (applyMirror) ON_ERR(uhdr_add_effect_mirror(enc_handle, direction))
    if (applyRotate) ON_ERR(uhdr_add_effect_rotate(enc_handle, degrees))
    if (applyCrop) ON_ERR(uhdr_add_effect_crop(enc_handle, left, right, top, bottom))
    if (applyResize) ON_ERR(uhdr_add_effect_resize(enc_handle, resizeWidth, resizeHeight))

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
            std::copy(maxBoost, maxBoost + 3, metadata.max_content_boost);
            std::copy(minBoost, minBoost + 3, metadata.min_content_boost);
            std::copy(gamma, gamma + 3, metadata.gamma);
            std::copy(offsetSdr, offsetSdr + 3, metadata.offset_sdr);
            std::copy(offsetHdr, offsetHdr + 3, metadata.offset_hdr);
            metadata.hdr_capacity_min = minCapacity;
            metadata.hdr_capacity_max = maxCapacity;
            metadata.use_base_cg = useBaseCg;
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
          ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, hdr_ct))
          if (hdr_ct == UHDR_CT_LINEAR)
            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
          else if (hdr_ct == UHDR_CT_SRGB)
            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
          else
            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
          ON_ERR(uhdr_decode(dec_handle))
          uhdr_release_decoder(dec_handle);
        }
      }
    }
    uhdr_reset_encoder(enc_handle);
    uhdr_release_encoder(enc_handle);
    ON_ERR(status);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UltraHdrEncFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
