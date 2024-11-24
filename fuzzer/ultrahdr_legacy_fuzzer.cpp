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

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/jpegr.h"

using namespace ultrahdr;

// Color gamuts for image data, sync with ultrahdr.h
const int kCgMin = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
const int kCgMax = ULTRAHDR_COLORGAMUT_BT2100;

// Transfer functions for image data, sync with ultrahdr.h
const int kTfMin = ULTRAHDR_TF_UNSPECIFIED;
const int kTfMax = ULTRAHDR_TF_SRGB;

// Transfer functions for image data, sync with ultrahdr.h
const int kOfMin = ULTRAHDR_OUTPUT_UNSPECIFIED;
const int kOfMax = ULTRAHDR_OUTPUT_HDR_HLG;

// quality factor
const int kQfMin = -10;
const int kQfMax = 110;

class UltraHdrEncFuzzer {
 public:
  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {};
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
    struct jpegr_uncompressed_struct p010Img{};
    struct jpegr_uncompressed_struct yuv420Img{};
    struct jpegr_uncompressed_struct grayImg{};
    struct jpegr_compressed_struct jpegImgR{};
    struct jpegr_compressed_struct jpegImg{};
    struct jpegr_compressed_struct jpegGainMap{};

    // which encode api to select
    int muxSwitch = mFdp.ConsumeIntegralInRange<int>(0, 4);

    // quality factor
    int quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);

    // hdr_tf
    auto tf =
        static_cast<ultrahdr_transfer_function>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));

    // p010 Cg
    auto p010Cg =
        static_cast<ultrahdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));

    // 420 Cg
    auto yuv420Cg =
        static_cast<ultrahdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));

    // hdr_of
    auto of = static_cast<ultrahdr_output_format>(mFdp.ConsumeIntegralInRange<int>(kOfMin, kOfMax));

    int width = mFdp.ConsumeIntegralInRange<int>(kMinWidth, kMaxWidth);
    width = (width >> 1) << 1;

    int height = mFdp.ConsumeIntegralInRange<int>(kMinHeight, kMaxHeight);
    height = (height >> 1) << 1;

    // gain_map quality factor
    auto gainmap_quality = mFdp.ConsumeIntegral<int8_t>();

    // multi channel gainmap
    auto multi_channel_gainmap = mFdp.ConsumeIntegral<int8_t>();

    // gainmap scale factor
    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int16_t>(-32, 192);

    // encoding speed preset
    auto enc_preset = mFdp.ConsumeBool() ? UHDR_USAGE_REALTIME : UHDR_USAGE_BEST_QUALITY;

    // gainmap metadata
    auto minBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
    auto maxBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
    auto gamma = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
    auto offsetSdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
    auto offsetHdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
    auto minCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
    auto maxCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);

    // target display peak brightness
    auto targetDispPeakBrightness = mFdp.ConsumeFloatingPointInRange<float>(100.0f, 10500.0f);

    // raw buffer config
    bool hasP010Stride = mFdp.ConsumeBool();
    size_t yP010Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
    if (!hasP010Stride) yP010Stride = width;
    bool isP010UVContiguous = mFdp.ConsumeBool();
    bool hasP010UVStride = mFdp.ConsumeBool();
    size_t uvP010Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
    if (!hasP010UVStride) uvP010Stride = width;

    bool hasYuv420Stride = mFdp.ConsumeBool();
    size_t yYuv420Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
    if (!hasYuv420Stride) yYuv420Stride = width;
    bool isYuv420UVContiguous = mFdp.ConsumeBool();
    bool hasYuv420UVStride = mFdp.ConsumeBool();
    size_t uvYuv420Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width / 2, width / 2 + 128);
    if (!hasYuv420UVStride) uvYuv420Stride = width / 2;

    // display boost
    float displayBoost = mFdp.ConsumeFloatingPointInRange<float>(1.0, FLT_MAX);

    std::unique_ptr<uint16_t[]> bufferYHdr = nullptr;
    std::unique_ptr<uint16_t[]> bufferUVHdr = nullptr;
    std::unique_ptr<uint8_t[]> bufferYSdr = nullptr;
    std::unique_ptr<uint8_t[]> bufferUVSdr = nullptr;
    std::unique_ptr<uint8_t[]> grayImgRaw = nullptr;
    if (muxSwitch != 4) {
      // init p010 image
      p010Img.width = width;
      p010Img.height = height;
      p010Img.colorGamut = p010Cg;
      p010Img.luma_stride = yP010Stride;
      if (isP010UVContiguous) {
        size_t p010Size = yP010Stride * height * 3 / 2;
        bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
        p010Img.data = bufferYHdr.get();
        p010Img.chroma_data = nullptr;
        p010Img.chroma_stride = 0;
        fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yP010Stride);
        fillBuffer<uint16_t>(bufferYHdr.get() + yP010Stride * height, width, height / 2,
                             yP010Stride);
      } else {
        size_t p010YSize = yP010Stride * height;
        bufferYHdr = std::make_unique<uint16_t[]>(p010YSize);
        p010Img.data = bufferYHdr.get();
        fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yP010Stride);
        size_t p010UVSize = uvP010Stride * p010Img.height / 2;
        bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
        p010Img.chroma_data = bufferUVHdr.get();
        p010Img.chroma_stride = uvP010Stride;
        fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvP010Stride);
      }
    } else {
      size_t map_width = width / kMapDimensionScaleFactorDefault;
      size_t map_height = height / kMapDimensionScaleFactorDefault;
      // init 400 image
      grayImg.width = map_width;
      grayImg.height = map_height;
      grayImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
      const size_t graySize = map_width * map_height;
      grayImgRaw = std::make_unique<uint8_t[]>(graySize);
      grayImg.data = grayImgRaw.get();
      fillBuffer<uint8_t>(grayImgRaw.get(), map_width, map_height, map_width);
      grayImg.chroma_data = nullptr;
      grayImg.luma_stride = 0;
      grayImg.chroma_stride = 0;
    }

    if (muxSwitch > 0) {
      // init 420 image
      yuv420Img.width = width;
      yuv420Img.height = height;
      yuv420Img.colorGamut = yuv420Cg;
      yuv420Img.luma_stride = yYuv420Stride;
      if (isYuv420UVContiguous) {
        size_t yuv420Size = yYuv420Stride * height * 3 / 2;
        bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
        yuv420Img.data = bufferYSdr.get();
        yuv420Img.chroma_data = nullptr;
        yuv420Img.chroma_stride = 0;
        fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yYuv420Stride);
        fillBuffer<uint8_t>(bufferYSdr.get() + yYuv420Stride * height, width / 2, height / 2,
                            yYuv420Stride / 2);
        fillBuffer<uint8_t>(bufferYSdr.get() + yYuv420Stride * height * 5 / 4, width / 2,
                            height / 2, yYuv420Stride / 2);
      } else {
        size_t yuv420YSize = yYuv420Stride * height;
        bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
        yuv420Img.data = bufferYSdr.get();
        fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yYuv420Stride);
        size_t yuv420UVSize = uvYuv420Stride * yuv420Img.height / 2 * 2;
        bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
        yuv420Img.chroma_data = bufferUVSdr.get();
        yuv420Img.chroma_stride = uvYuv420Stride;
        fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvYuv420Stride);
        fillBuffer<uint8_t>(bufferUVSdr.get() + uvYuv420Stride * height / 2, width / 2, height / 2,
                            uvYuv420Stride);
      }
    }

    // dest
    // 2 * p010 size as input data is random, DCT compression might not behave as expected
    jpegImgR.maxLength = std::max(64 * 1024 /* min size 8kb */, width * height * 3 * 2);
    auto jpegImgRaw = std::make_unique<uint8_t[]>(jpegImgR.maxLength);
    jpegImgR.data = jpegImgRaw.get();
// #define DUMP_PARAM
#ifdef DUMP_PARAM
    std::cout << "Api Select " << muxSwitch << std::endl;
    std::cout << "image dimensions " << width << " x " << height << std::endl;
    std::cout << "p010 color gamut " << p010Img.colorGamut << std::endl;
    std::cout << "p010 luma stride " << p010Img.luma_stride << std::endl;
    std::cout << "p010 chroma stride " << p010Img.chroma_stride << std::endl;
    std::cout << "420 color gamut " << yuv420Img.colorGamut << std::endl;
    std::cout << "420 luma stride " << yuv420Img.luma_stride << std::endl;
    std::cout << "420 chroma stride " << yuv420Img.chroma_stride << std::endl;
    std::cout << "quality factor " << quality << std::endl;
#endif
    JpegR jpegHdr(nullptr, gm_scale_factor, gainmap_quality, multi_channel_gainmap, gamma,
                  enc_preset, minBoost, maxBoost, targetDispPeakBrightness);
    status_t status = JPEGR_UNKNOWN_ERROR;
    if (muxSwitch == 0) {  // api 0
      jpegImgR.length = 0;
      status = jpegHdr.encodeJPEGR(&p010Img, tf, &jpegImgR, quality, nullptr);
    } else if (muxSwitch == 1) {  // api 1
      jpegImgR.length = 0;
      status = jpegHdr.encodeJPEGR(&p010Img, &yuv420Img, tf, &jpegImgR, quality, nullptr);
    } else {
      // compressed img
      JpegEncoderHelper encoder;
      struct jpegr_uncompressed_struct yuv420ImgCopy = yuv420Img;
      if (yuv420ImgCopy.luma_stride == 0) yuv420ImgCopy.luma_stride = yuv420Img.width;
      if (!yuv420ImgCopy.chroma_data) {
        uint8_t* data = reinterpret_cast<uint8_t*>(yuv420Img.data);
        yuv420ImgCopy.chroma_data = data + yuv420Img.luma_stride * yuv420Img.height;
        yuv420ImgCopy.chroma_stride = yuv420Img.luma_stride >> 1;
      }
      const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420ImgCopy.data),
                               reinterpret_cast<uint8_t*>(yuv420ImgCopy.chroma_data),
                               reinterpret_cast<uint8_t*>(yuv420ImgCopy.chroma_data) +
                                   yuv420ImgCopy.chroma_stride * yuv420ImgCopy.height / 2};
      const unsigned int strides[3]{yuv420ImgCopy.luma_stride, yuv420ImgCopy.chroma_stride,
                                    yuv420ImgCopy.chroma_stride};
      if (encoder
              .compressImage(planes, strides, yuv420ImgCopy.width, yuv420ImgCopy.height,
                             UHDR_IMG_FMT_12bppYCbCr420, quality, nullptr, 0)
              .error_code == UHDR_CODEC_OK) {
        jpegImg.length = encoder.getCompressedImageSize();
        jpegImg.maxLength = jpegImg.length;
        jpegImg.data = encoder.getCompressedImagePtr();
        jpegImg.colorGamut = yuv420Cg;
        if (muxSwitch == 2) {  // api 2
          jpegImgR.length = 0;
          status = jpegHdr.encodeJPEGR(&p010Img, &yuv420Img, &jpegImg, tf, &jpegImgR);
        } else if (muxSwitch == 3) {  // api 3
          jpegImgR.length = 0;
          status = jpegHdr.encodeJPEGR(&p010Img, &jpegImg, tf, &jpegImgR);
        } else if (muxSwitch == 4) {  // api 4
          jpegImgR.length = 0;
          JpegEncoderHelper gainMapEncoder;
          const uint8_t* planeGm[1]{reinterpret_cast<uint8_t*>(grayImg.data)};
          const unsigned int strideGm[1]{grayImg.width};
          if (gainMapEncoder
                  .compressImage(planeGm, strideGm, grayImg.width, grayImg.height,
                                 UHDR_IMG_FMT_8bppYCbCr400, quality, nullptr, 0)
                  .error_code == UHDR_CODEC_OK) {
            jpegGainMap.length = gainMapEncoder.getCompressedImageSize();
            jpegGainMap.maxLength = jpegImg.length;
            jpegGainMap.data = gainMapEncoder.getCompressedImagePtr();
            jpegGainMap.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
            ultrahdr_metadata_struct metadata;
            metadata.version = kJpegrVersion;
            metadata.maxContentBoost = maxBoost;
            metadata.minContentBoost = minBoost;
            metadata.gamma = gamma;
            metadata.offsetSdr = offsetSdr;
            metadata.offsetHdr = offsetHdr;
            metadata.hdrCapacityMin = minCapacity;
            metadata.hdrCapacityMax = maxCapacity;
            status = jpegHdr.encodeJPEGR(&jpegImg, &jpegGainMap, &metadata, &jpegImgR);
          }
        }
      }
    }
    if (status == JPEGR_NO_ERROR) {
      jpegr_info_struct info{};
      status = jpegHdr.getJPEGRInfo(&jpegImgR, &info);
      if (status == JPEGR_NO_ERROR) {
        size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
        jpegr_uncompressed_struct decodedJpegR;
        auto decodedRaw = std::make_unique<uint8_t[]>(outSize);
        decodedJpegR.data = decodedRaw.get();
        ultrahdr_metadata_struct metadata;
        status = jpegHdr.decodeJPEGR(&jpegImgR, &decodedJpegR, displayBoost, nullptr, of, nullptr,
                                     &metadata);
        if (status != JPEGR_NO_ERROR) {
          ALOGE("encountered error during decoding %d", status);
        }
      } else {
        ALOGE("encountered error during get jpeg info %d", status);
      }
    } else {
      ALOGE("encountered error during encoding %d", status);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UltraHdrEncFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
