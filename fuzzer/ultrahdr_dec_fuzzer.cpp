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

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"

using namespace ultrahdr;

// Transfer functions for image data, sync with ultrahdr.h
constexpr int kTfMin = UHDR_CT_UNSPECIFIED;
constexpr int kTfMax = UHDR_CT_SRGB;

class UltraHdrDecFuzzer {
 public:
  UltraHdrDecFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {};
  void process();

 private:
  FuzzedDataProvider mFdp;
};

void UltraHdrDecFuzzer::process() {
  auto output_ct =
      static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int8_t>(kTfMin, kTfMax));
  auto displayBoost = mFdp.ConsumeFloatingPointInRange<float>(-10.0f, 100.0f);
  auto enableGpu = mFdp.ConsumeBool();

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

  auto buffer = mFdp.ConsumeRemainingBytes<uint8_t>();

  uhdr_compressed_image_t jpegImgR{
      buffer.data(),       (unsigned int)buffer.size(), (unsigned int)buffer.size(),
      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,         UHDR_CR_UNSPECIFIED};
#define ON_ERR(x)                              \
  {                                            \
    uhdr_error_info_t status_ = (x);           \
    if (status_.error_code != UHDR_CODEC_OK) { \
      if (status_.has_detail) {                \
        ALOGE("%s", status_.detail);           \
      }                                        \
    }                                          \
  }

  (void)is_uhdr_image(buffer.data(), buffer.size());

  uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
  if (dec_handle) {
    ON_ERR(uhdr_dec_set_image(dec_handle, &jpegImgR))
    ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, output_ct))
    if (output_ct == UHDR_CT_LINEAR)
      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
    else if (output_ct == UHDR_CT_SRGB)
      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
    else
      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
    ON_ERR(uhdr_dec_set_out_max_display_boost(dec_handle, displayBoost))
    ON_ERR(uhdr_enable_gpu_acceleration(dec_handle, enableGpu))
    if (applyMirror) ON_ERR(uhdr_add_effect_mirror(dec_handle, direction))
    if (applyRotate) ON_ERR(uhdr_add_effect_rotate(dec_handle, degrees))
    if (applyCrop) ON_ERR(uhdr_add_effect_crop(dec_handle, left, right, top, bottom))
    if (applyResize) ON_ERR(uhdr_add_effect_resize(dec_handle, resizeWidth, resizeHeight))
    uhdr_dec_probe(dec_handle);
    auto width = uhdr_dec_get_image_width(dec_handle);
    auto height = uhdr_dec_get_image_height(dec_handle);
    auto gainmap_width = uhdr_dec_get_gainmap_width(dec_handle);
    auto gainmap_height = uhdr_dec_get_gainmap_height(dec_handle);

    ALOGV("image dimensions %d x %d ", (int)width, (int)height);
    ALOGV("gainmap image dimensions %d x %d ", (int)gainmap_width, (int)gainmap_height);
    ALOGV("output color transfer %d ", (int)output_ct);
    ALOGV("max display boost %f ", (float)displayBoost);
    ALOGV("enable gpu %d ", (int)enableGpu);
    if (applyMirror) ALOGV("added mirror effect, direction %d", (int)direction);
    if (applyRotate) ALOGV("added rotate effect, degrees %d", (int)degrees);
    if (applyCrop)
      ALOGV("added crop effect, crop-left %d, crop-right %d, crop-top %d, crop-bottom %d", left,
            right, top, bottom);
    if (applyResize)
      ALOGV("added resize effect, resize wd %d, resize ht %d", resizeWidth, resizeHeight);

    uhdr_dec_get_exif(dec_handle);
    uhdr_dec_get_icc(dec_handle);
    uhdr_dec_get_base_image(dec_handle);
    uhdr_dec_get_gainmap_image(dec_handle);
    uhdr_dec_get_gainmap_metadata(dec_handle);
    uhdr_decode(dec_handle);
    uhdr_get_decoded_image(dec_handle);
    uhdr_get_decoded_gainmap_image(dec_handle);
    uhdr_reset_decoder(dec_handle);
    uhdr_release_decoder(dec_handle);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UltraHdrDecFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
