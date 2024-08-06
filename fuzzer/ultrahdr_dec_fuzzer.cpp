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
#include <iostream>
#include <memory>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"

using namespace ultrahdr;

// Transfer functions for image data, sync with ultrahdr.h
constexpr int kTfMin = UHDR_CT_UNSPECIFIED + 1;
constexpr int kTfMax = UHDR_CT_PQ;

class UltraHdrDecFuzzer {
 public:
  UltraHdrDecFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
  void process();

 private:
  FuzzedDataProvider mFdp;
};

void UltraHdrDecFuzzer::process() {
  // hdr_of
  auto tf = static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
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
  uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
  if (dec_handle) {
    ON_ERR(uhdr_dec_set_image(dec_handle, &jpegImgR))
    ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, tf))
    if (tf == UHDR_CT_LINEAR)
      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
    else if (tf == UHDR_CT_SRGB)
      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
    else
      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
    uhdr_dec_probe(dec_handle);
    uhdr_dec_get_image_width(dec_handle);
    uhdr_dec_get_image_height(dec_handle);
    uhdr_dec_get_gainmap_width(dec_handle);
    uhdr_dec_get_gainmap_height(dec_handle);
    uhdr_dec_get_exif(dec_handle);
    uhdr_dec_get_icc(dec_handle);
    uhdr_dec_get_gain_map_metadata(dec_handle);
    uhdr_decode(dec_handle);
    uhdr_get_decoded_image(dec_handle);
    uhdr_get_gain_map_image(dec_handle);
    uhdr_release_decoder(dec_handle);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UltraHdrDecFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
