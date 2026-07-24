/*
 * Copyright 2026 The Android Open Source Project
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
#include <vector>
#include <memory>

#include "ultrahdr/editorhelper.h"
#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"

using namespace ultrahdr;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Limit image dimensions to avoid excessive memory allocation
  // Minimum 2x2 to avoid some immediate crashes in subsampled formats
  uint32_t width = fdp.ConsumeIntegralInRange<uint32_t>(2, 512);
  uint32_t height = fdp.ConsumeIntegralInRange<uint32_t>(2, 512);

  uhdr_img_fmt_t fmt = fdp.PickValueInArray(
      {UHDR_IMG_FMT_12bppYCbCr420, UHDR_IMG_FMT_8bppYCbCr400, UHDR_IMG_FMT_32bppRGBA8888,
       UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_IMG_FMT_32bppRGBA1010102, UHDR_IMG_FMT_24bppYCbCr444,
       UHDR_IMG_FMT_16bppYCbCr422, UHDR_IMG_FMT_16bppYCbCr440, UHDR_IMG_FMT_12bppYCbCr411,
       UHDR_IMG_FMT_10bppYCbCr410, UHDR_IMG_FMT_24bppRGB888, UHDR_IMG_FMT_30bppYCbCr444});

  // For some formats, width and height must be even
  if (fmt == UHDR_IMG_FMT_12bppYCbCr420 || fmt == UHDR_IMG_FMT_16bppYCbCr422 ||
      fmt == UHDR_IMG_FMT_16bppYCbCr440 || fmt == UHDR_IMG_FMT_12bppYCbCr411 ||
      fmt == UHDR_IMG_FMT_10bppYCbCr410) {
    width = (width >> 1) << 1;
    height = (height >> 1) << 1;
    if (width < 2) width = 2;
    if (height < 2) height = 2;
  }

  uhdr_color_gamut_t cg =
      fdp.PickValueInArray({UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100});

  uhdr_color_transfer_t ct =
      fdp.PickValueInArray({UHDR_CT_LINEAR, UHDR_CT_HLG, UHDR_CT_PQ, UHDR_CT_SRGB});

  uhdr_color_range_t range = fdp.PickValueInArray({UHDR_CR_LIMITED_RANGE, UHDR_CR_FULL_RANGE});

  // Create a raw image
  std::unique_ptr<uhdr_raw_image_ext_t> src_img;
  try {
    src_img = std::make_unique<uhdr_raw_image_ext_t>(fmt, cg, ct, range, width, height, 1);
  } catch (...) {
    return 0;
  }

  if (!src_img) return 0;

  // Fill ONLY the first plane to be safe, as we are fuzzed transformation logic
  if (src_img->planes[0] != nullptr) {
    // Very conservative fill
    size_t safe_size = src_img->stride[0] * src_img->h;
    if (fdp.remaining_bytes() > 0) {
      size_t to_fill = std::min(safe_size, fdp.remaining_bytes());
      std::vector<uint8_t> data_fill = fdp.ConsumeBytes<uint8_t>(to_fill);
      memcpy(src_img->planes[0], data_fill.data(), data_fill.size());
    }
  }

  int effect_type = fdp.ConsumeIntegralInRange<int>(0, 3);
  switch (effect_type) {
    case 0: {  // Rotate
      int degree = fdp.PickValueInArray({90, 180, 270});
      uhdr_rotate_effect_t desc(degree);
      apply_rotate(&desc, src_img.get());
      break;
    }
    case 1: {  // Mirror
      uhdr_mirror_direction_t dir =
          fdp.PickValueInArray({UHDR_MIRROR_HORIZONTAL, UHDR_MIRROR_VERTICAL});
      uhdr_mirror_effect_t desc(dir);
      apply_mirror(&desc, src_img.get());
      break;
    }
    case 2: {  // Resize
      uint32_t dst_w = fdp.ConsumeIntegralInRange<uint32_t>(2, 512);
      uint32_t dst_h = fdp.ConsumeIntegralInRange<uint32_t>(2, 512);
      // Ensure even for subsampled
      if (fmt == UHDR_IMG_FMT_12bppYCbCr420 || fmt == UHDR_IMG_FMT_16bppYCbCr422 ||
          fmt == UHDR_IMG_FMT_16bppYCbCr440 || fmt == UHDR_IMG_FMT_12bppYCbCr411 ||
          fmt == UHDR_IMG_FMT_10bppYCbCr410) {
        dst_w = (dst_w >> 1) << 1;
        dst_h = (dst_h >> 1) << 1;
        if (dst_w < 2) dst_w = 2;
        if (dst_h < 2) dst_h = 2;
      }
      uhdr_resize_effect_t desc(dst_w, dst_h);
      apply_resize(&desc, src_img.get(), dst_w, dst_h);
      break;
    }
    case 3: {  // Crop
      int left = fdp.ConsumeIntegralInRange<int>(0, width - 2);
      int top = fdp.ConsumeIntegralInRange<int>(0, height - 2);
      int wd = fdp.ConsumeIntegralInRange<int>(2, width - left);
      int ht = fdp.ConsumeIntegralInRange<int>(2, height - top);
      // Ensure even for subsampled
      if (fmt == UHDR_IMG_FMT_12bppYCbCr420 || fmt == UHDR_IMG_FMT_16bppYCbCr422 ||
          fmt == UHDR_IMG_FMT_16bppYCbCr440 || fmt == UHDR_IMG_FMT_12bppYCbCr411 ||
          fmt == UHDR_IMG_FMT_10bppYCbCr410) {
        left = (left >> 1) << 1;
        top = (top >> 1) << 1;
        wd = (wd >> 1) << 1;
        ht = (ht >> 1) << 1;
        if (wd < 2) wd = 2;
        if (ht < 2) ht = 2;
      }
      uhdr_crop_effect_t desc(left, left + wd, top, top + ht);
      apply_crop(&desc, src_img.get(), left, top, wd, ht);
      break;
    }
  }

  return 0;
}
