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

#include "ultrahdr/gainmapmath.h"

using namespace ultrahdr;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  Color color;
  color.r = fdp.ConsumeFloatingPoint<float>();
  color.g = fdp.ConsumeFloatingPoint<float>();
  color.b = fdp.ConsumeFloatingPoint<float>();

  // Test various color transformations
  (void)srgbLuminance(color);
  (void)srgbRgbToYuv(color);
  (void)srgbYuvToRgb(color);
  (void)srgbInvOetf(color.r);
  (void)srgbOetf(color.r);

  (void)p3Luminance(color);
  (void)p3RgbToYuv(color);
  (void)p3YuvToRgb(color);

  (void)bt2100Luminance(color);
  (void)bt2100RgbToYuv(color);
  (void)bt2100YuvToRgb(color);

  (void)hlgOetf(color.r);
  (void)hlgInvOetf(color.r);
  (void)pqOetf(color.r);
  (void)pqInvOetf(color.r);

  // Test gain map calculations
  uhdr_gainmap_metadata_ext_t metadata;
  for (int i = 0; i < 3; i++) {
    metadata.max_content_boost[i] = fdp.ConsumeFloatingPointInRange<float>(1.0f, 10.0f);
    metadata.min_content_boost[i] = fdp.ConsumeFloatingPointInRange<float>(0.1f, 1.0f);
    metadata.gamma[i] = fdp.ConsumeFloatingPointInRange<float>(0.1f, 10.0f);
    metadata.offset_sdr[i] = fdp.ConsumeFloatingPoint<float>();
    metadata.offset_hdr[i] = fdp.ConsumeFloatingPoint<float>();
  }
  metadata.hdr_capacity_min = fdp.ConsumeFloatingPointInRange<float>(1.0f, 2.0f);
  metadata.hdr_capacity_max = fdp.ConsumeFloatingPointInRange<float>(2.0f, 10.0f);
  metadata.use_base_cg = fdp.ConsumeBool();

  float gain = fdp.ConsumeFloatingPoint<float>();
  (void)applyGain(color, gain, &metadata);

  Color gainColor;
  gainColor.r = fdp.ConsumeFloatingPoint<float>();
  gainColor.g = fdp.ConsumeFloatingPoint<float>();
  gainColor.b = fdp.ConsumeFloatingPoint<float>();
  (void)applyGain(color, gainColor, &metadata);

  (void)encodeGain(color.r, color.g, &metadata, 0);

  // Test common utils
  (void)floatToHalf(color.r);
  (void)halfToFloat(fdp.ConsumeIntegral<uint16_t>());

  int32_t n;
  uint32_t d;
  (void)floatToSignedFraction(color.r, &n, &d);
  (void)floatToUnsignedFraction(color.r, (uint32_t*)&n, &d);

  return 0;
}
