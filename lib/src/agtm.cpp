/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <algorithm>
#include <array>
#include <cmath>
#include <vector>

#include "ultrahdr/agtm.h"
#include "ultrahdr/gainmapmath.h"

#ifdef UHDR_ENABLE_SMPTE2094_50
#include "smpte2094_50/pchip.h"
#include "smpte2094_50/utils.h"

namespace ultrahdr {

static float applyMix(const Color& pixel, const smpte2094_50::ComponentMix& mix, float luma) {
  float k_sum = mix.rgb[0] + mix.rgb[1] + mix.rgb[2] + mix.component + mix.max + mix.min;
  if (k_sum == 0.0f) return luma;

  float x = mix.rgb[0] * pixel.r + mix.rgb[1] * pixel.g + mix.rgb[2] * pixel.b;
  x += mix.component * luma;
  if (mix.max > 0.0f) x += mix.max * std::max({pixel.r, pixel.g, pixel.b});
  if (mix.min > 0.0f) x += mix.min * std::min({pixel.r, pixel.g, pixel.b});

  return std::clamp(x, 0.0f, 1.0f);
}

uhdr_error_info_t generateGainMap(uhdr_raw_image_t* image,
                                  const smpte2094_50::DynamicMetadata& metadata,
                                  uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                  std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                  float hdr_capacity_max) {
  smpte2094_50::DynamicMetadata local_metadata = metadata;
  auto smpte_status = smpte2094_50::PopulateImplicitParameters(local_metadata);
  if (!smpte_status.ok()) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "SMPTE 2094-50 metadata error: %s",
             smpte_status.ToString().c_str());
    return status;
  }

  float max_headroom_log2 = local_metadata.baseline_hdr_headroom_log2;
  for (const auto& rule : local_metadata.rules) {
    max_headroom_log2 = std::max(max_headroom_log2, rule.alternate_hdr_headroom_log2);
  }

  if (hdr_capacity_max < 0.0f) hdr_capacity_max = exp2(max_headroom_log2);

  // Represents an evaluated curve at a specific target headroom.
  struct Evaluator {
    float H;
    smpte2094_50::ComponentMix mix;
    std::array<float, kGainFactorNumEntries> log2GainLUT;
    bool is_baseline;
  };

  std::vector<Evaluator> evaluators;
  Evaluator baseline;
  baseline.H = local_metadata.baseline_hdr_headroom_log2;
  baseline.is_baseline = true;
  baseline.log2GainLUT.fill(0.0f);
  evaluators.push_back(std::move(baseline));

  for (const auto& rule : local_metadata.rules) {
    Evaluator ev;
    ev.H = rule.alternate_hdr_headroom_log2;
    ev.is_baseline = false;
    ev.mix = rule.mix;

    std::vector<float> x, y;
    x.reserve(rule.curve.size());
    y.reserve(rule.curve.size());
    for (const auto& cp : rule.curve) {
      x.push_back(cp.x);
      y.push_back(cp.y);
    }
    auto result = smpte2094_50::GainCurve::Create(x, y);
    if (!result.ok()) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "Failed to create gain curve: %s",
               result.status().ToString().c_str());
      return status;
    }
    for (size_t i = 0; i < kGainFactorNumEntries; ++i) {
      float xi = static_cast<float>(i) / (kGainFactorNumEntries - 1);
      ev.log2GainLUT[i] = result->Interpolate(xi);
    }
    evaluators.push_back(std::move(ev));
  }

  // Sort evaluators by their targeting headroom for interpolation bounding.
  std::sort(evaluators.begin(), evaluators.end(),
            [](const Evaluator& a, const Evaluator& b) { return a.H < b.H; });

  float target_H = log2(hdr_capacity_max);
  if (target_H < evaluators.front().H) target_H = evaluators.front().H;
  if (target_H > evaluators.back().H) target_H = evaluators.back().H;

  size_t idx = 0;
  if (evaluators.size() > 1) {
    for (size_t i = 0; i < evaluators.size() - 1; ++i) {
      if (target_H >= evaluators[i].H && target_H <= evaluators[i + 1].H) {
        idx = i;
        break;
      }
    }
  }

  gainmap_metadata->hdr_capacity_min = 1.0f;
  gainmap_metadata->hdr_capacity_max = hdr_capacity_max;
  for (int i = 0; i < 3; i++) {
    gainmap_metadata->min_content_boost[i] = 1.0f;
    gainmap_metadata->max_content_boost[i] = gainmap_metadata->hdr_capacity_max;
    gainmap_metadata->gamma[i] = 1.0f;
    gainmap_metadata->offset_sdr[i] = 0.0f;
    gainmap_metadata->offset_hdr[i] = 0.0f;
  }

  std::array<float, 3> log2MinBoost;
  std::array<float, 3> log2MaxBoost;
  for (int i = 0; i < 3; i++) {
    log2MinBoost[i] = log2(gainmap_metadata->min_content_boost[i]);
    log2MaxBoost[i] = log2(gainmap_metadata->max_content_boost[i]);
    if (fabs(log2MaxBoost[i] - log2MinBoost[i]) < FLT_EPSILON) {
      log2MaxBoost[i] += 0.0001f;
    }
  }

  gainmap_img = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppRGB888, image->cg, image->ct,
                                                      image->range, image->w, image->h, 64);

  SamplePixelFn sample_pixel_fn = getSamplePixelFn(image->fmt);
  LuminanceFn luminance_fn = getLuminanceFn(image->cg);
  ColorTransformFn yuv_to_rgb_fn = getYuvToRgbFn(image->cg);

  const bool is_rgb = isPixelFormatRgb(image->fmt);

  for (unsigned int y = 0; y < image->h; ++y) {
    for (unsigned int x = 0; x < image->w; ++x) {
      Color pixel = sample_pixel_fn(image, 1, x, y);
      if (!is_rgb && yuv_to_rgb_fn != nullptr) {
        pixel = yuv_to_rgb_fn(pixel);
      }
      float luma = luminance_fn(pixel);

      float logGain = 0.0f;
      if (evaluators.size() > 1) {
        const Evaluator& ev0 = evaluators[idx];
        const Evaluator& ev1 = evaluators[idx + 1];
        float w1 = (ev1.H == ev0.H) ? 0.0f : (target_H - ev0.H) / (ev1.H - ev0.H);
        float w0 = 1.0f - w1;

        float gy0 = 0.0f;
        if (!ev0.is_baseline) {
          float x0 = applyMix(pixel, ev0.mix, luma);
          int32_t i0 = static_cast<int32_t>(x0 * (kGainFactorNumEntries - 1) + 0.5);
          gy0 = ev0.log2GainLUT[CLIP3(i0, 0, kGainFactorNumEntries - 1)];
        }

        float gy1 = 0.0f;
        if (!ev1.is_baseline) {
          float x1 = applyMix(pixel, ev1.mix, luma);
          int32_t i1 = static_cast<int32_t>(x1 * (kGainFactorNumEntries - 1) + 0.5);
          gy1 = ev1.log2GainLUT[CLIP3(i1, 0, kGainFactorNumEntries - 1)];
        }
        logGain = w0 * gy0 + w1 * gy1;
      } else {
        const Evaluator& ev0 = evaluators[0];
        if (!ev0.is_baseline) {
          float x0 = applyMix(pixel, ev0.mix, luma);
          int32_t i0 = static_cast<int32_t>(x0 * (kGainFactorNumEntries - 1) + 0.5);
          logGain = ev0.log2GainLUT[CLIP3(i0, 0, kGainFactorNumEntries - 1)];
        }
      }

      size_t pixel_idx = (x + y * gainmap_img->stride[UHDR_PLANE_PACKED]) * 3;
      uint8_t* out_ptr =
          reinterpret_cast<uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]) + pixel_idx;

      for (int c = 0; c < 3; c++) {
        out_ptr[c] = affineMapGain(logGain, log2MinBoost[c], log2MaxBoost[c],
                                   gainmap_metadata->gamma[c]);
      }
    }
  }

  return g_no_error;
}

}  // namespace ultrahdr
#endif
