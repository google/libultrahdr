/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef ULTRAHDR_AGTM_H
#define ULTRAHDR_AGTM_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "ultrahdr_api.h"
#include "ultrahdr/gainmapmath.h"

namespace ultrahdr {

namespace smpte2094_50 {

/**
 * A 2D control point with an optional derivative slope `m` for SMPTE ST 2094-50 gain curves.
 */
struct ControlPoint {
  float x = 0.0f;  // Linear input luminance in SDR-relative units, in [0.0, 64.0].
  float y = 0.0f;  // Log2 gain value at `x`, in [-6.0, 6.0].
  float m = 0.0f;  // Derivative slope dy/dx at `x`, used when `use_pchip_slope` is false.

  bool operator==(const ControlPoint& other) const {
    return x == other.x && y == other.y && m == other.m;
  }
  bool operator!=(const ControlPoint& other) const { return !(*this == other); }
};

/**
 * Component mixing weights for SMPTE ST 2094-50 color gain evaluation (Clause 6.4).
 */
struct ComponentMix {
  std::array<float, 3> rgb = {0.0f, 0.0f, 0.0f};
  float max = 0.0f;
  float min = 0.0f;
  float component = 0.0f;

  bool operator==(const ComponentMix& other) const {
    return rgb == other.rgb && max == other.max && min == other.min &&
           component == other.component;
  }
  bool operator!=(const ComponentMix& other) const { return !(*this == other); }
};

/**
 * Alternate headroom tone-mapping rule in SMPTE ST 2094-50.
 */
struct ToneMappingRule {
  float alternate_hdr_headroom_log2 = 0.0f;  // In [0.0, 6.0].
  std::vector<ControlPoint> curve;           // 1 to 32 control points.
  bool use_pchip_slope = false;              // True to compute PCHIP slopes implicitly.
  ComponentMix mix{};
};

/**
 * Pure C++17 representation of SMPTE ST 2094-50:2026 Headroom Adaptive Gain Curves (HAGC / AGTM)
 * dynamic metadata.
 */
struct DynamicMetadata {
  static constexpr uint8_t kApplicationVersion = 0;
  static constexpr uint8_t kMinimumApplicationVersion = 0;
  static constexpr float kDefaultHdrReferenceWhite = 203.0f;
  static constexpr size_t kMaxNumAlternateImages = 4;
  static constexpr size_t kMaxNumControlPoints = 32;
  static constexpr size_t kNumMixCoefficients = 6;

  static constexpr std::array<float, 8> kChromaticitiesSrgb = {
      0.64f, 0.33f, 0.30f, 0.60f, 0.15f, 0.06f, 0.3127f, 0.3290f};
  static constexpr std::array<float, 8> kChromaticitiesDisplayP3 = {
      0.68f, 0.32f, 0.265f, 0.69f, 0.15f, 0.06f, 0.3127f, 0.3290f};
  static constexpr std::array<float, 8> kChromaticitiesRec2020 = {
      0.708f, 0.292f, 0.17f, 0.797f, 0.131f, 0.046f, 0.3127f, 0.3290f};

  float hdr_reference_white = kDefaultHdrReferenceWhite;
  bool has_adaptive_tone_map_flag = true;
  float baseline_hdr_headroom_log2 = 0.0f;
  bool use_reference_white_tone_mapping_flag = false;
  std::array<float, 8> gain_application_space_chromaticities = kChromaticitiesRec2020;
  std::vector<ToneMappingRule> rules;
};

/**
 * Computes Fritsch-Carlson PCHIP slopes according to SMPTE ST 2094-50 Annex C (Formulas C.7-C.10).
 */
uhdr_error_info_t computePchipSlopes(const std::vector<float>& x, const std::vector<float>& y,
                                     std::vector<float>& out_slopes);

/**
 * Piecewise Cubic Hermite Interpolating Polynomial (PCHIP) evaluator with flat boundary clamping.
 */
class PchipInterpolator {
 public:
  PchipInterpolator() = default;

  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  PchipInterpolator& out);
  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  const std::vector<float>& slopes, PchipInterpolator& out);

  float interpolate(float xi) const;
  bool reverseInterpolate(float yi, float& out_xi) const;

  const std::vector<float>& x() const { return mX; }
  const std::vector<float>& y() const { return mY; }
  const std::vector<float>& slopes() const { return mSlopes; }

 private:
  std::vector<float> mX;
  std::vector<float> mY;
  std::vector<float> mSlopes;
};

/**
 * SMPTE ST 2094-50 gain curve evaluator: PCHIP over [x_0, x_{N-1}], flat below x_0, and
 * y_{N-1} + log2(x_{N-1} / x) highlight roll-off above x_{N-1} (Formula 11).
 */
class GainCurve {
 public:
  GainCurve() = default;

  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  GainCurve& out);
  static uhdr_error_info_t create(const std::vector<float>& x, const std::vector<float>& y,
                                  const std::vector<float>& slopes, GainCurve& out);

  float interpolate(float xi) const;
  bool reverseInterpolate(float yi, float& out_xi) const;

  const PchipInterpolator& interpolator() const { return mInterp; }

 private:
  PchipInterpolator mInterp;
  float mYMin = 0.0f;
};

/**
 * Greedy error-minimizing PCHIP curve subsampler selecting at most `num_control_points` knots.
 */
uhdr_error_info_t createSubsampledPchip(const std::vector<float>& x, const std::vector<float>& y,
                                        size_t num_control_points, PchipInterpolator& out);

/**
 * Populates rules and slopes using the SMPTE ST 2094-50 Annex C.3.8 Reference White Tone Mapping
 * operator (RWTM).
 */
void populateUsingRwtm(DynamicMetadata& metadata);

/**
 * Populates RWTM rules (when `use_reference_white_tone_mapping_flag` is set) and computes PCHIP
 * slopes for all rules where `use_pchip_slope` is true.
 */
uhdr_error_info_t populateImplicitParameters(DynamicMetadata& metadata);

/**
 * Validates all normative SMPTE ST 2094-50 metadata and Annex C serialization constraints.
 */
uhdr_error_info_t validateDynamicMetadata(const DynamicMetadata& metadata);

/**
 * Serializes `metadata` into its SMPTE ST 2094-50 Annex C packed binary representation.
 */
uhdr_error_info_t encodeSt2094_50(const DynamicMetadata& metadata,
                                  std::vector<uint8_t>& out_bitstream);

/**
 * Parses a SMPTE ST 2094-50 Annex C binary payload into `out_metadata` and validates normative
 * constraints.
 */
uhdr_error_info_t parseSt2094_50(const uint8_t* data, size_t size, DynamicMetadata& out_metadata);

}  // namespace smpte2094_50

using HagcMetadata = smpte2094_50::DynamicMetadata;

/**
 * Generates a gain map from an image and SMPTE 2094-50 dynamic metadata.
 *
 * @param image The input HDR image.
 * @param metadata The SMPTE 2094-50 dynamic metadata.
 * @param gainmap_metadata Output gain map metadata.
 * @param gainmap_img Output gain map image.
 * @param hdr_capacity_max Maximum display boost value for which the map is applied completely.
 * @return UHDR_CODEC_OK on success, or an error code on failure.
 */
uhdr_error_info_t generateGainMap(uhdr_raw_image_t* image,
                                  const smpte2094_50::DynamicMetadata& metadata,
                                  uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                  std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                  float hdr_capacity_max = -1.0f);

}  // namespace ultrahdr

#endif  // ULTRAHDR_AGTM_H
