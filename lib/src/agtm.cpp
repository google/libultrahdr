/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include "ultrahdr/agtm.h"

#include <algorithm>
#include <array>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include "ultrahdr/gainmapmath.h"

namespace ultrahdr {

namespace smpte2094_50 {

namespace {

constexpr float kPi = 3.14159265358979323846f;
constexpr float kLn2 = 0.69314718055994530942f;
constexpr float kMixParamScale = 50000.0f;
constexpr size_t kMaxAnnexCBytes = 1024;

uhdr_error_info_t makeError(uhdr_codec_err_t code, const char* msg) {
  uhdr_error_info_t status;
  status.error_code = code;
  status.has_detail = 1;
  std::snprintf(status.detail, sizeof(status.detail), "%s", msg);
  return status;
}

uint16_t floatToUint16(float v, uint16_t clamp_min, uint16_t clamp_max, uint16_t offset,
                       float scale) {
  const long rounded = std::lround(static_cast<double>(v) * static_cast<double>(scale)) +
                       static_cast<long>(offset);
  const long clamped =
      std::clamp(rounded, static_cast<long>(clamp_min), static_cast<long>(clamp_max));
  return static_cast<uint16_t>(clamped);
}

float uint16ToFloat(uint16_t v, uint16_t clamp_min, uint16_t clamp_max, uint16_t offset,
                    float scale) {
  const uint16_t clamped = std::clamp(v, clamp_min, clamp_max);
  return static_cast<float>(static_cast<int32_t>(clamped) - static_cast<int32_t>(offset)) / scale;
}

bool inClosedInterval(float x, float lo, float hi) { return std::isfinite(x) && x >= lo && x <= hi; }

float threePointFiniteDifference(float h0, float h1, float s0, float s1) {
  if (s0 == 0.0f) {
    return 0.0f;
  }
  const float num = (2.0f * h0 + h1) * s0 - h0 * s1;
  const float den = h0 + h1;
  float m = num / den;
  if (std::signbit(m) != std::signbit(s0)) {
    m = 0.0f;
  } else if (s1 != 0.0f && std::signbit(m) != std::signbit(s1) &&
             std::fabs(m) > 3.0f * std::fabs(s0)) {
    m = 3.0f * s0;
  }
  return m;
}

uint8_t getChromaticitiesMode(const std::array<float, 8>& chrom) {
  if (chrom == DynamicMetadata::kChromaticitiesSrgb) return 0;
  if (chrom == DynamicMetadata::kChromaticitiesDisplayP3) return 1;
  if (chrom == DynamicMetadata::kChromaticitiesRec2020) return 2;
  return 3;
}

struct EncodedMix {
  uint8_t type = 3;
  std::array<uint8_t, DynamicMetadata::kNumMixCoefficients> flags = {0, 0, 0, 0, 0, 0};
  std::array<uint16_t, DynamicMetadata::kNumMixCoefficients> coeffs = {0, 0, 0, 0, 0, 0};

  bool operator==(const EncodedMix& other) const {
    return type == other.type && flags == other.flags && coeffs == other.coeffs;
  }
};

EncodedMix encodeComponentMix(const ComponentMix& mix) {
  EncodedMix enc;
  if (mix.rgb[0] == 0.0f && mix.rgb[1] == 0.0f && mix.rgb[2] == 0.0f && mix.max == 1.0f &&
      mix.min == 0.0f && mix.component == 0.0f) {
    enc.type = 0;
    return enc;
  }
  if (mix.rgb[0] == 0.0f && mix.rgb[1] == 0.0f && mix.rgb[2] == 0.0f && mix.max == 0.0f &&
      mix.min == 0.0f && mix.component == 1.0f) {
    enc.type = 1;
    return enc;
  }
  constexpr float kOneSixth = 1.0f / 6.0f;
  if (std::fabs(mix.rgb[0] - kOneSixth) <= 1e-6f && std::fabs(mix.rgb[1] - kOneSixth) <= 1e-6f &&
      std::fabs(mix.rgb[2] - kOneSixth) <= 1e-6f && mix.max == 0.5f && mix.min == 0.0f &&
      mix.component == 0.0f) {
    enc.type = 2;
    return enc;
  }

  enc.type = 3;
  const std::array<float, DynamicMetadata::kNumMixCoefficients> raw = {
      mix.rgb[0], mix.rgb[1], mix.rgb[2], mix.max, mix.min, mix.component};
  float max_c = 0.0f;
  for (float v : raw) {
    max_c = std::max(max_c, v);
  }
  if (max_c > 0.0f) {
    for (size_t k = 0; k < DynamicMetadata::kNumMixCoefficients; ++k) {
      const uint16_t q = floatToUint16(raw[k] / max_c, 0u, 50000u, 0u, kMixParamScale);
      enc.coeffs[k] = q;
      enc.flags[k] = (q != 0u) ? 1u : 0u;
    }
  }
  return enc;
}

/**
 * Fixed-capacity stack bit writer for SMPTE ST 2094-50 Annex C (max valid bitstream < 860 bytes).
 * Avoids std::vector::push_back reallocation patterns that trigger GCC 15 -Wfree-nonheap-object.
 */
class AnnexCBitWriter {
 public:
  bool writeBits(uint16_t value, int num_bits) {
    if (num_bits <= 0) return true;
    const uint64_t mask = (num_bits == 64) ? ~0ULL : ((1ULL << num_bits) - 1ULL);
    mBitBuffer = (mBitBuffer << num_bits) | (static_cast<uint64_t>(value) & mask);
    mBitCount += num_bits;
    while (mBitCount >= 8) {
      if (mByteLen >= mBuf.size()) return false;
      mBuf[mByteLen++] = static_cast<uint8_t>((mBitBuffer >> (mBitCount - 8)) & 0xFFu);
      mBitCount -= 8;
    }
    return true;
  }

  bool writeBit(bool bit) { return writeBits(bit ? 1u : 0u, 1); }

  bool writeU16BE(uint16_t value) { return writeBits(value, 16); }

  bool finish(std::vector<uint8_t>& out) {
    if (mBitCount > 0) {
      if (mByteLen >= mBuf.size()) return false;
      mBuf[mByteLen++] = static_cast<uint8_t>((mBitBuffer << (8 - mBitCount)) & 0xFFu);
      mBitBuffer = 0;
      mBitCount = 0;
    }
    out.assign(mBuf.data(), mBuf.data() + mByteLen);
    return true;
  }

 private:
  std::array<uint8_t, kMaxAnnexCBytes> mBuf{};
  size_t mByteLen = 0;
  uint64_t mBitBuffer = 0;
  int mBitCount = 0;
};

class AnnexCBitReader {
 public:
  AnnexCBitReader(const uint8_t* data, size_t size) : mData(data), mSize(size) {}

  bool readBits(int num_bits, uint32_t& out) {
    uint32_t val = 0;
    for (int b = 0; b < num_bits; ++b) {
      if (mBytePos >= mSize) return false;
      const uint8_t byte = mData[mBytePos];
      val = (val << 1) | static_cast<uint32_t>((byte >> (7 - mBitPos)) & 1u);
      ++mBitPos;
      if (mBitPos == 8) {
        ++mBytePos;
        mBitPos = 0;
      }
    }
    out = val;
    return true;
  }

  bool readBit(bool& out) {
    uint32_t v = 0;
    if (!readBits(1, v)) return false;
    out = (v != 0u);
    return true;
  }

  bool readU16BE(uint16_t& out) {
    uint32_t v = 0;
    if (!readBits(16, v)) return false;
    out = static_cast<uint16_t>(v);
    return true;
  }

 private:
  const uint8_t* mData = nullptr;
  size_t mSize = 0;
  size_t mBytePos = 0;
  int mBitPos = 0;
};

}  // namespace

uhdr_error_info_t computePchipSlopes(const std::vector<float>& x, const std::vector<float>& y,
                                     std::vector<float>& out_slopes) {
  if (x.size() != y.size()) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "PCHIP x and y vectors must have equal length");
  }
  const size_t n = x.size();
  for (size_t i = 0; i < n; ++i) {
    if (!std::isfinite(x[i]) || !std::isfinite(y[i])) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "PCHIP control points must be finite");
    }
    if (i + 1 < n && x[i + 1] < x[i]) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "PCHIP x values must be non-decreasing");
    }
  }

  if (n <= 1) {
    out_slopes.assign(n, 0.0f);
    return g_no_error;
  }

  std::vector<float> h(n - 1, 0.0f);
  std::vector<float> s(n - 1, 0.0f);
  for (size_t i = 0; i < n - 1; ++i) {
    h[i] = x[i + 1] - x[i];
    s[i] = (h[i] != 0.0f) ? ((y[i + 1] - y[i]) / h[i]) : 0.0f;
  }

  out_slopes.assign(n, 0.0f);
  if (n == 2) {
    out_slopes[0] = s[0];
    out_slopes[1] = s[0];
    return g_no_error;
  }

  for (size_t i = 0; i < n; ++i) {
    if (i > 0 && i + 1 < n && h[i - 1] > 0.0f && h[i] > 0.0f) {
      if (s[i - 1] == 0.0f || s[i] == 0.0f || std::signbit(s[i - 1]) != std::signbit(s[i])) {
        out_slopes[i] = 0.0f;
      } else {
        const float num = 3.0f * (h[i - 1] + h[i]) * s[i - 1] * s[i];
        const float den = (2.0f * h[i - 1] + h[i]) * s[i - 1] + (h[i - 1] + 2.0f * h[i]) * s[i];
        out_slopes[i] = num / den;
      }
    } else if (i + 1 < n && h[i] > 0.0f) {
      if (i + 2 < n && h[i + 1] > 0.0f) {
        out_slopes[i] = threePointFiniteDifference(h[i], h[i + 1], s[i], s[i + 1]);
      } else {
        out_slopes[i] = s[i];
      }
    } else if (i > 0 && h[i - 1] > 0.0f) {
      if (i > 1 && h[i - 2] > 0.0f) {
        out_slopes[i] = threePointFiniteDifference(h[i - 1], h[i - 2], s[i - 1], s[i - 2]);
      } else {
        out_slopes[i] = s[i - 1];
      }
    } else {
      out_slopes[i] = 0.0f;
    }
  }

  return g_no_error;
}

uhdr_error_info_t PchipInterpolator::create(const std::vector<float>& x,
                                            const std::vector<float>& y, PchipInterpolator& out) {
  std::vector<float> slopes;
  uhdr_error_info_t status = computePchipSlopes(x, y, slopes);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }
  return create(x, y, slopes, out);
}

uhdr_error_info_t PchipInterpolator::create(const std::vector<float>& x,
                                            const std::vector<float>& y,
                                            const std::vector<float>& slopes,
                                            PchipInterpolator& out) {
  if (x.size() != y.size() || x.size() != slopes.size()) {
    return makeError(UHDR_CODEC_INVALID_PARAM,
                     "PchipInterpolator x, y, and slopes must have equal length");
  }
  for (size_t i = 0; i < x.size(); ++i) {
    if (!std::isfinite(x[i]) || !std::isfinite(y[i]) || !std::isfinite(slopes[i])) {
      return makeError(UHDR_CODEC_INVALID_PARAM,
                       "PchipInterpolator control points and slopes must be finite");
    }
    if (i + 1 < x.size() && x[i + 1] < x[i]) {
      return makeError(UHDR_CODEC_INVALID_PARAM,
                       "PchipInterpolator x values must be non-decreasing");
    }
  }
  out.mX = x;
  out.mY = y;
  out.mSlopes = slopes;
  return g_no_error;
}

float PchipInterpolator::interpolate(float xi) const {
  if (mX.empty()) {
    return 0.0f;
  }
  const auto it = std::upper_bound(mX.begin(), mX.end(), xi);
  if (it == mX.begin()) {
    return mY.front();
  }
  if (it == mX.end()) {
    return mY.back();
  }

  const size_t i = static_cast<size_t>(std::distance(mX.begin(), it)) - 1;
  const float x0 = mX[i];
  const float x1 = mX[i + 1];
  const float y0 = mY[i];
  const float y1 = mY[i + 1];
  const float h = x1 - x0;
  if (h == 0.0f) {
    return y0;
  }

  const float m0 = mSlopes[i];
  const float m1 = mSlopes[i + 1];
  const float t = (xi - x0) / h;
  const float omt = 1.0f - t;

  const float h00 = (1.0f + 2.0f * t) * omt * omt;
  const float h10 = t * omt * omt;
  const float h01 = t * t * (3.0f - 2.0f * t);
  const float h11 = t * t * (t - 1.0f);

  return h00 * y0 + h10 * h * m0 + h01 * y1 + h11 * h * m1;
}

bool PchipInterpolator::reverseInterpolate(float yi, float& out_xi) const {
  if (mX.size() < 2) {
    out_xi = mX.empty() ? 0.0f : mX.front();
    return false;
  }

  float min_y = mY[0];
  float max_y = mY[0];
  size_t min_idx = 0;
  size_t max_idx = 0;
  for (size_t i = 1; i < mY.size(); ++i) {
    if (mY[i] < min_y) {
      min_y = mY[i];
      min_idx = i;
    }
    if (mY[i] > max_y) {
      max_y = mY[i];
      max_idx = i;
    }
  }

  if (yi <= min_y) {
    out_xi = mX[min_idx];
    return yi == min_y;
  }
  if (yi >= max_y) {
    out_xi = mX[max_idx];
    return yi == max_y;
  }

  for (size_t i = 0; i + 1 < mX.size(); ++i) {
    const float y0 = mY[i];
    const float y1 = mY[i + 1];
    if ((y0 <= yi && yi <= y1) || (y1 <= yi && yi <= y0)) {
      float low = mX[i];
      float high = mX[i + 1];
      if (std::fabs(yi - y0) < 1e-9f) {
        out_xi = low;
        return true;
      }
      if (std::fabs(yi - y1) < 1e-9f) {
        out_xi = high;
        return true;
      }

      const bool increasing = (y0 <= y1);
      for (int step = 0; step < 20; ++step) {
        const float mid_x = low + 0.5f * (high - low);
        if (interpolate(mid_x) < yi) {
          if (increasing) {
            low = mid_x;
          } else {
            high = mid_x;
          }
        } else {
          if (increasing) {
            high = mid_x;
          } else {
            low = mid_x;
          }
        }
      }
      out_xi = low + 0.5f * (high - low);
      return true;
    }
  }

  out_xi = mX.back();
  return false;
}

uhdr_error_info_t GainCurve::create(const std::vector<float>& x, const std::vector<float>& y,
                                    GainCurve& out) {
  uhdr_error_info_t status = PchipInterpolator::create(x, y, out.mInterp);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }
  out.mYMin = 0.0f;
  if (!y.empty()) {
    out.mYMin = *std::min_element(y.begin(), y.end());
  }
  return g_no_error;
}

uhdr_error_info_t GainCurve::create(const std::vector<float>& x, const std::vector<float>& y,
                                    const std::vector<float>& slopes, GainCurve& out) {
  uhdr_error_info_t status = PchipInterpolator::create(x, y, slopes, out.mInterp);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }
  out.mYMin = 0.0f;
  if (!y.empty()) {
    out.mYMin = *std::min_element(y.begin(), y.end());
  }
  return g_no_error;
}

float GainCurve::interpolate(float xi) const {
  if (!mInterp.x().empty()) {
    const float x_back = mInterp.x().back();
    const float y_back = mInterp.y().back();
    if (xi > x_back && x_back > 0.0f) {
      return y_back + std::log2(x_back / xi);
    }
  }
  return mInterp.interpolate(xi);
}

bool GainCurve::reverseInterpolate(float yi, float& out_xi) const {
  if (!mInterp.x().empty()) {
    const float x_back = mInterp.x().back();
    const float y_back = mInterp.y().back();
    if (yi < mYMin && yi < y_back && x_back > 0.0f) {
      out_xi = x_back * std::exp2(y_back - yi);
      return true;
    }
  }
  return mInterp.reverseInterpolate(yi, out_xi);
}

uhdr_error_info_t createSubsampledPchip(const std::vector<float>& x, const std::vector<float>& y,
                                        size_t num_control_points, PchipInterpolator& out) {
  if (x.size() != y.size() || x.empty() || num_control_points == 0) {
    return makeError(UHDR_CODEC_INVALID_PARAM,
                     "Invalid input points or num_control_points for createSubsampledPchip");
  }
  for (size_t i = 0; i < x.size(); ++i) {
    if (!std::isfinite(x[i]) || !std::isfinite(y[i])) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "Control points must be finite");
    }
    if (i + 1 < x.size() && x[i + 1] < x[i]) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "x values must be non-decreasing");
    }
  }

  std::vector<float> unique_x;
  std::vector<float> unique_y;
  unique_x.push_back(x[0]);
  unique_y.push_back(y[0]);
  for (size_t i = 1; i < x.size(); ++i) {
    if (x[i] > unique_x.back()) {
      unique_x.push_back(x[i]);
      unique_y.push_back(y[i]);
    } else {
      unique_y.back() = y[i];
    }
  }

  const size_t n = unique_x.size();
  std::vector<bool> selected_mask(n, false);
  selected_mask[0] = true;
  if (n > 1 && num_control_points > 1) {
    selected_mask[n - 1] = true;
  }

  const size_t extra_knots = (num_control_points > 2) ? (num_control_points - 2) : 0;
  for (size_t k = 0; k < extra_knots; ++k) {
    std::vector<float> cur_x;
    std::vector<float> cur_y;
    for (size_t j = 0; j < n; ++j) {
      if (selected_mask[j]) {
        cur_x.push_back(unique_x[j]);
        cur_y.push_back(unique_y[j]);
      }
    }
    PchipInterpolator interp;
    uhdr_error_info_t status = PchipInterpolator::create(cur_x, cur_y, interp);
    if (status.error_code != UHDR_CODEC_OK) {
      return status;
    }

    float max_err = -1.0f;
    size_t best_idx = n;
    for (size_t j = 0; j < n; ++j) {
      if (!selected_mask[j]) {
        const float err = std::fabs(interp.interpolate(unique_x[j]) - unique_y[j]);
        if (err > max_err) {
          max_err = err;
          best_idx = j;
        }
      }
    }
    if (best_idx < n) {
      selected_mask[best_idx] = true;
    } else {
      break;
    }
  }

  std::vector<float> sel_x;
  std::vector<float> sel_y;
  for (size_t j = 0; j < n; ++j) {
    if (selected_mask[j]) {
      sel_x.push_back(unique_x[j]);
      sel_y.push_back(unique_y[j]);
    }
  }
  return PchipInterpolator::create(sel_x, sel_y, out);
}

void populateUsingRwtm(DynamicMetadata& metadata) {
  metadata.has_adaptive_tone_map_flag = true;
  metadata.use_reference_white_tone_mapping_flag = true;
  metadata.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesRec2020;

  if (metadata.baseline_hdr_headroom_log2 == 0.0f) {
    metadata.rules.clear();
    return;
  }

  const float ref_ratio =
      std::min(metadata.baseline_hdr_headroom_log2 / std::log2(1000.0f / 203.0f), 1.0f);

  metadata.rules.assign(2, ToneMappingRule{});
  metadata.rules[0].alternate_hdr_headroom_log2 = 0.0f;
  metadata.rules[1].alternate_hdr_headroom_log2 = std::log2(8.0f / 3.0f) * ref_ratio;

  for (size_t a = 0; a < metadata.rules.size(); ++a) {
    ToneMappingRule& rule = metadata.rules[a];
    rule.mix = ComponentMix{};
    rule.mix.max = 1.0f;

    const float y_white = (a == 1) ? 1.0f : (1.0f - 0.5f * ref_ratio);
    constexpr float kappa = 0.65f;
    const float x_knee = 1.0f;
    const float y_knee = y_white;
    const float x_max = std::exp2(metadata.baseline_hdr_headroom_log2);
    const float y_max = std::exp2(rule.alternate_hdr_headroom_log2);
    const float x_mid = (1.0f - kappa) * x_knee + kappa * (x_knee * y_max / y_knee);
    const float y_mid = (1.0f - kappa) * y_knee + kappa * y_max;

    const float a_x = x_knee - 2.0f * x_mid + x_max;
    const float a_y = y_knee - 2.0f * y_mid + y_max;
    const float b_x = 2.0f * x_mid - 2.0f * x_knee;
    const float b_y = 2.0f * y_mid - 2.0f * y_knee;
    const float c_x = x_knee;
    const float c_y = y_knee;

    rule.curve.assign(8, ControlPoint{});
    rule.use_pchip_slope = false;
    for (size_t c = 0; c < 8; ++c) {
      const float t = static_cast<float>(c) / 7.0f;
      const float lin_x = c_x + t * (b_x + t * a_x);
      const float lin_y = c_y + t * (b_y + t * a_y);
      const float lin_m = (2.0f * a_y * t + b_y) / (2.0f * a_x * t + b_x);

      rule.curve[c].x = lin_x;
      rule.curve[c].y = std::log2(lin_y / lin_x);
      rule.curve[c].m = (lin_x * lin_m - lin_y) / (lin_x * lin_y * kLn2);
    }
  }
}

uhdr_error_info_t populateImplicitParameters(DynamicMetadata& metadata) {
  if (metadata.use_reference_white_tone_mapping_flag) {
    populateUsingRwtm(metadata);
  }
  for (ToneMappingRule& rule : metadata.rules) {
    if (rule.curve.empty() || !rule.use_pchip_slope) {
      continue;
    }
    std::vector<float> cp_x(rule.curve.size());
    std::vector<float> cp_y(rule.curve.size());
    for (size_t i = 0; i < rule.curve.size(); ++i) {
      cp_x[i] = rule.curve[i].x;
      cp_y[i] = rule.curve[i].y;
    }
    std::vector<float> slopes;
    uhdr_error_info_t status = computePchipSlopes(cp_x, cp_y, slopes);
    if (status.error_code != UHDR_CODEC_OK) {
      return status;
    }
    for (size_t i = 0; i < rule.curve.size(); ++i) {
      rule.curve[i].m = slopes[i];
    }
    rule.use_pchip_slope = false;
  }
  return g_no_error;
}

uhdr_error_info_t validateDynamicMetadata(const DynamicMetadata& metadata) {
  if (!std::isfinite(metadata.hdr_reference_white) || metadata.hdr_reference_white <= 0.0f ||
      metadata.hdr_reference_white > 10000.0f) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "hdr_reference_white must be in (0, 10000]");
  }
  if (floatToUint16(metadata.hdr_reference_white, 0u, 50000u, 0u, 5.0f) == 0u) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "hdr_reference_white quantizes to 0");
  }

  if (!metadata.has_adaptive_tone_map_flag) {
    return g_no_error;
  }

  if (!inClosedInterval(metadata.baseline_hdr_headroom_log2, 0.0f, 6.0f)) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "baseline_hdr_headroom_log2 must be in [0, 6]");
  }

  if (metadata.use_reference_white_tone_mapping_flag) {
    return g_no_error;
  }

  if (metadata.rules.size() > DynamicMetadata::kMaxNumAlternateImages) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "num_alternate_images must not exceed 4");
  }

  // Validate chromaticities (Clause 6.2.2): unit interval, non-zero RGB triangle area, and
  // strictly interior white point after Annex C quantization.
  std::array<float, 8> q_chrom{};
  for (size_t r = 0; r < 8; ++r) {
    if (!inClosedInterval(metadata.gain_application_space_chromaticities[r], 0.0f, 1.0f)) {
      return makeError(UHDR_CODEC_INVALID_PARAM,
                       "gain_application_space_chromaticities must be in [0, 1]");
    }
    const uint16_t raw = floatToUint16(metadata.gain_application_space_chromaticities[r], 0u,
                                       50000u, 0u, kMixParamScale);
    q_chrom[r] = uint16ToFloat(raw, 0u, 50000u, 0u, kMixParamScale);
  }
  const float xr = q_chrom[0], yr = q_chrom[1];
  const float xg = q_chrom[2], yg = q_chrom[3];
  const float xb = q_chrom[4], yb = q_chrom[5];
  const float xw = q_chrom[6], yw = q_chrom[7];
  const float det = (yg - yb) * (xr - xb) + (xb - xg) * (yr - yb);
  if (std::fabs(det) <= 1e-12f) {
    return makeError(UHDR_CODEC_INVALID_PARAM,
                     "gain_application_space_chromaticities form a degenerate RGB triangle");
  }
  const float l1 = ((yg - yb) * (xw - xb) + (xb - xg) * (yw - yb)) / det;
  const float l2 = ((yb - yr) * (xw - xb) + (xr - xb) * (yw - yb)) / det;
  const float l3 = 1.0f - l1 - l2;
  if (l1 <= 0.0f || l2 <= 0.0f || l3 <= 0.0f) {
    return makeError(UHDR_CODEC_INVALID_PARAM,
                     "White point lies outside gain_application_space_chromaticities triangle");
  }

  const uint16_t enc_baseline =
      floatToUint16(metadata.baseline_hdr_headroom_log2, 0u, 60000u, 0u, 10000.0f);
  uint16_t prev_enc_alt = 0;

  for (size_t a = 0; a < metadata.rules.size(); ++a) {
    const ToneMappingRule& rule = metadata.rules[a];
    if (!inClosedInterval(rule.alternate_hdr_headroom_log2, 0.0f, 6.0f)) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "alternate_hdr_headroom_log2 must be in [0, 6]");
    }
    const uint16_t enc_alt =
        floatToUint16(rule.alternate_hdr_headroom_log2, 0u, 60000u, 0u, 10000.0f);
    if (enc_alt == enc_baseline ||
        rule.alternate_hdr_headroom_log2 == metadata.baseline_hdr_headroom_log2) {
      return makeError(UHDR_CODEC_INVALID_PARAM,
                       "alternate_hdr_headroom_log2 must not equal baseline_hdr_headroom_log2");
    }
    if (a > 0 && (enc_alt <= prev_enc_alt ||
                  rule.alternate_hdr_headroom_log2 <=
                      metadata.rules[a - 1].alternate_hdr_headroom_log2)) {
      return makeError(UHDR_CODEC_INVALID_PARAM,
                       "alternate_hdr_headroom_log2 values must be strictly ascending");
    }
    prev_enc_alt = enc_alt;

    // Validate ComponentMix (Clause 6.4.2).
    const std::array<float, DynamicMetadata::kNumMixCoefficients> mix_vals = {
        rule.mix.rgb[0], rule.mix.rgb[1], rule.mix.rgb[2],
        rule.mix.max,    rule.mix.min,    rule.mix.component};
    float mix_sum = 0.0f;
    for (float mv : mix_vals) {
      if (!inClosedInterval(mv, 0.0f, 1.0f)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "ComponentMix weights must be in [0, 1]");
      }
      mix_sum += mv;
    }
    if (mix_sum <= 0.0f) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "ComponentMix weights must sum to > 0");
    }
    const EncodedMix enc_mix = encodeComponentMix(rule.mix);
    if (enc_mix.type == 3) {
      uint32_t q_sum = 0;
      for (uint16_t qc : enc_mix.coeffs) q_sum += qc;
      if (q_sum == 0u) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Quantized ComponentMix weights sum to 0");
      }
    }

    // Validate GainCurve (Clauses 6.2.3 & 6.5.2).
    if (rule.curve.empty() || rule.curve.size() > DynamicMetadata::kMaxNumControlPoints) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "Gain curve must have 1 to 32 control points");
    }
    const bool inverse_tm = (enc_alt > enc_baseline);
    for (size_t c = 0; c < rule.curve.size(); ++c) {
      const ControlPoint& cp = rule.curve[c];
      if (!inClosedInterval(cp.x, 0.0f, 64.0f)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Control point x must be in [0, 64]");
      }
      if (!inClosedInterval(cp.y, -6.0f, 6.0f)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Control point y must be in [-6, 6]");
      }
      if (!rule.use_pchip_slope && !std::isfinite(cp.m)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Control point slope m must be finite");
      }
      if (inverse_tm && cp.y < 0.0f) {
        return makeError(
            UHDR_CODEC_INVALID_PARAM,
            "Control point y must be >= 0 when alternate headroom > baseline headroom");
      }
      if (!inverse_tm && cp.y > 0.0f) {
        return makeError(
            UHDR_CODEC_INVALID_PARAM,
            "Control point y must be <= 0 when alternate headroom < baseline headroom");
      }
      if (c > 0) {
        const ControlPoint& prev = rule.curve[c - 1];
        if (cp.x < prev.x) {
          return makeError(UHDR_CODEC_INVALID_PARAM, "Control point x must be non-decreasing");
        }
        const uint16_t enc_x_prev = floatToUint16(prev.x, 0u, 64000u, 0u, 1000.0f);
        const uint16_t enc_x_cur = floatToUint16(cp.x, 0u, 64000u, 0u, 1000.0f);
        const uint16_t enc_y_prev = floatToUint16(std::fabs(prev.y), 0u, 60000u, 0u, 10000.0f);
        const uint16_t enc_y_cur = floatToUint16(std::fabs(cp.y), 0u, 60000u, 0u, 10000.0f);
        if ((cp.x == prev.x && cp.y != prev.y) || (enc_x_cur == enc_x_prev && enc_y_cur != enc_y_prev)) {
          return makeError(UHDR_CODEC_INVALID_PARAM,
                           "Duplicate control point x must have identical y");
        }
      }
    }
  }

  return g_no_error;
}

uhdr_error_info_t encodeSt2094_50(const DynamicMetadata& metadata,
                                  std::vector<uint8_t>& out_bitstream) {
  uhdr_error_info_t status = validateDynamicMetadata(metadata);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }

  AnnexCBitWriter writer;

  // Table C.1: smpte_st_2094_50_application_info()
  writer.writeBits(DynamicMetadata::kApplicationVersion, 3);
  writer.writeBits(DynamicMetadata::kMinimumApplicationVersion, 3);
  writer.writeBits(0u, 2);  // reserved_zero_2bits

  // Table C.2: smpte_st_2094_50_color_volume_transform()
  const bool has_custom_ref_white =
      (metadata.hdr_reference_white != DynamicMetadata::kDefaultHdrReferenceWhite);
  writer.writeBit(has_custom_ref_white);
  writer.writeBit(metadata.has_adaptive_tone_map_flag);
  writer.writeBits(0u, 6);  // reserved_zero_6bits

  if (has_custom_ref_white) {
    writer.writeU16BE(floatToUint16(metadata.hdr_reference_white, 1u, 50000u, 0u, 5.0f));
  }

  if (!metadata.has_adaptive_tone_map_flag) {
    if (!writer.finish(out_bitstream)) {
      return makeError(UHDR_CODEC_MEM_ERROR, "Annex C buffer overflow");
    }
    return g_no_error;
  }

  // Table C.3: smpte_st_2094_50_adaptive_tone_map()
  const uint16_t enc_baseline =
      floatToUint16(metadata.baseline_hdr_headroom_log2, 0u, 60000u, 0u, 10000.0f);
  writer.writeU16BE(enc_baseline);
  writer.writeBit(metadata.use_reference_white_tone_mapping_flag);
  if (metadata.use_reference_white_tone_mapping_flag) {
    writer.writeBits(0u, 7);  // reserved_zero_7bits
    if (!writer.finish(out_bitstream)) {
      return makeError(UHDR_CODEC_MEM_ERROR, "Annex C buffer overflow");
    }
    return g_no_error;
  }

  const size_t num_alt = metadata.rules.size();
  writer.writeBits(static_cast<uint16_t>(num_alt), 3);

  const uint8_t chrom_mode = getChromaticitiesMode(metadata.gain_application_space_chromaticities);
  writer.writeBits(chrom_mode, 2);

  std::array<EncodedMix, DynamicMetadata::kMaxNumAlternateImages> enc_mixes{};
  for (size_t a = 0; a < num_alt; ++a) {
    enc_mixes[a] = encodeComponentMix(metadata.rules[a].mix);
  }

  bool has_common_mix = (num_alt > 1);
  bool has_common_curve = (num_alt > 1);
  for (size_t a = 1; a < num_alt; ++a) {
    if (!(enc_mixes[a] == enc_mixes[0])) {
      has_common_mix = false;
    }
    if (metadata.rules[a].use_pchip_slope != metadata.rules[0].use_pchip_slope ||
        metadata.rules[a].curve.size() != metadata.rules[0].curve.size()) {
      has_common_curve = false;
    } else {
      for (size_t c = 0; c < metadata.rules[a].curve.size(); ++c) {
        const uint16_t x0 = floatToUint16(metadata.rules[0].curve[c].x, 0u, 64000u, 0u, 1000.0f);
        const uint16_t xa = floatToUint16(metadata.rules[a].curve[c].x, 0u, 64000u, 0u, 1000.0f);
        if (x0 != xa) {
          has_common_curve = false;
          break;
        }
      }
    }
  }
  writer.writeBit(has_common_mix);
  writer.writeBit(has_common_curve);

  if (chrom_mode == 3) {
    for (size_t r = 0; r < 8; ++r) {
      writer.writeU16BE(floatToUint16(metadata.gain_application_space_chromaticities[r], 0u, 50000u,
                                      0u, kMixParamScale));
    }
  }

  for (size_t a = 0; a < num_alt; ++a) {
    const ToneMappingRule& rule = metadata.rules[a];
    const uint16_t enc_alt =
        floatToUint16(rule.alternate_hdr_headroom_log2, 0u, 60000u, 0u, 10000.0f);
    writer.writeU16BE(enc_alt);

    // Table C.4: smpte_st_2094_50_component_mixing(a)
    if (a == 0 || !has_common_mix) {
      const EncodedMix& em = enc_mixes[a];
      writer.writeBits(em.type, 2);
      if (em.type != 3) {
        writer.writeBits(0u, 6);  // reserved_zero_6bits
      } else {
        for (size_t k = 0; k < DynamicMetadata::kNumMixCoefficients; ++k) {
          writer.writeBit(em.flags[k] != 0u);
        }
        for (size_t k = 0; k < DynamicMetadata::kNumMixCoefficients; ++k) {
          if (em.flags[k] != 0u) {
            writer.writeU16BE(em.coeffs[k]);
          }
        }
      }
    }

    // Table C.5: smpte_st_2094_50_gain_curve(a)
    if (a == 0 || !has_common_curve) {
      writer.writeBits(static_cast<uint16_t>(rule.curve.size() - 1u), 5);
      writer.writeBit(rule.use_pchip_slope);
      writer.writeBits(0u, 2);  // reserved_zero_2bits
      for (const ControlPoint& cp : rule.curve) {
        writer.writeU16BE(floatToUint16(cp.x, 0u, 64000u, 0u, 1000.0f));
      }
    }

    for (const ControlPoint& cp : rule.curve) {
      writer.writeU16BE(floatToUint16(std::fabs(cp.y), 0u, 60000u, 0u, 10000.0f));
    }

    if (!rule.use_pchip_slope) {
      for (const ControlPoint& cp : rule.curve) {
        const float theta = std::atan(cp.m);
        writer.writeU16BE(floatToUint16(theta, 1u, 35999u, 18000u, 36000.0f / kPi));
      }
    }
  }

  if (!writer.finish(out_bitstream)) {
    return makeError(UHDR_CODEC_MEM_ERROR, "Annex C buffer overflow");
  }
  return g_no_error;
}

uhdr_error_info_t parseSt2094_50(const uint8_t* data, size_t size, DynamicMetadata& out_metadata) {
  if (data == nullptr || size < 2) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "Annex C bitstream is null or too short");
  }

  DynamicMetadata parsed{};
  AnnexCBitReader reader(data, size);

  uint32_t app_version = 0;
  uint32_t min_app_version = 0;
  uint32_t reserved = 0;
  if (!reader.readBits(3, app_version) || !reader.readBits(3, min_app_version) ||
      !reader.readBits(2, reserved)) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated Annex C application_info");
  }
  (void)app_version;
  if (min_app_version > 0 || reserved != 0u) {
    return makeError(UHDR_CODEC_INVALID_PARAM,
                     "Unsupported minimum_application_version or non-zero reserved bits");
  }

  bool has_custom_ref_white = false;
  if (!reader.readBit(has_custom_ref_white) || !reader.readBit(parsed.has_adaptive_tone_map_flag) ||
      !reader.readBits(6, reserved)) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated Annex C color_volume_transform");
  }
  if (reserved != 0u) {
    return makeError(UHDR_CODEC_INVALID_PARAM,
                     "Non-zero reserved bits in color_volume_transform");
  }

  if (has_custom_ref_white) {
    uint16_t raw_white = 0;
    if (!reader.readU16BE(raw_white)) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated hdr_reference_white");
    }
    parsed.hdr_reference_white = uint16ToFloat(raw_white, 1u, 50000u, 0u, 5.0f);
  } else {
    parsed.hdr_reference_white = DynamicMetadata::kDefaultHdrReferenceWhite;
  }

  if (!parsed.has_adaptive_tone_map_flag) {
    parsed.rules.clear();
    out_metadata = std::move(parsed);
    return g_no_error;
  }

  uint16_t raw_baseline = 0;
  if (!reader.readU16BE(raw_baseline)) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated baseline_hdr_headroom");
  }
  parsed.baseline_hdr_headroom_log2 = uint16ToFloat(raw_baseline, 0u, 60000u, 0u, 10000.0f);

  if (!reader.readBit(parsed.use_reference_white_tone_mapping_flag)) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated adaptive_tone_map flags");
  }
  if (parsed.use_reference_white_tone_mapping_flag) {
    if (!reader.readBits(7, reserved) || reserved != 0u) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "Invalid reserved bits in RWTM adaptive_tone_map");
    }
    populateUsingRwtm(parsed);
    out_metadata = std::move(parsed);
    return g_no_error;
  }

  uint32_t num_alt = 0;
  uint32_t chrom_mode = 0;
  bool has_common_mix = false;
  bool has_common_curve = false;
  if (!reader.readBits(3, num_alt) || !reader.readBits(2, chrom_mode) ||
      !reader.readBit(has_common_mix) || !reader.readBit(has_common_curve)) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated adaptive_tone_map header");
  }
  if (num_alt > DynamicMetadata::kMaxNumAlternateImages) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "num_alternate_images exceeds maximum (4)");
  }

  if (chrom_mode == 0u) {
    parsed.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesSrgb;
  } else if (chrom_mode == 1u) {
    parsed.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesDisplayP3;
  } else if (chrom_mode == 2u) {
    parsed.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesRec2020;
  } else {
    for (size_t r = 0; r < 8; ++r) {
      uint16_t raw_c = 0;
      if (!reader.readU16BE(raw_c)) {
        return makeError(UHDR_CODEC_INVALID_PARAM,
                         "Truncated gain_application_space_chromaticities");
      }
      parsed.gain_application_space_chromaticities[r] =
          uint16ToFloat(raw_c, 0u, 50000u, 0u, kMixParamScale);
    }
  }

  parsed.rules.assign(num_alt, ToneMappingRule{});
  ComponentMix common_mix{};
  size_t common_num_pts = 0;
  bool common_use_pchip = false;
  std::vector<float> common_x;

  for (size_t a = 0; a < num_alt; ++a) {
    ToneMappingRule& rule = parsed.rules[a];
    uint16_t raw_alt = 0;
    if (!reader.readU16BE(raw_alt)) {
      return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated alternate_hdr_headroom");
    }
    rule.alternate_hdr_headroom_log2 = uint16ToFloat(raw_alt, 0u, 60000u, 0u, 10000.0f);

    if (a == 0 || !has_common_mix) {
      uint32_t mix_type = 0;
      if (!reader.readBits(2, mix_type)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated component_mixing_type");
      }
      if (mix_type != 3u) {
        if (!reader.readBits(6, reserved) || reserved != 0u) {
          return makeError(UHDR_CODEC_INVALID_PARAM,
                           "Invalid reserved bits in component_mixing");
        }
        rule.mix = ComponentMix{};
        if (mix_type == 0u) {
          rule.mix.max = 1.0f;
        } else if (mix_type == 1u) {
          rule.mix.component = 1.0f;
        } else {
          constexpr float kOneSixth = 1.0f / 6.0f;
          rule.mix.rgb = {kOneSixth, kOneSixth, kOneSixth};
          rule.mix.max = 0.5f;
        }
      } else {
        std::array<bool, DynamicMetadata::kNumMixCoefficients> flags{};
        for (size_t k = 0; k < DynamicMetadata::kNumMixCoefficients; ++k) {
          if (!reader.readBit(flags[k])) {
            return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated component_mixing flags");
          }
        }
        std::array<double, DynamicMetadata::kNumMixCoefficients> p{};
        double p_sum = 0.0;
        for (size_t k = 0; k < DynamicMetadata::kNumMixCoefficients; ++k) {
          if (flags[k]) {
            uint16_t raw_coeff = 0;
            if (!reader.readU16BE(raw_coeff)) {
              return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated component_mixing coefficient");
            }
            p[k] = static_cast<double>(std::min<uint16_t>(raw_coeff, 50000u));
            p_sum += p[k];
          }
        }
        if (p_sum <= 0.0) {
          return makeError(UHDR_CODEC_INVALID_PARAM, "Component mixing coefficients sum to zero");
        }
        auto norm = [p_sum](double v) {
          return std::clamp(static_cast<float>(v / p_sum), 0.0f, 1.0f);
        };
        rule.mix.rgb = {norm(p[0]), norm(p[1]), norm(p[2])};
        rule.mix.max = norm(p[3]);
        rule.mix.min = norm(p[4]);
        rule.mix.component = norm(p[5]);
      }
      if (a == 0) {
        common_mix = rule.mix;
      }
    } else {
      rule.mix = common_mix;
    }

    size_t num_pts = 0;
    if (a == 0 || !has_common_curve) {
      uint32_t num_pts_m1 = 0;
      if (!reader.readBits(5, num_pts_m1) || !reader.readBit(rule.use_pchip_slope) ||
          !reader.readBits(2, reserved)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated gain_curve header");
      }
      if (reserved != 0u) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Invalid reserved bits in gain_curve");
      }
      num_pts = static_cast<size_t>(num_pts_m1) + 1u;
      rule.curve.assign(num_pts, ControlPoint{});
      for (size_t c = 0; c < num_pts; ++c) {
        uint16_t raw_x = 0;
        if (!reader.readU16BE(raw_x)) {
          return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated gain_curve x");
        }
        rule.curve[c].x = uint16ToFloat(raw_x, 0u, 64000u, 0u, 1000.0f);
      }
      if (a == 0) {
        common_num_pts = num_pts;
        common_use_pchip = rule.use_pchip_slope;
        common_x.resize(num_pts);
        for (size_t c = 0; c < num_pts; ++c) {
          common_x[c] = rule.curve[c].x;
        }
      }
    } else {
      num_pts = common_num_pts;
      rule.use_pchip_slope = common_use_pchip;
      rule.curve.assign(num_pts, ControlPoint{});
      for (size_t c = 0; c < num_pts; ++c) {
        rule.curve[c].x = common_x[c];
      }
    }

    const float sign = (raw_baseline < raw_alt) ? 1.0f : -1.0f;
    for (size_t c = 0; c < num_pts; ++c) {
      uint16_t raw_y = 0;
      if (!reader.readU16BE(raw_y)) {
        return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated gain_curve y");
      }
      rule.curve[c].y = sign * uint16ToFloat(raw_y, 0u, 60000u, 0u, 10000.0f);
    }

    if (!rule.use_pchip_slope) {
      for (size_t c = 0; c < num_pts; ++c) {
        uint16_t raw_theta = 0;
        if (!reader.readU16BE(raw_theta)) {
          return makeError(UHDR_CODEC_INVALID_PARAM, "Truncated gain_curve theta");
        }
        const float theta = uint16ToFloat(raw_theta, 1u, 35999u, 18000u, 36000.0f / kPi);
        rule.curve[c].m = std::tan(theta);
      }
    } else {
      std::vector<float> cp_x(num_pts);
      std::vector<float> cp_y(num_pts);
      for (size_t c = 0; c < num_pts; ++c) {
        cp_x[c] = rule.curve[c].x;
        cp_y[c] = rule.curve[c].y;
      }
      std::vector<float> slopes;
      uhdr_error_info_t slope_status = computePchipSlopes(cp_x, cp_y, slopes);
      if (slope_status.error_code != UHDR_CODEC_OK) {
        return slope_status;
      }
      for (size_t c = 0; c < num_pts; ++c) {
        rule.curve[c].m = slopes[c];
      }
    }
  }

  uhdr_error_info_t val_status = validateDynamicMetadata(parsed);
  if (val_status.error_code != UHDR_CODEC_OK) {
    return val_status;
  }

  out_metadata = std::move(parsed);
  return g_no_error;
}

}  // namespace smpte2094_50

static float applyMix(const Color& pixel, const smpte2094_50::ComponentMix& mix, float luma) {
  const float k_sum =
      mix.rgb[0] + mix.rgb[1] + mix.rgb[2] + mix.component + mix.max + mix.min;
  if (k_sum <= 0.0f) return luma;

  float mixed = mix.rgb[0] * pixel.r + mix.rgb[1] * pixel.g + mix.rgb[2] * pixel.b;
  mixed += mix.component * luma;
  if (mix.max > 0.0f) mixed += mix.max * std::max({pixel.r, pixel.g, pixel.b});
  if (mix.min > 0.0f) mixed += mix.min * std::min({pixel.r, pixel.g, pixel.b});
  mixed /= k_sum;

  return std::clamp(mixed, 0.0f, 1.0f);
}

uhdr_error_info_t generateGainMap(uhdr_raw_image_t* image,
                                  const smpte2094_50::DynamicMetadata& metadata,
                                  uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                  std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                  float hdr_capacity_max) {
  if (image == nullptr || gainmap_metadata == nullptr) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_INVALID_PARAM;
    status.has_detail = 1;
    std::snprintf(status.detail, sizeof(status.detail),
                  "Null image or gainmap_metadata in generateGainMap");
    return status;
  }

  smpte2094_50::DynamicMetadata local_metadata = metadata;
  uhdr_error_info_t smpte_status = smpte2094_50::populateImplicitParameters(local_metadata);
  if (smpte_status.error_code != UHDR_CODEC_OK) {
    return smpte_status;
  }

  float max_headroom_log2 = local_metadata.baseline_hdr_headroom_log2;
  for (const auto& rule : local_metadata.rules) {
    max_headroom_log2 = std::max(max_headroom_log2, rule.alternate_hdr_headroom_log2);
  }

  if (hdr_capacity_max < 0.0f) hdr_capacity_max = std::exp2(max_headroom_log2);

  struct Evaluator {
    float H = 0.0f;
    smpte2094_50::ComponentMix mix{};
    std::array<float, kGainFactorNumEntries> log2GainLUT{};
    bool is_baseline = false;
  };

  std::vector<Evaluator> evaluators;
  Evaluator baseline;
  baseline.H = local_metadata.baseline_hdr_headroom_log2;
  baseline.is_baseline = true;
  baseline.log2GainLUT.fill(0.0f);
  evaluators.push_back(std::move(baseline));

  for (size_t r_idx = 0; r_idx < local_metadata.rules.size(); ++r_idx) {
    const auto& rule = local_metadata.rules[r_idx];
    Evaluator ev;
    ev.H = rule.alternate_hdr_headroom_log2;
    ev.is_baseline = false;
    ev.mix = rule.mix;

    std::vector<float> cp_x;
    std::vector<float> cp_y;
    std::vector<float> cp_m;
    cp_x.reserve(rule.curve.size());
    cp_y.reserve(rule.curve.size());
    cp_m.reserve(rule.curve.size());
    bool has_nonzero_slope = local_metadata.use_reference_white_tone_mapping_flag;
    for (const auto& cp : rule.curve) {
      cp_x.push_back(cp.x);
      cp_y.push_back(cp.y);
      cp_m.push_back(cp.m);
      if (cp.m != 0.0f) has_nonzero_slope = true;
    }

    smpte2094_50::GainCurve curve;
    uhdr_error_info_t curve_status =
        has_nonzero_slope ? smpte2094_50::GainCurve::create(cp_x, cp_y, cp_m, curve)
                          : smpte2094_50::GainCurve::create(cp_x, cp_y, curve);
    if (curve_status.error_code != UHDR_CODEC_OK) {
      return curve_status;
    }
    for (size_t i = 0; i < kGainFactorNumEntries; ++i) {
      const float xi = static_cast<float>(i) / static_cast<float>(kGainFactorNumEntries - 1);
      ev.log2GainLUT[i] = curve.interpolate(xi);
    }
    evaluators.push_back(std::move(ev));
  }

  std::sort(evaluators.begin(), evaluators.end(),
            [](const Evaluator& a, const Evaluator& b) { return a.H < b.H; });

  float target_H = std::log2(hdr_capacity_max);
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

  std::array<float, 3> log2MinBoost{};
  std::array<float, 3> log2MaxBoost{};
  for (int i = 0; i < 3; i++) {
    log2MinBoost[i] = std::log2(gainmap_metadata->min_content_boost[i]);
    log2MaxBoost[i] = std::log2(gainmap_metadata->max_content_boost[i]);
    if (std::fabs(log2MaxBoost[i] - log2MinBoost[i]) < FLT_EPSILON) {
      log2MaxBoost[i] += 0.0001f;
    }
  }

  gainmap_img = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppRGB888, image->cg,
                                                       image->ct, image->range, image->w, image->h,
                                                       64);

  SamplePixelFn sample_pixel_fn = getSamplePixelFn(image->fmt);
  LuminanceFn luminance_fn = getLuminanceFn(image->cg);
  ColorTransformFn yuv_to_rgb_fn = getYuvToRgbFn(image->cg);

  const bool is_rgb = isPixelFormatRgb(image->fmt);

  for (unsigned int py = 0; py < image->h; ++py) {
    for (unsigned int px = 0; px < image->w; ++px) {
      Color pixel = sample_pixel_fn(image, 1, px, py);
      if (!is_rgb && yuv_to_rgb_fn != nullptr) {
        pixel = yuv_to_rgb_fn(pixel);
      }
      const float luma = luminance_fn(pixel);

      float logGain = 0.0f;
      if (evaluators.size() > 1) {
        const Evaluator& ev0 = evaluators[idx];
        const Evaluator& ev1 = evaluators[idx + 1];
        const float w1 = (ev1.H == ev0.H) ? 0.0f : (target_H - ev0.H) / (ev1.H - ev0.H);
        const float w0 = 1.0f - w1;

        float gy0 = 0.0f;
        if (!ev0.is_baseline) {
          const float x0 = applyMix(pixel, ev0.mix, luma);
          const int32_t i0 = static_cast<int32_t>(x0 * (kGainFactorNumEntries - 1) + 0.5f);
          gy0 = ev0.log2GainLUT[CLIP3(i0, 0, static_cast<int32_t>(kGainFactorNumEntries) - 1)];
        }

        float gy1 = 0.0f;
        if (!ev1.is_baseline) {
          const float x1 = applyMix(pixel, ev1.mix, luma);
          const int32_t i1 = static_cast<int32_t>(x1 * (kGainFactorNumEntries - 1) + 0.5f);
          gy1 = ev1.log2GainLUT[CLIP3(i1, 0, static_cast<int32_t>(kGainFactorNumEntries) - 1)];
        }
        logGain = w0 * gy0 + w1 * gy1;
      } else {
        const Evaluator& ev0 = evaluators[0];
        if (!ev0.is_baseline) {
          const float x0 = applyMix(pixel, ev0.mix, luma);
          const int32_t i0 = static_cast<int32_t>(x0 * (kGainFactorNumEntries - 1) + 0.5f);
          logGain = ev0.log2GainLUT[CLIP3(i0, 0, static_cast<int32_t>(kGainFactorNumEntries) - 1)];
        }
      }

      const size_t pixel_idx =
          (static_cast<size_t>(px) + static_cast<size_t>(py) * gainmap_img->stride[UHDR_PLANE_PACKED]) *
          3u;
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
