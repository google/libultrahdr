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
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/icc.h"

namespace ultrahdr {

namespace {

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
uhdr_error_info_t makeStatusError(uhdr_codec_err_t code, const char* fmt, ...) {
  uhdr_error_info_t status{};
  status.error_code = code;
  status.has_detail = 1;
  va_list args;
  va_start(args, fmt);
  std::vsnprintf(status.detail, sizeof(status.detail), fmt, args);
  va_end(args);
  return status;
}

}  // namespace

namespace smpte2094_50 {

namespace {

constexpr float kPi = 3.14159265358979323846f;
constexpr float kLn2 = 0.69314718055994530942f;
constexpr float kMixParamScale = 50000.0f;
constexpr size_t kMaxAnnexCBytes = 1024;

uint16_t floatToUint16(float v, uint16_t clamp_min, uint16_t clamp_max, uint16_t offset,
                       float scale) {
  const long rounded = std::lround(static_cast<double>(v) * static_cast<double>(scale)) +
                       static_cast<long>(offset);
  const long clamped =
      std::clamp(rounded, static_cast<long>(clamp_min), static_cast<long>(clamp_max));
  return static_cast<uint16_t>(clamped);
}

bool uint16ToFloatChecked(uint16_t v, uint16_t min_val, uint16_t max_val, uint16_t offset,
                          float scale, float& out) {
  if (v < min_val || v > max_val) {
    return false;
  }
  out = static_cast<float>(static_cast<int32_t>(v) - static_cast<int32_t>(offset)) / scale;
  return true;
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

  bool atEnd() const { return mBytePos == mSize && mBitPos == 0; }

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
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "PCHIP x and y vectors must have equal length");
  }
  const size_t n = x.size();
  for (size_t i = 0; i < n; ++i) {
    if (!std::isfinite(x[i]) || !std::isfinite(y[i])) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "PCHIP control points must be finite");
    }
    if (i + 1 < n && x[i + 1] < x[i]) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "PCHIP x values must be non-decreasing");
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
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "PchipInterpolator x, y, and slopes must have equal length");
  }
  for (size_t i = 0; i < x.size(); ++i) {
    if (!std::isfinite(x[i]) || !std::isfinite(y[i]) || !std::isfinite(slopes[i])) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                       "PchipInterpolator control points and slopes must be finite");
    }
    if (i + 1 < x.size() && x[i + 1] < x[i]) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
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

      const float h = high - low;
      const float m0 = mSlopes[i];
      const float m1 = mSlopes[i + 1];
      const bool increasing = (y0 <= y1);
      float t_lo = 0.0f;
      float t_hi = 1.0f;
      for (int step = 0; step < 16; ++step) {
        const float t = 0.5f * (t_lo + t_hi);
        const float omt = 1.0f - t;
        const float val = ((1.0f + 2.0f * t) * omt * omt) * y0 + (t * omt * omt) * h * m0 +
                          (t * t * (3.0f - 2.0f * t)) * y1 + (t * t * (t - 1.0f)) * h * m1;
        if (val < yi) {
          if (increasing) {
            t_lo = t;
          } else {
            t_hi = t;
          }
        } else {
          if (increasing) {
            t_hi = t;
          } else {
            t_lo = t;
          }
        }
      }
      out_xi = low + 0.5f * (t_lo + t_hi) * h;
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
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "Invalid input points or num_control_points for createSubsampledPchip");
  }
  for (size_t i = 0; i < x.size(); ++i) {
    if (!std::isfinite(x[i]) || !std::isfinite(y[i])) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Control points must be finite");
    }
    if (i + 1 < x.size() && x[i + 1] < x[i]) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "x values must be non-decreasing");
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
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "hdr_reference_white must be in (0, 10000]");
  }
  if (floatToUint16(metadata.hdr_reference_white, 0u, 50000u, 0u, 5.0f) == 0u) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "hdr_reference_white quantizes to 0");
  }

  if (!metadata.has_adaptive_tone_map_flag) {
    return g_no_error;
  }

  if (!inClosedInterval(metadata.baseline_hdr_headroom_log2, 0.0f, 6.0f)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "baseline_hdr_headroom_log2 must be in [0, 6]");
  }

  if (metadata.use_reference_white_tone_mapping_flag) {
    return g_no_error;
  }

  if (metadata.rules.size() > DynamicMetadata::kMaxNumAlternateImages) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "num_alternate_images must not exceed 4");
  }

  // Validate chromaticities (Clause 6.2.2): unit interval, non-zero RGB triangle area, and
  // strictly interior white point after Annex C quantization.
  std::array<float, 8> q_chrom{};
  for (size_t r = 0; r < 8; ++r) {
    if (!inClosedInterval(metadata.gain_application_space_chromaticities[r], 0.0f, 1.0f)) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                       "gain_application_space_chromaticities must be in [0, 1]");
    }
    const uint16_t raw = floatToUint16(metadata.gain_application_space_chromaticities[r], 0u,
                                       50000u, 0u, kMixParamScale);
    if (!uint16ToFloatChecked(raw, 0u, 50000u, 0u, kMixParamScale, q_chrom[r])) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                             "gain_application_space_chromaticities out of range");
    }
  }
  const float xr = q_chrom[0], yr = q_chrom[1];
  const float xg = q_chrom[2], yg = q_chrom[3];
  const float xb = q_chrom[4], yb = q_chrom[5];
  const float xw = q_chrom[6], yw = q_chrom[7];
  const float det = (yg - yb) * (xr - xb) + (xb - xg) * (yr - yb);
  if (std::fabs(det) <= 1e-12f) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "gain_application_space_chromaticities form a degenerate RGB triangle");
  }
  const float l1 = ((yg - yb) * (xw - xb) + (xb - xg) * (yw - yb)) / det;
  const float l2 = ((yb - yr) * (xw - xb) + (xr - xb) * (yw - yb)) / det;
  const float l3 = 1.0f - l1 - l2;
  if (l1 <= 0.0f || l2 <= 0.0f || l3 <= 0.0f) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "White point lies outside gain_application_space_chromaticities triangle");
  }

  const uint16_t enc_baseline =
      floatToUint16(metadata.baseline_hdr_headroom_log2, 0u, 60000u, 0u, 10000.0f);
  uint16_t prev_enc_alt = 0;

  for (size_t a = 0; a < metadata.rules.size(); ++a) {
    const ToneMappingRule& rule = metadata.rules[a];
    if (!inClosedInterval(rule.alternate_hdr_headroom_log2, 0.0f, 6.0f)) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "alternate_hdr_headroom_log2 must be in [0, 6]");
    }
    const uint16_t enc_alt =
        floatToUint16(rule.alternate_hdr_headroom_log2, 0u, 60000u, 0u, 10000.0f);
    if (enc_alt == enc_baseline ||
        rule.alternate_hdr_headroom_log2 == metadata.baseline_hdr_headroom_log2) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                       "alternate_hdr_headroom_log2 must not equal baseline_hdr_headroom_log2");
    }
    if (a > 0 && (enc_alt <= prev_enc_alt ||
                  rule.alternate_hdr_headroom_log2 <=
                      metadata.rules[a - 1].alternate_hdr_headroom_log2)) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
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
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "ComponentMix weights must be in [0, 1]");
      }
      mix_sum += mv;
    }
    if (mix_sum <= 0.0f) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "ComponentMix weights must sum to > 0");
    }
    const EncodedMix enc_mix = encodeComponentMix(rule.mix);
    if (enc_mix.type == 3) {
      uint32_t q_sum = 0;
      for (uint16_t qc : enc_mix.coeffs) q_sum += qc;
      if (q_sum == 0u) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Quantized ComponentMix weights sum to 0");
      }
    }

    // Validate GainCurve (Clauses 6.2.3 & 6.5.2).
    if (rule.curve.empty() || rule.curve.size() > DynamicMetadata::kMaxNumControlPoints) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Gain curve must have 1 to 32 control points");
    }
    const bool inverse_tm = (enc_alt > enc_baseline);
    for (size_t c = 0; c < rule.curve.size(); ++c) {
      const ControlPoint& cp = rule.curve[c];
      if (!inClosedInterval(cp.x, 0.0f, 64.0f)) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Control point x must be in [0, 64]");
      }
      if (!inClosedInterval(cp.y, -6.0f, 6.0f)) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Control point y must be in [-6, 6]");
      }
      if (!rule.use_pchip_slope && !std::isfinite(cp.m)) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Control point slope m must be finite");
      }
      if (inverse_tm && cp.y < 0.0f) {
        return makeStatusError(
            UHDR_CODEC_INVALID_PARAM,
            "Control point y must be >= 0 when alternate headroom > baseline headroom");
      }
      if (!inverse_tm && cp.y > 0.0f) {
        return makeStatusError(
            UHDR_CODEC_INVALID_PARAM,
            "Control point y must be <= 0 when alternate headroom < baseline headroom");
      }
      if (c > 0) {
        const ControlPoint& prev = rule.curve[c - 1];
        if (cp.x < prev.x) {
          return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Control point x must be non-decreasing");
        }
        const uint16_t enc_x_prev = floatToUint16(prev.x, 0u, 64000u, 0u, 1000.0f);
        const uint16_t enc_x_cur = floatToUint16(cp.x, 0u, 64000u, 0u, 1000.0f);
        const uint16_t enc_y_prev = floatToUint16(std::fabs(prev.y), 0u, 60000u, 0u, 10000.0f);
        const uint16_t enc_y_cur = floatToUint16(std::fabs(cp.y), 0u, 60000u, 0u, 10000.0f);
        if ((cp.x == prev.x && cp.y != prev.y) || (enc_x_cur == enc_x_prev && enc_y_cur != enc_y_prev)) {
          return makeStatusError(UHDR_CODEC_INVALID_PARAM,
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
      return makeStatusError(UHDR_CODEC_MEM_ERROR, "Annex C buffer overflow");
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
      return makeStatusError(UHDR_CODEC_MEM_ERROR, "Annex C buffer overflow");
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
    return makeStatusError(UHDR_CODEC_MEM_ERROR, "Annex C buffer overflow");
  }
  return g_no_error;
}

namespace {

uhdr_error_info_t readU16FloatField(AnnexCBitReader& reader, uint16_t min_val, uint16_t max_val,
                                    uint16_t offset, float scale, const char* field_name,
                                    float& out, uint16_t* raw_out = nullptr) {
  uint16_t raw = 0;
  if (!reader.readU16BE(raw)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated %s", field_name);
  }
  if (!uint16ToFloatChecked(raw, min_val, max_val, offset, scale, out)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Out-of-range %s", field_name);
  }
  if (raw_out != nullptr) *raw_out = raw;
  return g_no_error;
}

}  // namespace

uhdr_error_info_t parseSt2094_50(const uint8_t* data, size_t size, DynamicMetadata& out_metadata) {
  if (data == nullptr || size < 2) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Annex C bitstream is null or too short");
  }

  DynamicMetadata parsed{};
  AnnexCBitReader reader(data, size);

  uint32_t app_version = 0;
  uint32_t min_app_version = 0;
  uint32_t reserved = 0;
  if (!reader.readBits(3, app_version) || !reader.readBits(3, min_app_version) ||
      !reader.readBits(2, reserved)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated Annex C application_info");
  }
  (void)app_version;
  if (min_app_version > 0 || reserved != 0u) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "Unsupported minimum_application_version or non-zero reserved bits");
  }

  bool has_custom_ref_white = false;
  if (!reader.readBit(has_custom_ref_white) || !reader.readBit(parsed.has_adaptive_tone_map_flag) ||
      !reader.readBits(6, reserved)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated Annex C color_volume_transform");
  }
  if (reserved != 0u) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "Non-zero reserved bits in color_volume_transform");
  }

  if (has_custom_ref_white) {
    if (auto err = readU16FloatField(reader, 1u, 50000u, 0u, 5.0f, "hdr_reference_white",
                                     parsed.hdr_reference_white);
        err.error_code != UHDR_CODEC_OK) {
      return err;
    }
  } else {
    parsed.hdr_reference_white = DynamicMetadata::kDefaultHdrReferenceWhite;
  }

  if (!parsed.has_adaptive_tone_map_flag) {
    if (!reader.atEnd()) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                             "Unexpected trailing bytes in Annex C bitstream");
    }
    parsed.rules.clear();
    out_metadata = std::move(parsed);
    return g_no_error;
  }

  uint16_t raw_baseline = 0;
  if (auto err = readU16FloatField(reader, 0u, 60000u, 0u, 10000.0f, "baseline_hdr_headroom",
                                   parsed.baseline_hdr_headroom_log2, &raw_baseline);
      err.error_code != UHDR_CODEC_OK) {
    return err;
  }

  if (!reader.readBit(parsed.use_reference_white_tone_mapping_flag)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated adaptive_tone_map flags");
  }
  if (parsed.use_reference_white_tone_mapping_flag) {
    if (!reader.readBits(7, reserved) || reserved != 0u) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid reserved bits in RWTM adaptive_tone_map");
    }
    if (!reader.atEnd()) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                             "Unexpected trailing bytes in Annex C bitstream");
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
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated adaptive_tone_map header");
  }
  if (num_alt > DynamicMetadata::kMaxNumAlternateImages) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "num_alternate_images exceeds maximum (4)");
  }

  if (chrom_mode == 0u) {
    parsed.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesSrgb;
  } else if (chrom_mode == 1u) {
    parsed.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesDisplayP3;
  } else if (chrom_mode == 2u) {
    parsed.gain_application_space_chromaticities = DynamicMetadata::kChromaticitiesRec2020;
  } else {
    for (size_t r = 0; r < 8; ++r) {
      if (auto err =
              readU16FloatField(reader, 0u, 50000u, 0u, kMixParamScale,
                                "gain_application_space_chromaticities",
                                parsed.gain_application_space_chromaticities[r]);
          err.error_code != UHDR_CODEC_OK) {
        return err;
      }
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
    if (auto err = readU16FloatField(reader, 0u, 60000u, 0u, 10000.0f, "alternate_hdr_headroom",
                                     rule.alternate_hdr_headroom_log2, &raw_alt);
        err.error_code != UHDR_CODEC_OK) {
      return err;
    }

    if (a == 0 || !has_common_mix) {
      uint32_t mix_type = 0;
      if (!reader.readBits(2, mix_type)) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated component_mixing_type");
      }
      if (mix_type != 3u) {
        if (!reader.readBits(6, reserved) || reserved != 0u) {
          return makeStatusError(UHDR_CODEC_INVALID_PARAM,
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
            return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated component_mixing flags");
          }
        }
        std::array<double, DynamicMetadata::kNumMixCoefficients> p{};
        double p_sum = 0.0;
        for (size_t k = 0; k < DynamicMetadata::kNumMixCoefficients; ++k) {
          if (flags[k]) {
            uint16_t raw_coeff = 0;
            if (!reader.readU16BE(raw_coeff)) {
              return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated component_mixing coefficient");
            }
            if (raw_coeff > 50000u) {
              return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                               "Out-of-range component_mixing coefficient");
            }
            p[k] = static_cast<double>(raw_coeff);
            p_sum += p[k];
          }
        }
        if (p_sum <= 0.0) {
          return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Component mixing coefficients sum to zero");
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
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Truncated gain_curve header");
      }
      if (reserved != 0u) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid reserved bits in gain_curve");
      }
      num_pts = static_cast<size_t>(num_pts_m1) + 1u;
      rule.curve.assign(num_pts, ControlPoint{});
      for (size_t c = 0; c < num_pts; ++c) {
        if (auto err =
                readU16FloatField(reader, 0u, 64000u, 0u, 1000.0f, "gain_curve x", rule.curve[c].x);
            err.error_code != UHDR_CODEC_OK) {
          return err;
        }
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
      float abs_y = 0.0f;
      if (auto err = readU16FloatField(reader, 0u, 60000u, 0u, 10000.0f, "gain_curve y", abs_y);
          err.error_code != UHDR_CODEC_OK) {
        return err;
      }
      rule.curve[c].y = sign * abs_y;
    }

    if (!rule.use_pchip_slope) {
      for (size_t c = 0; c < num_pts; ++c) {
        float theta = 0.0f;
        if (auto err = readU16FloatField(reader, 1u, 35999u, 18000u, 36000.0f / kPi,
                                         "gain_curve theta", theta);
            err.error_code != UHDR_CODEC_OK) {
          return err;
        }
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

  if (!reader.atEnd()) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Unexpected trailing bytes in Annex C bitstream");
  }

  uhdr_error_info_t val_status = validateDynamicMetadata(parsed);
  if (val_status.error_code != UHDR_CODEC_OK) {
    return val_status;
  }

  out_metadata = std::move(parsed);
  return g_no_error;
}

namespace {

bool solveLinearSystem(size_t n,
                       std::array<std::array<double, DynamicMetadata::kNumMixCoefficients>,
                                  DynamicMetadata::kNumMixCoefficients>
                           mat,
                       std::array<double, DynamicMetadata::kNumMixCoefficients> rhs,
                       std::array<double, DynamicMetadata::kNumMixCoefficients>& out_sol) {
  out_sol.fill(0.0);
  for (size_t col = 0; col < n; ++col) {
    size_t piv = col;
    double max_abs = std::fabs(mat[col][col]);
    for (size_t row = col + 1; row < n; ++row) {
      const double v = std::fabs(mat[row][col]);
      if (v > max_abs) {
        max_abs = v;
        piv = row;
      }
    }
    if (max_abs <= 1e-13) {
      return false;
    }
    if (piv != col) {
      std::swap(mat[col], mat[piv]);
      std::swap(rhs[col], rhs[piv]);
    }
    const double inv_diag = 1.0 / mat[col][col];
    for (size_t row = col + 1; row < n; ++row) {
      const double factor = mat[row][col] * inv_diag;
      if (factor == 0.0) continue;
      mat[row][col] = 0.0;
      for (size_t k = col + 1; k < n; ++k) {
        mat[row][k] -= factor * mat[col][k];
      }
      rhs[row] -= factor * rhs[col];
    }
  }

  for (size_t idx = n; idx > 0; --idx) {
    const size_t row = idx - 1;
    double acc = rhs[row];
    for (size_t k = row + 1; k < n; ++k) {
      acc -= mat[row][k] * out_sol[k];
    }
    out_sol[row] = acc / mat[row][row];
  }
  return true;
}

float clampGainForHeadroom(float y, float base_headroom_log2, float alt_headroom_log2) {
  if (alt_headroom_log2 > base_headroom_log2) {
    return std::max(y, 0.0f);
  }
  return std::min(y, 0.0f);
}

}  // namespace

uhdr_error_info_t solveConstrainedL1Simplex(
    const float* A, const float* B, size_t num_rows, size_t num_vars,
    std::array<float, DynamicMetadata::kNumMixCoefficients>& out_weights,
    double* out_duality_gap) {
  out_weights.fill(0.0f);
  if (out_duality_gap != nullptr) {
    *out_duality_gap = 0.0;
  }
  if (A == nullptr || B == nullptr || num_rows == 0 || num_vars == 0 ||
      num_vars > DynamicMetadata::kNumMixCoefficients) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid dimensions or null pointers in L1 solver");
  }

  using Vec6d = std::array<double, DynamicMetadata::kNumMixCoefficients>;
  using Mat6d = std::array<Vec6d, DynamicMetadata::kNumMixCoefficients>;

  std::vector<Vec6d> rows_a(num_rows, Vec6d{});
  std::vector<double> rows_b(num_rows, 0.0);
  size_t m = 0;
  for (size_t i = 0; i < num_rows; ++i) {
    if (!std::isfinite(B[i])) continue;
    Vec6d r{};
    bool ok = true;
    for (size_t j = 0; j < num_vars; ++j) {
      const float val = A[i * num_vars + j];
      if (!std::isfinite(val)) {
        ok = false;
        break;
      }
      r[j] = static_cast<double>(val);
    }
    if (ok) {
      rows_a[m] = r;
      rows_b[m] = static_cast<double>(B[i]);
      ++m;
    }
  }
  if (m == 0) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "No finite rows provided to L1 solver");
  }
  rows_a.resize(m);
  rows_b.resize(m);

  if (num_vars == 1) {
    out_weights[0] = 1.0f;
    return g_no_error;
  }

  const size_t n = num_vars;
  constexpr int kLambdaVar = -1;
  // Variable states for bounded variables q in [0, m + n):
  //   0 -> non-basic at lower bound 0.0
  //   1 -> non-basic at upper bound 1.0 (only for q < m)
  //   2 -> basic (in basis[1 .. n-1])
  std::vector<int> state(m + n, 0);

  Vec6d rhs{};
  const double inv_n = 1.0 / static_cast<double>(n);
  Vec6d eff_rhs{};
  for (size_t i = 0; i < m; ++i) {
    double avg_a = 0.0;
    for (size_t j = 0; j < n; ++j) {
      rhs[j] += rows_a[i][j];
      avg_a += rows_a[i][j];
    }
    if (rows_b[i] > avg_a * inv_n) {
      state[i] = 1;
      for (size_t j = 0; j < n; ++j) {
        eff_rhs[j] -= rows_a[i][j];
      }
    } else {
      for (size_t j = 0; j < n; ++j) {
        eff_rhs[j] += rows_a[i][j];
      }
    }
  }

  // Phase-I-free warm-started dual-feasible basis:
  // v_i in {0, 1} (u_i = 2*v_i - 1 in {-1, +1}), lambda = min_j eff_rhs[j], s_j = eff_rhs[j] - lambda >= 0.
  size_t min_j = 0;
  for (size_t j = 1; j < n; ++j) {
    if (eff_rhs[j] < eff_rhs[min_j]) {
      min_j = j;
    }
  }

  std::array<int, DynamicMetadata::kNumMixCoefficients> basis{};
  basis[0] = kLambdaVar;
  size_t slot_fill = 1;
  for (size_t j = 0; j < n; ++j) {
    if (j == min_j) continue;
    const int svar = static_cast<int>(m + j);
    basis[slot_fill++] = svar;
    state[static_cast<size_t>(svar)] = 2;
  }

  auto getCol = [&](int var) -> Vec6d {
    Vec6d col{};
    if (var == kLambdaVar) {
      for (size_t j = 0; j < n; ++j) col[j] = 1.0;
    } else if (static_cast<size_t>(var) < m) {
      const size_t idx = static_cast<size_t>(var);
      for (size_t j = 0; j < n; ++j) col[j] = 2.0 * rows_a[idx][j];
    } else {
      const size_t j = static_cast<size_t>(var) - m;
      col[j] = 1.0;
    }
    return col;
  };

  auto getCost = [&](int var) -> double {
    if (var == kLambdaVar) return 1.0;
    if (static_cast<size_t>(var) < m) return 2.0 * rows_b[static_cast<size_t>(var)];
    return 0.0;
  };

  auto buildBasisMatrices = [&](Mat6d& m_b, Mat6d& m_bt, Vec6d& c_b) {
    m_b = Mat6d{};
    m_bt = Mat6d{};
    c_b = Vec6d{};
    for (size_t p = 0; p < n; ++p) {
      const Vec6d col = getCol(basis[p]);
      c_b[p] = getCost(basis[p]);
      for (size_t j = 0; j < n; ++j) {
        m_b[j][p] = col[j];
        m_bt[p][j] = col[j];
      }
    }
  };

  auto evalPrimalL1 = [&](const Vec6d& w_vec) -> double {
    double total = 0.0;
    for (size_t i = 0; i < m; ++i) {
      double dot = 0.0;
      for (size_t j = 0; j < n; ++j) {
        dot += rows_a[i][j] * w_vec[j];
      }
      total += std::fabs(dot - rows_b[i]);
    }
    return total;
  };

  auto sanitizeWeights = [&](const Vec6d& raw_w) -> Vec6d {
    Vec6d clean{};
    double sum = 0.0;
    for (size_t j = 0; j < n; ++j) {
      if (std::isfinite(raw_w[j]) && raw_w[j] > 0.0) {
        clean[j] = raw_w[j];
        sum += clean[j];
      }
    }
    if (sum > 0.0) {
      for (size_t j = 0; j < n; ++j) clean[j] /= sum;
    } else {
      clean[min_j] = 1.0;
    }
    return clean;
  };

  Mat6d m_b{};
  Mat6d m_bt{};
  Vec6d c_b{};
  buildBasisMatrices(m_b, m_bt, c_b);

  Vec6d x_b{};
  Vec6d w{};
  if (!solveLinearSystem(n, m_b, eff_rhs, x_b) || !solveLinearSystem(n, m_bt, c_b, w)) {
    out_weights[min_j] = 1.0f;
    return g_no_error;
  }

  Vec6d fallback_w{};
  for (size_t j = 0; j < n; ++j) fallback_w[j] = inv_n;

  std::vector<double> rc_cache(m + n, 0.0);
  bool rc_dirty = true;

  constexpr double kOptTol = 1e-11;
  constexpr double kPivTol = 1e-11;
  constexpr double kTieTol = 1e-13;
  const size_t max_iters = std::max<size_t>(2000u, 8u * (m + n));
  size_t degenerate_streak = 0;
  size_t pivot_count = 0;

  for (size_t iter = 0; iter < max_iters; ++iter) {
    if (rc_dirty) {
      for (size_t i = 0; i < m; ++i) {
        double dot = 0.0;
        for (size_t j = 0; j < n; ++j) {
          dot += rows_a[i][j] * w[j];
        }
        rc_cache[i] = 2.0 * (rows_b[i] - dot);
      }
      for (size_t j = 0; j < n; ++j) {
        rc_cache[m + j] = -w[j];
      }
      rc_dirty = false;
    }

    const bool use_bland = (degenerate_streak >= 8u);

    int enter_var = -1;
    double enter_sigma = 0.0;
    double best_gain = kOptTol;

    for (size_t q = 0; q < m + n; ++q) {
      const int st = state[q];
      if (st == 2) continue;

      const double rc = rc_cache[q];
      double gain = 0.0;
      double sigma = 0.0;
      if (st == 0 && rc > kOptTol) {
        gain = rc;
        sigma = 1.0;
      } else if (st == 1 && rc < -kOptTol) {
        gain = -rc;
        sigma = -1.0;
      } else {
        continue;
      }

      if (use_bland) {
        enter_var = static_cast<int>(q);
        enter_sigma = sigma;
        break;
      }
      if (gain > best_gain) {
        best_gain = gain;
        enter_var = static_cast<int>(q);
        enter_sigma = sigma;
      }
    }

    if (enter_var < 0) {
      // Dual & primal optimality reached.
      break;
    }

    Vec6d d{};
    if (!solveLinearSystem(n, m_b, getCol(enter_var), d)) {
      break;
    }

    double min_theta =
        (static_cast<size_t>(enter_var) < m) ? 1.0 : std::numeric_limits<double>::infinity();
    int leave_slot = -1;
    int leave_new_state = -1;
    double best_abs_delta = 0.0;

    for (size_t p = 1; p < n; ++p) {
      const double delta = enter_sigma * d[p];
      const int bvar = basis[p];
      int cand_state = -1;
      double avail = 0.0;
      if (delta > kPivTol) {
        avail = std::max(0.0, x_b[p]);
        cand_state = 0;
      } else if (static_cast<size_t>(bvar) < m && delta < -kPivTol) {
        avail = std::max(0.0, 1.0 - x_b[p]);
        cand_state = 1;
      } else {
        continue;
      }

      const double ratio = avail / std::fabs(delta);
      bool take = false;
      if (ratio < min_theta - kTieTol) {
        take = true;
      } else if (std::fabs(ratio - min_theta) <= kTieTol) {
        if (leave_slot == -1) {
          take = true;
        } else if (use_bland) {
          take = (bvar < basis[static_cast<size_t>(leave_slot)]);
        } else {
          take = (std::fabs(delta) > best_abs_delta);
        }
      }
      if (take) {
        min_theta = ratio;
        leave_slot = static_cast<int>(p);
        leave_new_state = cand_state;
        best_abs_delta = std::fabs(delta);
      }
    }

    if (!std::isfinite(min_theta)) {
      break;
    }

    if (min_theta <= 1e-12) {
      ++degenerate_streak;
    } else {
      degenerate_streak = 0;
    }

    const size_t q_idx = static_cast<size_t>(enter_var);
    if (leave_slot == -1) {
      // Bound flip on v_{enter_var} between 0 and 1 without changing the basis or w.
      const int new_state = 1 - state[q_idx];
      if (new_state == 1) {
        for (size_t j = 0; j < n; ++j) eff_rhs[j] -= 2.0 * rows_a[q_idx][j];
      } else {
        for (size_t j = 0; j < n; ++j) eff_rhs[j] += 2.0 * rows_a[q_idx][j];
      }
      state[q_idx] = new_state;
      for (size_t p = 0; p < n; ++p) {
        x_b[p] -= min_theta * enter_sigma * d[p];
      }
    } else {
      const size_t l_slot = static_cast<size_t>(leave_slot);
      const int leave_var = basis[l_slot];
      if (state[q_idx] == 1) {
        for (size_t j = 0; j < n; ++j) eff_rhs[j] += 2.0 * rows_a[q_idx][j];
      }
      if (leave_new_state == 1 && static_cast<size_t>(leave_var) < m) {
        const size_t l_idx = static_cast<size_t>(leave_var);
        for (size_t j = 0; j < n; ++j) eff_rhs[j] -= 2.0 * rows_a[l_idx][j];
      }
      state[static_cast<size_t>(leave_var)] = leave_new_state;
      state[q_idx] = 2;
      basis[l_slot] = enter_var;
      ++pivot_count;

      if ((pivot_count & 31u) == 0u) {
        eff_rhs = rhs;
        for (size_t i = 0; i < m; ++i) {
          if (state[i] == 1) {
            for (size_t j = 0; j < n; ++j) eff_rhs[j] -= 2.0 * rows_a[i][j];
          }
        }
      }

      buildBasisMatrices(m_b, m_bt, c_b);
      Vec6d next_xb{};
      Vec6d next_w{};
      if (!solveLinearSystem(n, m_b, eff_rhs, next_xb) ||
          !solveLinearSystem(n, m_bt, c_b, next_w)) {
        break;
      }
      x_b = next_xb;
      w = next_w;
      rc_dirty = true;
    }
  }

  Vec6d best_w = sanitizeWeights(w);
  if (evalPrimalL1(fallback_w) < evalPrimalL1(best_w)) {
    best_w = fallback_w;
  }

  // Normalize in single precision so sum_{j=0}^{n-1} out_weights[j] == 1.0f within float precision.
  float sum_f = 0.0f;
  for (size_t j = 0; j < n; ++j) {
    out_weights[j] = std::clamp(static_cast<float>(best_w[j]), 0.0f, 1.0f);
    sum_f += out_weights[j];
  }
  if (sum_f > 0.0f) {
    for (size_t j = 0; j < n; ++j) {
      out_weights[j] /= sum_f;
    }
  } else {
    out_weights[min_j] = 1.0f;
  }

  if (out_duality_gap != nullptr) {
    // Construct a strictly dual-feasible certificate (u in [-1, 1]^m, A^T u + lambda_cert * 1 <= 0)
    // to bound the distance from the exact global minimum.
    std::vector<double> u(m, -1.0);
    for (size_t i = 0; i < m; ++i) {
      if (state[i] == 1) {
        u[i] = 1.0;
      }
    }
    for (size_t p = 1; p < n; ++p) {
      const int bvar = basis[p];
      if (bvar >= 0 && static_cast<size_t>(bvar) < m) {
        u[static_cast<size_t>(bvar)] = std::clamp(2.0 * x_b[p] - 1.0, -1.0, 1.0);
      }
    }
    double max_atu = -std::numeric_limits<double>::infinity();
    for (size_t j = 0; j < n; ++j) {
      double acc = 0.0;
      for (size_t i = 0; i < m; ++i) {
        acc += rows_a[i][j] * u[i];
      }
      max_atu = std::max(max_atu, acc);
    }
    const double lambda_cert = -max_atu;
    double dual_obj = lambda_cert;
    for (size_t i = 0; i < m; ++i) {
      dual_obj += rows_b[i] * u[i];
    }

    Vec6d w_float_as_d{};
    for (size_t j = 0; j < n; ++j) {
      w_float_as_d[j] = static_cast<double>(out_weights[j]);
    }
    const double primal_float_obj = evalPrimalL1(w_float_as_d);
    *out_duality_gap = std::max(0.0, primal_float_obj - dual_obj);
  }

  return g_no_error;
}

uhdr_error_info_t toneMapCurveToGainCurve(const PchipInterpolator& tone_map_curve,
                                          float base_headroom_log2, float alt_headroom_log2,
                                          PchipInterpolator& out_gain_curve) {
  const std::vector<float>& x_values = tone_map_curve.x();
  const std::vector<float>& y_values = tone_map_curve.y();
  const std::vector<float>& slopes = tone_map_curve.slopes();
  if (x_values.empty() || y_values.size() != x_values.size() || slopes.size() != x_values.size()) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                     "Invalid or empty tone_map_curve in toneMapCurveToGainCurve");
  }

  const size_t num_points = x_values.size();
  std::vector<float> gains_log2(num_points, 0.0f);
  std::vector<float> gain_slopes(num_points, 0.0f);

  for (size_t i = 0; i < num_points; ++i) {
    const float x = x_values[i];
    const float y = y_values[i];
    float gain_log2 = 0.0f;
    bool was_clamped = false;

    float slope = slopes[i];
    if (x == 0.0f && i + 1 < num_points && x_values[i + 1] > x) {
      const float secant = (y_values[i + 1] - y) / (x_values[i + 1] - x);
      if (secant > 0.0f) {
        slope = std::max(slope, 0.5f * secant);
      }
    }

    if (x != 0.0f) {
      const float linear_gain = y / x;
      const float raw_gain_log2 = (linear_gain > 0.0f) ? std::log2(linear_gain) : 0.0f;
      gain_log2 = clampGainForHeadroom(raw_gain_log2, base_headroom_log2, alt_headroom_log2);
      was_clamped = (gain_log2 != raw_gain_log2);
    } else if (slope > 0.0f) {
      // L'Hopital's rule at x = 0: lim_{x->0} f(x)/x = f'(0).
      const float raw_gain_log2 = std::log2(slope);
      gain_log2 = clampGainForHeadroom(raw_gain_log2, base_headroom_log2, alt_headroom_log2);
      was_clamped = (gain_log2 != raw_gain_log2);
    }
    gains_log2[i] = gain_log2;

    float slope_log2 = 0.0f;
    if (!was_clamped) {
      if (x != 0.0f) {
        const float linear_gain = std::exp2(gain_log2);
        const float denominator = x * kLn2 * linear_gain;
        if (std::fabs(denominator) > 1e-6f) {
          slope_log2 = (slope - linear_gain) / denominator;
        }
      } else if (i + 1 < num_points && x_values[i + 1] > x && slope > 0.0f) {
        // Double L'Hopital's rule at x = 0: g'(0) = f''(0) / (2 * ln(2) * f'(0)).
        const float h = x_values[i + 1] - x;
        const float secant = (y_values[i + 1] - y) / h;
        const float m0 = slope;
        const float m1 = slopes[i + 1];
        const float tm_second_deriv = 2.0f * (3.0f * secant - 2.0f * m0 - m1) / h;
        slope_log2 = tm_second_deriv / (2.0f * kLn2 * m0);
      }
    }
    gain_slopes[i] = slope_log2;
  }

  return PchipInterpolator::create(x_values, gains_log2, gain_slopes, out_gain_curve);
}

}  // namespace smpte2094_50

static uhdr_error_info_t validateRawImagePlanesAndStrides(const uhdr_raw_image_t* image,
                                                          const char* caller_name) {
  if (image->w == 0 || image->h == 0) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Empty image dimensions in %s", caller_name);
  }
  switch (image->fmt) {
    case UHDR_IMG_FMT_24bppRGB888:
    case UHDR_IMG_FMT_32bppRGBA8888:
    case UHDR_IMG_FMT_32bppRGBA1010102:
    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
      if (image->planes[UHDR_PLANE_PACKED] == nullptr ||
          image->stride[UHDR_PLANE_PACKED] < image->w) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                               "Invalid packed plane or stride in %s", caller_name);
      }
      return g_no_error;
    case UHDR_IMG_FMT_8bppYCbCr400:
      if (image->planes[UHDR_PLANE_Y] == nullptr || image->stride[UHDR_PLANE_Y] < image->w) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                               "Invalid YCbCr400 plane or stride in %s", caller_name);
      }
      return g_no_error;
    case UHDR_IMG_FMT_24bppYCbCrP010:
      if (image->planes[UHDR_PLANE_Y] == nullptr || image->planes[UHDR_PLANE_UV] == nullptr ||
          image->stride[UHDR_PLANE_Y] < image->w || image->stride[UHDR_PLANE_UV] < image->w) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid P010 plane or stride in %s",
                               caller_name);
      }
      return g_no_error;
    case UHDR_IMG_FMT_24bppYCbCr444:
    case UHDR_IMG_FMT_30bppYCbCr444:
    case UHDR_IMG_FMT_16bppYCbCr422:
    case UHDR_IMG_FMT_12bppYCbCr420: {
      const unsigned int min_uv_stride = (image->fmt == UHDR_IMG_FMT_24bppYCbCr444 ||
                                          image->fmt == UHDR_IMG_FMT_30bppYCbCr444)
                                             ? image->w
                                             : (image->w + 1u) / 2u;
      if (image->planes[UHDR_PLANE_Y] == nullptr || image->planes[UHDR_PLANE_U] == nullptr ||
          image->planes[UHDR_PLANE_V] == nullptr || image->stride[UHDR_PLANE_Y] < image->w ||
          image->stride[UHDR_PLANE_U] < min_uv_stride ||
          image->stride[UHDR_PLANE_V] < min_uv_stride) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid YUV plane or stride in %s",
                               caller_name);
      }
      return g_no_error;
    }
    default:
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Unsupported image format in %s",
                             caller_name);
  }
}

static uhdr_error_info_t validateGenerateGainMapInputs(
    const uhdr_raw_image_t* image, const smpte2094_50::DynamicMetadata& metadata,
    float hdr_capacity_max, SamplePixelFn& sample_pixel_fn, LuminanceFn& luminance_fn,
    ColorTransformFn& yuv_to_rgb_fn, bool& is_rgb) {
  sample_pixel_fn = getSamplePixelFn(image->fmt);
  if (sample_pixel_fn == nullptr) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Unsupported image format in generateGainMap");
  }
  luminance_fn = getLuminanceFn(image->cg);
  if (luminance_fn == nullptr) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Unsupported color gamut in generateGainMap");
  }
  is_rgb = isPixelFormatRgb(image->fmt);
  yuv_to_rgb_fn = getYuvToRgbFn(image->cg);
  if (!is_rgb && yuv_to_rgb_fn == nullptr) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Missing YUV-to-RGB conversion in generateGainMap");
  }
  UHDR_ERR_CHECK(validateRawImagePlanesAndStrides(image, "generateGainMap"));
  if (!std::isfinite(hdr_capacity_max) || (hdr_capacity_max >= 0.0f && hdr_capacity_max < 1.0f)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid hdr_capacity_max in generateGainMap");
  }
  if (!std::isfinite(metadata.hdr_reference_white) || metadata.hdr_reference_white <= 0.0f ||
      !std::isfinite(metadata.baseline_hdr_headroom_log2) ||
      metadata.baseline_hdr_headroom_log2 < 0.0f || metadata.baseline_hdr_headroom_log2 > 6.0f) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Invalid baseline headroom or reference white in generateGainMap");
  }
  return g_no_error;
}

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
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                             "Null image or gainmap_metadata in generateGainMap");
  }

  SamplePixelFn sample_pixel_fn = nullptr;
  LuminanceFn luminance_fn = nullptr;
  ColorTransformFn yuv_to_rgb_fn = nullptr;
  bool is_rgb = false;
  uhdr_error_info_t input_status =
      validateGenerateGainMapInputs(image, metadata, hdr_capacity_max, sample_pixel_fn,
                                    luminance_fn, yuv_to_rgb_fn, is_rgb);
  if (input_status.error_code != UHDR_CODEC_OK) {
    return input_status;
  }

  smpte2094_50::DynamicMetadata local_metadata = metadata;
  uhdr_error_info_t smpte_status = smpte2094_50::populateImplicitParameters(local_metadata);
  if (smpte_status.error_code != UHDR_CODEC_OK) {
    return smpte_status;
  }

  float max_headroom_log2 = local_metadata.baseline_hdr_headroom_log2;
  for (const auto& rule : local_metadata.rules) {
    if (!std::isfinite(rule.alternate_hdr_headroom_log2) ||
        rule.alternate_hdr_headroom_log2 < 0.0f || rule.alternate_hdr_headroom_log2 > 6.0f) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                               "Invalid alternate_hdr_headroom in generateGainMap");
    }
    for (float w : {rule.mix.rgb[0], rule.mix.rgb[1], rule.mix.rgb[2], rule.mix.max, rule.mix.min,
                    rule.mix.component}) {
      if (!std::isfinite(w) || w < 0.0f) {
        return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                                 "Invalid component mix weight in generateGainMap");
      }
    }
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
    for (const auto& cp : rule.curve) {
      cp_x.push_back(cp.x);
      cp_y.push_back(cp.y);
      cp_m.push_back(cp.m);
    }

    smpte2094_50::GainCurve curve;
    uhdr_error_info_t curve_status = smpte2094_50::GainCurve::create(cp_x, cp_y, cp_m, curve);
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

  for (unsigned int py = 0; py < image->h; ++py) {
    for (unsigned int px = 0; px < image->w; ++px) {
      Color pixel = sample_pixel_fn(image, 1, px, py);
      if (!is_rgb && yuv_to_rgb_fn != nullptr) {
        pixel = yuv_to_rgb_fn(pixel);
      }
      const float luma = luminance_fn(pixel);

      auto evalGain = [&](const Evaluator& ev) -> float {
        if (ev.is_baseline) {
          return 0.0f;
        }
        const float x = applyMix(pixel, ev.mix, luma);
        const int32_t lut_idx =
            CLIP3(static_cast<int32_t>(x * (kGainFactorNumEntries - 1) + 0.5f), 0,
                  static_cast<int32_t>(kGainFactorNumEntries) - 1);
        return ev.log2GainLUT[lut_idx];
      };

      float logGain = 0.0f;
      if (evaluators.size() > 1) {
        const Evaluator& ev0 = evaluators[idx];
        const Evaluator& ev1 = evaluators[idx + 1];
        const float w1 = (ev1.H == ev0.H) ? 0.0f : (target_H - ev0.H) / (ev1.H - ev0.H);
        logGain = (1.0f - w1) * evalGain(ev0) + w1 * evalGain(ev1);
      } else {
        logGain = evalGain(evaluators[0]);
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

namespace {

struct HagcSamplePoint {
  std::array<float, 3> base_rgb = {0.0f, 0.0f, 0.0f};
  std::array<float, 3> gain_log2 = {0.0f, 0.0f, 0.0f};
};

std::array<float, 3> getLumaWeightsForGamut(uhdr_color_gamut_t cg) {
  switch (cg) {
    case UHDR_CG_BT_709:
      return {0.2126f, 0.7152f, 0.0722f};
    case UHDR_CG_DISPLAY_P3:
      return {0.228975f, 0.691739f, 0.079287f};
    case UHDR_CG_BT_2100:
    default:
      return {0.2627f, 0.6780f, 0.0593f};
  }
}

std::array<float, 8> getChromaticitiesForGamut(uhdr_color_gamut_t cg) {
  switch (cg) {
    case UHDR_CG_BT_709:
      return smpte2094_50::DynamicMetadata::kChromaticitiesSrgb;
    case UHDR_CG_DISPLAY_P3:
      return smpte2094_50::DynamicMetadata::kChromaticitiesDisplayP3;
    case UHDR_CG_BT_2100:
    default:
      return smpte2094_50::DynamicMetadata::kChromaticitiesRec2020;
  }
}

smpte2094_50::ComponentMix getInitialComponentMix(smpte2094_50::HagcComponentMixMode mode,
                                                  uhdr_color_gamut_t cg) {
  smpte2094_50::ComponentMix mix{};
  const std::array<float, 3> luma = getLumaWeightsForGamut(cg);
  switch (mode) {
    case smpte2094_50::HagcComponentMixMode::kMaxRgb:
      mix.max = 1.0f;
      break;
    case smpte2094_50::HagcComponentMixMode::kHalfLumaHalfMax:
      mix.rgb = {0.5f * luma[0], 0.5f * luma[1], 0.5f * luma[2]};
      mix.max = 0.5f;
      break;
    case smpte2094_50::HagcComponentMixMode::kOptimize:
    case smpte2094_50::HagcComponentMixMode::kOptimize4:
    case smpte2094_50::HagcComponentMixMode::kLuma:
    default:
      mix.rgb = luma;
      break;
  }
  return mix;
}

Color sampleGainMapBilinear(uhdr_raw_image_t* gainmap_img, GetPixelFn gm_get_pixel, size_t base_w,
                            size_t base_h, size_t px, size_t py) {
  const size_t gm_w = gainmap_img->w;
  const size_t gm_h = gainmap_img->h;
  if (gm_w == base_w && gm_h == base_h) {
    return gm_get_pixel(gainmap_img, px, py);
  }
  const float fx = std::clamp(
      (static_cast<float>(px) + 0.5f) * (static_cast<float>(gm_w) / static_cast<float>(base_w)) -
          0.5f,
      0.0f, static_cast<float>(gm_w - 1u));
  const float fy = std::clamp(
      (static_cast<float>(py) + 0.5f) * (static_cast<float>(gm_h) / static_cast<float>(base_h)) -
          0.5f,
      0.0f, static_cast<float>(gm_h - 1u));

  const size_t x0 = static_cast<size_t>(fx);
  const size_t y0 = static_cast<size_t>(fy);
  const size_t x1 = std::min(x0 + 1u, gm_w - 1u);
  const size_t y1 = std::min(y0 + 1u, gm_h - 1u);
  const float tx = fx - static_cast<float>(x0);
  const float ty = fy - static_cast<float>(y0);

  const Color c00 = gm_get_pixel(gainmap_img, x0, y0);
  const Color c10 = gm_get_pixel(gainmap_img, x1, y0);
  const Color c01 = gm_get_pixel(gainmap_img, x0, y1);
  const Color c11 = gm_get_pixel(gainmap_img, x1, y1);

  const Color top = c00 * (1.0f - tx) + c10 * tx;
  const Color bot = c01 * (1.0f - tx) + c11 * tx;
  return top * (1.0f - ty) + bot * ty;
}

void evaluateMixedPairs(const std::vector<HagcSamplePoint>& samples, bool gm_is_1ch,
                        const smpte2094_50::ComponentMix& mix, std::vector<float>& out_values,
                        std::vector<float>& out_gains) {
  const double sum = static_cast<double>(mix.rgb[0]) + static_cast<double>(mix.rgb[1]) +
                     static_cast<double>(mix.rgb[2]) + static_cast<double>(mix.max) +
                     static_cast<double>(mix.min) + static_cast<double>(mix.component);
  if (sum <= 0.0) {
    out_values.assign(samples.size(), 0.0f);
    out_gains.assign(samples.size(), 0.0f);
    return;
  }

  const float inv_sum = static_cast<float>(1.0 / sum);
  const float wr = mix.rgb[0] * inv_sum;
  const float wg = mix.rgb[1] * inv_sum;
  const float wb = mix.rgb[2] * inv_sum;
  const float wmax = mix.max * inv_sum;
  const float wmin = mix.min * inv_sum;
  const float wcomp = mix.component * inv_sum;

  const bool per_channel = (wcomp != 0.0f);
  const size_t total = samples.size() * (per_channel ? 3u : 1u);
  out_values.resize(total);
  out_gains.resize(total);

  size_t idx = 0;
  for (const HagcSamplePoint& s : samples) {
    const float r = s.base_rgb[0];
    const float g = s.base_rgb[1];
    const float b = s.base_rgb[2];
    float common = wr * r + wg * g + wb * b;
    if (wmax != 0.0f) common += wmax * std::max({r, g, b});
    if (wmin != 0.0f) common += wmin * std::min({r, g, b});

    if (!per_channel) {
      out_values[idx] = common;
      out_gains[idx] =
          gm_is_1ch ? s.gain_log2[0]
                    : ((s.gain_log2[0] + s.gain_log2[1] + s.gain_log2[2]) / 3.0f);
      ++idx;
    } else {
      for (size_t c = 0; c < 3u; ++c) {
        out_values[idx] = common + wcomp * s.base_rgb[c];
        out_gains[idx] = gm_is_1ch ? s.gain_log2[0] : s.gain_log2[c];
        ++idx;
      }
    }
  }
}

void computeMovingWindowCurvePoints(const std::vector<HagcSamplePoint>& samples, bool gm_is_1ch,
                                    const smpte2094_50::ComponentMix& mix,
                                    smpte2094_50::HagcFitHeuristic heuristic, float base_h,
                                    float alt_h, std::vector<float>& out_values,
                                    std::vector<float>& out_gains) {
  std::vector<float> raw_values;
  std::vector<float> raw_gains;
  evaluateMixedPairs(samples, gm_is_1ch, mix, raw_values, raw_gains);

  const size_t n = raw_values.size();
  if (n == 0) {
    out_values = {0.0f};
    out_gains = {0.0f};
    return;
  }

  std::vector<std::pair<float, float>> pairs(n);
  float max_val = 0.0f;
  for (size_t i = 0; i < n; ++i) {
    pairs[i] = {raw_values[i], raw_gains[i]};
    max_val = std::max(max_val, raw_values[i]);
  }
  std::sort(pairs.begin(), pairs.end());

  const auto clamp_sign_gain = [&](float g) {
    return (alt_h > base_h) ? std::max(g, 0.0f) : std::min(g, 0.0f);
  };

  if (max_val <= 0.0f) {
    float avg = 0.0f;
    for (const auto& p : pairs) avg += p.second;
    avg /= static_cast<float>(n);
    out_values = {0.0f};
    out_gains = {clamp_sign_gain(avg)};
    return;
  }

  const float scale = max_val / 255.0f;
  out_values.clear();
  out_gains.clear();

  size_t ind_min = 0;
  constexpr int kWindowSize = 5;
  std::vector<float> median_buf;
  for (int i = 0; i < 256; ++i) {
    const float lo = static_cast<float>(i - kWindowSize) * scale;
    const float hi = static_cast<float>(i + kWindowSize) * scale;
    while (ind_min + 1u < n && pairs[ind_min].first < lo) {
      ++ind_min;
    }
    if (pairs[ind_min].first > hi) {
      continue;
    }
    size_t ind_max = ind_min;
    while (ind_max + 1u < n && pairs[ind_max + 1u].first <= hi) {
      ++ind_max;
    }

    float g_val = 0.0f;
    if (heuristic == smpte2094_50::HagcFitHeuristic::kMovingMedian) {
      const size_t count = ind_max - ind_min + 1u;
      median_buf.resize(count);
      for (size_t k = 0; k < count; ++k) {
        median_buf[k] = pairs[ind_min + k].second;
      }
      const size_t mid = count / 2u;
      std::nth_element(median_buf.begin(), median_buf.begin() + static_cast<ptrdiff_t>(mid),
                       median_buf.end());
      g_val = median_buf[mid];
    } else {
      double acc = 0.0;
      for (size_t j = ind_min; j <= ind_max; ++j) {
        acc += static_cast<double>(pairs[j].second);
      }
      g_val = static_cast<float>(acc / static_cast<double>(ind_max - ind_min + 1u));
    }
    out_values.push_back(static_cast<float>(i) * scale);
    out_gains.push_back(clamp_sign_gain(g_val));
  }

  if (out_values.empty()) {
    out_values = {0.0f};
    out_gains = {0.0f};
  }
}

float getPerceptualWeight(float x, float hdr_reference_white) {
  constexpr float kMaxWeight = 10.0f;
  if (x <= 0.0f) return kMaxWeight;
  const float normalized = (x * hdr_reference_white) / 10000.0f;
  constexpr float kLn10k = 9.210340371976184f;
  const float slope = 1.0f / (normalized * kLn10k);
  return std::min(slope, kMaxWeight);
}

uhdr_error_info_t fitQuantileToneMapGainCurve(const std::vector<HagcSamplePoint>& samples,
                                              const smpte2094_50::ComponentMix& mix,
                                              size_t num_control_points, float base_h, float alt_h,
                                              float hdr_ref_white,
                                              smpte2094_50::PchipInterpolator& out_gain_curve) {
  smpte2094_50::ComponentMix gray_mix = mix;
  gray_mix.component = 0.0f;

  std::vector<float> base_gray(samples.size(), 0.0f);
  std::vector<float> alt_gray(samples.size(), 0.0f);
  const double msum = static_cast<double>(gray_mix.rgb[0]) + static_cast<double>(gray_mix.rgb[1]) +
                      static_cast<double>(gray_mix.rgb[2]) + static_cast<double>(gray_mix.max) +
                      static_cast<double>(gray_mix.min);
  const float inv = (msum > 0.0) ? static_cast<float>(1.0 / msum) : 1.0f;

  for (size_t i = 0; i < samples.size(); ++i) {
    const auto& s = samples[i];
    const std::array<float, 3> alt_rgb = {s.base_rgb[0] * std::exp2(s.gain_log2[0]),
                                          s.base_rgb[1] * std::exp2(s.gain_log2[1]),
                                          s.base_rgb[2] * std::exp2(s.gain_log2[2])};
    auto eval_gray = [&](const std::array<float, 3>& rgb) {
      if (msum <= 0.0) return rgb[0];
      float v = (gray_mix.rgb[0] * rgb[0] + gray_mix.rgb[1] * rgb[1] + gray_mix.rgb[2] * rgb[2]) *
                inv;
      if (gray_mix.max != 0.0f) v += (gray_mix.max * inv) * std::max({rgb[0], rgb[1], rgb[2]});
      if (gray_mix.min != 0.0f) v += (gray_mix.min * inv) * std::min({rgb[0], rgb[1], rgb[2]});
      return v;
    };
    base_gray[i] = eval_gray(s.base_rgb);
    alt_gray[i] = eval_gray(alt_rgb);
  }

  std::sort(base_gray.begin(), base_gray.end());
  std::sort(alt_gray.begin(), alt_gray.end());

  const float base_max_lin = std::exp2(base_h);
  const float alt_max_lin = std::exp2(alt_h);
  const size_t base_above = static_cast<size_t>(
      base_gray.end() - std::upper_bound(base_gray.begin(), base_gray.end(), base_max_lin));
  const size_t alt_above = static_cast<size_t>(
      alt_gray.end() - std::upper_bound(alt_gray.begin(), alt_gray.end(), alt_max_lin));
  const size_t discard = std::max(base_above, alt_above);
  const size_t kept = (discard < base_gray.size()) ? (base_gray.size() - discard) : 1u;
  base_gray.resize(kept);
  alt_gray.resize(kept);

  // Deduplicate x and clamp y so tone-mapping does not cross y = x.
  std::vector<float> px;
  std::vector<float> py;
  for (size_t i = 0; i < kept; ++i) {
    const float xv = base_gray[i];
    const float yv = (alt_h > base_h) ? std::max(alt_gray[i], xv) : std::min(alt_gray[i], xv);
    if (!px.empty() && xv == px.back()) {
      py.back() = yv;
    } else {
      px.push_back(xv);
      py.push_back(yv);
    }
  }

  const size_t n = px.size();
  const size_t target_cp = std::min(num_control_points, n);
  std::vector<bool> selected(n, false);
  selected[0] = true;
  if (n > 1u && target_cp > 1u) {
    selected[n - 1u] = true;
  }

  const size_t extra = (target_cp > 2u && n > 2u) ? (target_cp - 2u) : 0u;
  for (size_t iter = 0; iter < extra; ++iter) {
    std::vector<float> cur_x;
    std::vector<float> cur_y;
    for (size_t j = 0; j < n; ++j) {
      if (selected[j]) {
        cur_x.push_back(px[j]);
        cur_y.push_back(py[j]);
      }
    }
    smpte2094_50::PchipInterpolator tm_curve;
    uhdr_error_info_t st = smpte2094_50::PchipInterpolator::create(cur_x, cur_y, tm_curve);
    if (st.error_code != UHDR_CODEC_OK) return st;

    smpte2094_50::PchipInterpolator gc;
    st = smpte2094_50::toneMapCurveToGainCurve(tm_curve, base_h, alt_h, gc);
    if (st.error_code != UHDR_CODEC_OK) return st;

    const float x_span = px.back() - px.front();
    float min_dist_allowed = x_span / ((static_cast<float>(cur_x.size()) + 1.0f) * 4.0f);
    size_t best_idx = n;
    double max_err = 0.0;

    while (best_idx == n && min_dist_allowed > 1e-5f) {
      for (size_t j = 0; j < n; ++j) {
        if (selected[j]) continue;
        float min_dist = x_span;
        for (float cx : cur_x) {
          min_dist = std::min(min_dist, std::fabs(px[j] - cx));
        }
        if (min_dist < min_dist_allowed) continue;

        const float y_interp = px[j] * std::exp2(gc.interpolate(px[j]));
        const double per_err = static_cast<double>(std::fabs(y_interp - py[j])) *
                               static_cast<double>(getPerceptualWeight(py[j], hdr_ref_white));
        if (per_err > max_err) {
          max_err = per_err;
          best_idx = j;
        }
      }
      if (best_idx == n) {
        min_dist_allowed *= 0.5f;
      }
    }
    if (best_idx < n) {
      selected[best_idx] = true;
    } else {
      break;
    }
  }

  std::vector<float> sub_x;
  std::vector<float> sub_y;
  for (size_t j = 0; j < n; ++j) {
    if (selected[j]) {
      sub_x.push_back(px[j]);
      sub_y.push_back(py[j]);
    }
  }
  smpte2094_50::PchipInterpolator final_tm;
  uhdr_error_info_t st = smpte2094_50::PchipInterpolator::create(sub_x, sub_y, final_tm);
  if (st.error_code != UHDR_CODEC_OK) return st;
  return smpte2094_50::toneMapCurveToGainCurve(final_tm, base_h, alt_h, out_gain_curve);
}

uhdr_error_info_t solveForBestComponentMix(const std::vector<HagcSamplePoint>& samples,
                                           bool gm_is_1ch,
                                           smpte2094_50::HagcComponentMixMode mix_mode,
                                           const smpte2094_50::PchipInterpolator& gain_curve_pchip,
                                           size_t max_rows, smpte2094_50::ComponentMix& inout_mix) {
  if (mix_mode != smpte2094_50::HagcComponentMixMode::kOptimize &&
      mix_mode != smpte2094_50::HagcComponentMixMode::kOptimize4) {
    return g_no_error;
  }

  const std::vector<float>& ys = gain_curve_pchip.y();
  if (ys.size() < 2u) {
    return g_no_error;
  }
  const auto minmax = std::minmax_element(ys.begin(), ys.end());
  if (*minmax.second - *minmax.first <= 1e-5f) {
    // Constant gain curve: output is invariant to component mix weights.
    return g_no_error;
  }

  smpte2094_50::GainCurve gain_curve;
  uhdr_error_info_t status = smpte2094_50::GainCurve::create(
      gain_curve_pchip.x(), gain_curve_pchip.y(), gain_curve_pchip.slopes(), gain_curve);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }

  const size_t ch_count = gm_is_1ch ? 1u : 3u;
  const size_t num_vars =
      (mix_mode == smpte2094_50::HagcComponentMixMode::kOptimize4) ? 4u : (gm_is_1ch ? 5u : 6u);

  const size_t cap = samples.size() * ch_count;
  std::vector<std::array<float, 6>> cand_a(cap);
  std::vector<float> cand_b(cap, 0.0f);
  size_t count = 0;

  for (const HagcSamplePoint& s : samples) {
    const float cr = s.base_rgb[0];
    const float cg = s.base_rgb[1];
    const float cb = s.base_rgb[2];
    const float cmax = std::max({cr, cg, cb});
    const float cmin = std::min({cr, cg, cb});
    for (size_t c = 0; c < ch_count; ++c) {
      float target_x = 0.0f;
      if (!gain_curve.reverseInterpolate(s.gain_log2[c], target_x)) {
        continue;
      }
      cand_a[count] = {cr, cg, cb, cmax, cmin, s.base_rgb[c]};
      cand_b[count] = target_x;
      ++count;
    }
  }

  if (count == 0) {
    return g_no_error;
  }

  const size_t kept_rows = std::min(count, std::max<size_t>(1u, max_rows));
  std::vector<float> flat_a(kept_rows * num_vars, 0.0f);
  std::vector<float> flat_b(kept_rows, 0.0f);
  for (size_t i = 0; i < kept_rows; ++i) {
    const size_t src_idx = (kept_rows > 1u && count > kept_rows)
                               ? ((i * (count - 1u)) / (kept_rows - 1u))
                               : i;
    for (size_t j = 0; j < num_vars; ++j) {
      flat_a[i * num_vars + j] = cand_a[src_idx][j];
    }
    flat_b[i] = cand_b[src_idx];
  }

  std::array<float, smpte2094_50::DynamicMetadata::kNumMixCoefficients> weights{};
  status = smpte2094_50::solveConstrainedL1Simplex(flat_a.data(), flat_b.data(), kept_rows,
                                                   num_vars, weights);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }

  inout_mix.rgb = {weights[0], weights[1], weights[2]};
  inout_mix.max = weights[3];
  inout_mix.min = weights[4];
  inout_mix.component = weights[5];
  return g_no_error;
}

}  // namespace

uhdr_error_info_t deriveHagcFromGainMap(
    uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
    const uhdr_gainmap_metadata_ext_t* gainmap_metadata, smpte2094_50::DynamicMetadata& out_hagc,
    const smpte2094_50::HagcDerivationOptions& options) {
  if (sdr_intent == nullptr || gainmap_img == nullptr || gainmap_metadata == nullptr) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Null image or metadata pointer in deriveHagcFromGainMap");
  }
  if (options.num_control_points == 0 ||
      options.num_control_points > smpte2094_50::DynamicMetadata::kMaxNumControlPoints ||
      options.max_samples == 0) {
    return makeStatusError(
        UHDR_CODEC_INVALID_PARAM,
        "num_control_points must be in [1, 32] and max_samples >= 1 in deriveHagcFromGainMap");
  }
  if (!std::isfinite(gainmap_metadata->hdr_capacity_min) ||
      !std::isfinite(gainmap_metadata->hdr_capacity_max) ||
      gainmap_metadata->hdr_capacity_min <= 0.0f || gainmap_metadata->hdr_capacity_max <= 0.0f) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Invalid hdr_capacity_min/max in deriveHagcFromGainMap");
  }
  for (int c = 0; c < 3; ++c) {
    if (!std::isfinite(gainmap_metadata->min_content_boost[c]) ||
        !std::isfinite(gainmap_metadata->max_content_boost[c]) ||
        !std::isfinite(gainmap_metadata->gamma[c]) ||
        !std::isfinite(gainmap_metadata->offset_sdr[c]) ||
        !std::isfinite(gainmap_metadata->offset_hdr[c]) ||
        gainmap_metadata->min_content_boost[c] <= 0.0f ||
        gainmap_metadata->max_content_boost[c] < gainmap_metadata->min_content_boost[c] ||
        gainmap_metadata->gamma[c] <= 0.0f || gainmap_metadata->offset_sdr[c] < 0.0f ||
        gainmap_metadata->offset_hdr[c] < 0.0f) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                             "Invalid gainmap channel parameters in deriveHagcFromGainMap");
    }
  }

  const uhdr_color_gamut_t base_cg =
      (sdr_intent->cg == UHDR_CG_UNSPECIFIED) ? UHDR_CG_BT_709 : sdr_intent->cg;
  if (base_cg != UHDR_CG_BT_709 && base_cg != UHDR_CG_DISPLAY_P3 && base_cg != UHDR_CG_BT_2100) {
    return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                           "Unsupported base color gamut in deriveHagcFromGainMap");
  }

  const uhdr_color_transfer_t base_ct =
      (sdr_intent->ct == UHDR_CT_UNSPECIFIED) ? UHDR_CT_SRGB : sdr_intent->ct;
  ColorTransformFn inv_oetf = getInverseOetfFn(base_ct);
  SceneToDisplayLuminanceFn base_ootf = getOotfFn(base_ct);
  LuminanceFn base_luma_fn = getLuminanceFn(base_cg);
  if (inv_oetf == nullptr || base_ootf == nullptr || base_luma_fn == nullptr) {
    return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                           "Unsupported base transfer function in deriveHagcFromGainMap");
  }

  GetPixelFn base_get_pixel = getPixelFn(sdr_intent->fmt);
  GetPixelFn gm_get_pixel = getPixelFn(gainmap_img->fmt);
  if (base_get_pixel == nullptr || gm_get_pixel == nullptr) {
    return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                           "Unsupported pixel format in deriveHagcFromGainMap");
  }
  if (gainmap_img->fmt != UHDR_IMG_FMT_8bppYCbCr400 &&
      gainmap_img->fmt != UHDR_IMG_FMT_24bppRGB888 &&
      gainmap_img->fmt != UHDR_IMG_FMT_32bppRGBA8888) {
    return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                           "Gain map format must be YCbCr400, RGB888, or RGBA8888");
  }
  UHDR_ERR_CHECK(validateRawImagePlanesAndStrides(sdr_intent, "deriveHagcFromGainMap sdr_intent"));
  UHDR_ERR_CHECK(validateRawImagePlanesAndStrides(gainmap_img, "deriveHagcFromGainMap gainmap_img"));

  const bool base_is_rgb =
      isPixelFormatRgb(sdr_intent->fmt) || sdr_intent->fmt == UHDR_IMG_FMT_24bppRGB888;
  ColorTransformFn base_yuv_to_rgb = options.sdr_is_601 ? p3YuvToRgb : getYuvToRgbFn(base_cg);
  if (!base_is_rgb && base_yuv_to_rgb == nullptr) {
    return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                             "Missing YUV-to-RGB conversion for base gamut");
  }

  uhdr_color_gamut_t app_cg = base_cg;
  ColorTransformFn base_to_app_gamut = identityConversion;
  if (!gainmap_metadata->use_base_cg && gainmap_img->cg != UHDR_CG_UNSPECIFIED &&
      gainmap_img->cg != base_cg) {
    app_cg = gainmap_img->cg;
    base_to_app_gamut = getGamutConversionFn(app_cg, base_cg);
    if (base_to_app_gamut == nullptr) {
      return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                               "Unsupported gain application color gamut");
    }
  }

  float base_sdr_scale = 1.0f;
  if (base_ct == UHDR_CT_HLG || base_ct == UHDR_CT_PQ) {
    const float peak_nits = getReferenceDisplayPeakLuminanceInNits(base_ct);
    if (peak_nits > 0.0f) {
      base_sdr_scale = peak_nits / kSdrWhiteNits;
    }
  }

  const float raw_base_h = std::log2(gainmap_metadata->hdr_capacity_min);
  const float raw_alt_h = std::log2(gainmap_metadata->hdr_capacity_max);
  const float base_h = std::clamp(raw_base_h, 0.0f, 6.0f);
  const float alt_h = std::clamp(raw_alt_h, 0.0f, 6.0f);

  out_hagc = smpte2094_50::DynamicMetadata{};
  out_hagc.hdr_reference_white = smpte2094_50::DynamicMetadata::kDefaultHdrReferenceWhite;
  out_hagc.has_adaptive_tone_map_flag = true;
  out_hagc.use_reference_white_tone_mapping_flag = false;
  out_hagc.baseline_hdr_headroom_log2 = base_h;
  out_hagc.gain_application_space_chromaticities = getChromaticitiesForGamut(app_cg);

  const long q_base_h = std::lround(static_cast<double>(base_h) * 10000.0);
  const long q_alt_h = std::lround(static_cast<double>(alt_h) * 10000.0);
  if (q_base_h == q_alt_h) {
    // Identity headroom: ST 2094-50 represents identity via zero alternate rules.
    out_hagc.rules.clear();
    return smpte2094_50::validateDynamicMetadata(out_hagc);
  }

  const size_t w = sdr_intent->w;
  const size_t h = sdr_intent->h;
  const size_t max_samples = options.max_samples;
  const bool gm_is_1ch = (gainmap_img->fmt == UHDR_IMG_FMT_8bppYCbCr400);

  // Build a deterministic set of <= max_samples coordinates combining global extrema + 2D grid.
  std::vector<std::pair<size_t, size_t>> coords;
  auto pushUniqueCoord = [&](size_t cx, size_t cy) {
    if (coords.size() >= max_samples) return;
    for (const auto& existing : coords) {
      if (existing.first == cx && existing.second == cy) return;
    }
    coords.emplace_back(cx, cy);
  };

  if (w * h <= max_samples) {
    for (size_t py = 0; py < h; ++py) {
      for (size_t px = 0; px < w; ++px) {
        coords.emplace_back(px, py);
      }
    }
  } else {
    // Fast coarse extrema scan (<= 48x48) to capture brightest/darkest base & gainmap locations.
    if (max_samples >= 16u) {
      const size_t scan_x = std::min<size_t>(w, 48u);
      const size_t scan_y = std::min<size_t>(h, 48u);
      float min_b = std::numeric_limits<float>::infinity();
      float max_b = -std::numeric_limits<float>::infinity();
      float min_g = std::numeric_limits<float>::infinity();
      float max_g = -std::numeric_limits<float>::infinity();
      std::pair<size_t, size_t> pos_min_b{0, 0}, pos_max_b{0, 0}, pos_min_g{0, 0}, pos_max_g{0, 0};

      for (size_t sy = 0; sy < scan_y; ++sy) {
        const size_t py = (scan_y > 1u) ? ((sy * (h - 1u)) / (scan_y - 1u)) : 0u;
        for (size_t sx = 0; sx < scan_x; ++sx) {
          const size_t px = (scan_x > 1u) ? ((sx * (w - 1u)) / (scan_x - 1u)) : 0u;
          Color bp = base_get_pixel(sdr_intent, px, py);
          if (!base_is_rgb) bp = base_yuv_to_rgb(bp);
          const float b_metric = bp.r + bp.g + bp.b;
          if (b_metric < min_b) {
            min_b = b_metric;
            pos_min_b = {px, py};
          }
          if (b_metric > max_b) {
            max_b = b_metric;
            pos_max_b = {px, py};
          }

          const size_t gx = (px * gainmap_img->w) / w;
          const size_t gy = (py * gainmap_img->h) / h;
          const Color gp = gm_get_pixel(gainmap_img, gx, gy);
          const float g_metric = gm_is_1ch ? gp.y : (gp.r + gp.g + gp.b);
          if (g_metric < min_g) {
            min_g = g_metric;
            pos_min_g = {px, py};
          }
          if (g_metric > max_g) {
            max_g = g_metric;
            pos_max_g = {px, py};
          }
        }
      }
      pushUniqueCoord(pos_min_b.first, pos_min_b.second);
      pushUniqueCoord(pos_max_b.first, pos_max_b.second);
      pushUniqueCoord(pos_min_g.first, pos_min_g.second);
      pushUniqueCoord(pos_max_g.first, pos_max_g.second);
    }

    const size_t rem = max_samples - coords.size();
    const double aspect = static_cast<double>(w) / static_cast<double>(h);
    size_t grid_w = static_cast<size_t>(std::max(
        1.0, std::floor(std::sqrt(static_cast<double>(rem) * aspect))));
    grid_w = std::min(grid_w, w);
    size_t grid_h = std::max<size_t>(1u, rem / grid_w);
    grid_h = std::min(grid_h, h);
    while (grid_w * grid_h > rem && grid_h > 1u) {
      --grid_h;
    }

    for (size_t gy = 0; gy < grid_h; ++gy) {
      const size_t py = (grid_h > 1u) ? ((gy * (h - 1u)) / (grid_h - 1u)) : (h / 2u);
      for (size_t gx = 0; gx < grid_w; ++gx) {
        const size_t px = (grid_w > 1u) ? ((gx * (w - 1u)) / (grid_w - 1u)) : (w / 2u);
        pushUniqueCoord(px, py);
      }
    }
  }

  std::array<float, 3> log2_min_boost{};
  std::array<float, 3> log2_max_boost{};
  std::array<float, 3> inv_gamma{};
  bool has_offsets = false;
  for (int c = 0; c < 3; ++c) {
    log2_min_boost[c] = std::log2(gainmap_metadata->min_content_boost[c]);
    log2_max_boost[c] = std::log2(gainmap_metadata->max_content_boost[c]);
    inv_gamma[c] = 1.0f / gainmap_metadata->gamma[c];
    if (gainmap_metadata->offset_sdr[c] != 0.0f || gainmap_metadata->offset_hdr[c] != 0.0f) {
      has_offsets = true;
    }
  }
  const float headroom_weight =
      (std::fabs(raw_alt_h - raw_base_h) > 1e-6f) ? ((alt_h - base_h) / (raw_alt_h - raw_base_h))
                                                  : 1.0f;

  std::vector<HagcSamplePoint> samples(coords.size());
  for (size_t i = 0; i < coords.size(); ++i) {
    const size_t px = coords[i].first;
    const size_t py = coords[i].second;

    Color bp = base_get_pixel(sdr_intent, px, py);
    if (!base_is_rgb) {
      bp = base_yuv_to_rgb(bp);
    }
    if (base_ct != UHDR_CT_LINEAR) {
      bp = clampPixelFloat(bp);
    }
    Color lin = inv_oetf(bp);
    lin = base_ootf(lin, base_luma_fn) * base_sdr_scale;
    lin = base_to_app_gamut(lin);
    lin = clipNegatives(lin);

    const Color gp = sampleGainMapBilinear(gainmap_img, gm_get_pixel, w, h, px, py);
    const std::array<float, 3> g_enc =
        gm_is_1ch ? std::array<float, 3>{gp.y, gp.y, gp.y} : std::array<float, 3>{gp.r, gp.g, gp.b};
    const std::array<float, 3> base_arr = {lin.r, lin.g, lin.b};

    std::array<float, 3> raw_g{};
    for (int c = 0; c < 3; ++c) {
      const int mc = (gm_is_1ch && gainmap_metadata->are_all_channels_identical()) ? 0 : c;
      const float gc_clamped = std::clamp(g_enc[c], 0.0f, 1.0f);
      const float gc_lin = (inv_gamma[mc] == 1.0f) ? gc_clamped : std::pow(gc_clamped, inv_gamma[mc]);
      raw_g[c] = (log2_min_boost[mc] + (log2_max_boost[mc] - log2_min_boost[mc]) * gc_lin) *
                 headroom_weight;
    }

    std::array<float, 3> eff_g = raw_g;
    if (has_offsets) {
      constexpr float kEps = 1e-6f;
      float nz_sum = 0.0f;
      int nz_cnt = 0;
      for (int c = 0; c < 3; ++c) {
        const float alt_c =
            std::max((base_arr[c] + gainmap_metadata->offset_sdr[c]) * std::exp2(raw_g[c]) -
                         gainmap_metadata->offset_hdr[c],
                     0.0f);
        if (base_arr[c] > kEps) {
          eff_g[c] = (alt_c > 1e-12f) ? std::log2(alt_c / base_arr[c]) : -6.0f;
          nz_sum += eff_g[c];
          ++nz_cnt;
        }
      }
      const float fallback_g = (nz_cnt > 0) ? (nz_sum / static_cast<float>(nz_cnt)) : raw_g[0];
      for (int c = 0; c < 3; ++c) {
        if (base_arr[c] <= kEps) {
          eff_g[c] = fallback_g;
        }
      }
      if (gm_is_1ch) {
        const float avg_g = (eff_g[0] + eff_g[1] + eff_g[2]) / 3.0f;
        eff_g = {avg_g, avg_g, avg_g};
      }
    }

    samples[i].base_rgb = base_arr;
    samples[i].gain_log2 = eff_g;
  }

  smpte2094_50::ComponentMix mix = getInitialComponentMix(options.mix_mode, app_cg);
  smpte2094_50::PchipInterpolator gain_curve_pchip;
  bool use_pchip_slope_flag = true;

  if (options.heuristic == smpte2094_50::HagcFitHeuristic::kQuantileToneMap) {
    use_pchip_slope_flag = false;
    uhdr_error_info_t st = fitQuantileToneMapGainCurve(
        samples, mix, options.num_control_points, base_h, alt_h, out_hagc.hdr_reference_white,
        gain_curve_pchip);
    if (st.error_code != UHDR_CODEC_OK) {
      return st;
    }
    st = solveForBestComponentMix(samples, gm_is_1ch, options.mix_mode, gain_curve_pchip,
                                  options.max_samples, mix);
    if (st.error_code != UHDR_CODEC_OK) {
      return st;
    }
  } else {
    use_pchip_slope_flag = true;
    constexpr int kNumIterations = 2;
    for (int iter = 0; iter < kNumIterations; ++iter) {
      std::vector<float> values;
      std::vector<float> gains;
      computeMovingWindowCurvePoints(samples, gm_is_1ch, mix, options.heuristic, base_h, alt_h,
                                     values, gains);
      uhdr_error_info_t st =
          smpte2094_50::createSubsampledPchip(values, gains, options.num_control_points,
                                              gain_curve_pchip);
      if (st.error_code != UHDR_CODEC_OK) {
        return st;
      }
      st = solveForBestComponentMix(samples, gm_is_1ch, options.mix_mode, gain_curve_pchip,
                                    options.max_samples, mix);
      if (st.error_code != UHDR_CODEC_OK) {
        return st;
      }
    }
  }

  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = alt_h;
  rule.mix = mix;
  rule.use_pchip_slope = use_pchip_slope_flag;

  const std::vector<float>& cx = gain_curve_pchip.x();
  const std::vector<float>& cy = gain_curve_pchip.y();
  const std::vector<float>& cm = gain_curve_pchip.slopes();
  for (size_t i = 0; i < cx.size(); ++i) {
    const float x_clamped = std::clamp(cx[i], 0.0f, 64.0f);
    const float y_signed = (alt_h > base_h) ? std::clamp(cy[i], 0.0f, 6.0f)
                                            : std::clamp(cy[i], -6.0f, 0.0f);
    const float m_clamped = std::isfinite(cm[i]) ? std::clamp(cm[i], -1e4f, 1e4f) : 0.0f;

    const long q_x = std::lround(static_cast<double>(x_clamped) * 1000.0);
    if (!rule.curve.empty()) {
      const long prev_q_x = std::lround(static_cast<double>(rule.curve.back().x) * 1000.0);
      if (q_x == prev_q_x) {
        // Deduplicate knots that collide on the Annex C 1e-3 x-grid to guarantee continuity.
        rule.curve.back() = {x_clamped, y_signed, m_clamped};
        continue;
      }
    }
    rule.curve.push_back({x_clamped, y_signed, m_clamped});
  }

  if (rule.curve.empty()) {
    rule.curve.push_back({0.0f, 0.0f, 0.0f});
  }
  if (rule.use_pchip_slope) {
    std::vector<float> rx(rule.curve.size());
    std::vector<float> ry(rule.curve.size());
    for (size_t i = 0; i < rule.curve.size(); ++i) {
      rx[i] = rule.curve[i].x;
      ry[i] = rule.curve[i].y;
    }
    std::vector<float> rslopes;
    uhdr_error_info_t st = smpte2094_50::computePchipSlopes(rx, ry, rslopes);
    if (st.error_code != UHDR_CODEC_OK) {
      return st;
    }
    for (size_t i = 0; i < rule.curve.size(); ++i) {
      rule.curve[i].m = rslopes[i];
    }
  }

  out_hagc.rules = {std::move(rule)};
  return smpte2094_50::validateDynamicMetadata(out_hagc);
}

uhdr_error_info_t deriveEncodedHagcFromGainMap(
    uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
    const uhdr_gainmap_metadata_ext_t* gainmap_metadata, std::vector<uint8_t>& out_bitstream,
    const smpte2094_50::HagcDerivationOptions& options) {
  smpte2094_50::DynamicMetadata hagc{};
  uhdr_error_info_t status =
      deriveHagcFromGainMap(sdr_intent, gainmap_img, gainmap_metadata, hagc, options);
  if (status.error_code != UHDR_CODEC_OK) {
    return status;
  }
  return smpte2094_50::encodeSt2094_50(hagc, out_bitstream);
}

namespace {

struct Mat3d {
  double m[3][3] = {{1.0, 0.0, 0.0}, {0.0, 1.0, 0.0}, {0.0, 0.0, 1.0}};
};

struct Mat3f {
  float m[3][3] = {{1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, 0.0f, 1.0f}};
};

Mat3d mulMat3d(const Mat3d& a, const Mat3d& b) {
  Mat3d out{{{0.0, 0.0, 0.0}, {0.0, 0.0, 0.0}, {0.0, 0.0, 0.0}}};
  for (int r = 0; r < 3; ++r) {
    for (int c = 0; c < 3; ++c) {
      out.m[r][c] = a.m[r][0] * b.m[0][c] + a.m[r][1] * b.m[1][c] + a.m[r][2] * b.m[2][c];
    }
  }
  return out;
}

std::array<double, 3> mulMatVec3d(const Mat3d& a, const std::array<double, 3>& v) {
  return {a.m[0][0] * v[0] + a.m[0][1] * v[1] + a.m[0][2] * v[2],
          a.m[1][0] * v[0] + a.m[1][1] * v[1] + a.m[1][2] * v[2],
          a.m[2][0] * v[0] + a.m[2][1] * v[1] + a.m[2][2] * v[2]};
}

bool invertMat3d(const Mat3d& src, Mat3d& dst) {
  const double a00 = src.m[0][0], a01 = src.m[0][1], a02 = src.m[0][2];
  const double a10 = src.m[1][0], a11 = src.m[1][1], a12 = src.m[1][2];
  const double a20 = src.m[2][0], a21 = src.m[2][1], a22 = src.m[2][2];

  const double c00 = a11 * a22 - a12 * a21;
  const double c01 = -(a10 * a22 - a12 * a20);
  const double c02 = a10 * a21 - a11 * a20;
  const double det = a00 * c00 + a01 * c01 + a02 * c02;
  if (!std::isfinite(det) || std::fabs(det) <= 1e-12) {
    return false;
  }
  const double inv_det = 1.0 / det;
  dst.m[0][0] = c00 * inv_det;
  dst.m[0][1] = -(a01 * a22 - a02 * a21) * inv_det;
  dst.m[0][2] = (a01 * a12 - a02 * a11) * inv_det;
  dst.m[1][0] = c01 * inv_det;
  dst.m[1][1] = (a00 * a22 - a02 * a20) * inv_det;
  dst.m[1][2] = -(a00 * a12 - a02 * a10) * inv_det;
  dst.m[2][0] = c02 * inv_det;
  dst.m[2][1] = -(a00 * a21 - a01 * a20) * inv_det;
  dst.m[2][2] = (a00 * a11 - a01 * a10) * inv_det;
  for (int r = 0; r < 3; ++r) {
    for (int c = 0; c < 3; ++c) {
      if (!std::isfinite(dst.m[r][c])) {
        return false;
      }
    }
  }
  return true;
}

bool primariesToXYZD50(const std::array<float, 8>& ch, Mat3d& out_to_xyz, Mat3d& out_from_xyz) {
  for (float v : ch) {
    if (!std::isfinite(v) || v < 0.0f || v > 1.0f) {
      return false;
    }
  }
  const double rx = ch[0], ry = ch[1];
  const double gx = ch[2], gy = ch[3];
  const double bx = ch[4], by = ch[5];
  const double wx = ch[6], wy = ch[7];
  if (wy <= 1e-6) {
    return false;
  }

  const Mat3d primaries{
      {{rx, gx, bx}, {ry, gy, by}, {1.0 - rx - ry, 1.0 - gx - gy, 1.0 - bx - by}}};
  Mat3d primaries_inv{};
  if (!invertMat3d(primaries, primaries_inv)) {
    return false;
  }

  const std::array<double, 3> w_xyz = {wx / wy, 1.0, (1.0 - wx - wy) / wy};
  const std::array<double, 3> scale = mulMatVec3d(primaries_inv, w_xyz);
  const Mat3d diag_scale{{{scale[0], 0.0, 0.0}, {0.0, scale[1], 0.0}, {0.0, 0.0, scale[2]}}};
  const Mat3d to_xyz = mulMat3d(primaries, diag_scale);

  // Bradford chromatic adaptation from (wx, wy) to PCS D50 (matching skcms_AdaptToXYZD50).
  constexpr Mat3d kXyzToLms = {
      {{0.8951, 0.2664, -0.1614}, {-0.7502, 1.7135, 0.0367}, {0.0389, -0.0685, 1.0296}}};
  constexpr Mat3d kLmsToXyz = {{{0.9869929, -0.1470543, 0.1599627},
                                {0.4323053, 0.5183603, 0.0492912},
                                {-0.0085287, 0.0400428, 0.9684867}}};
  constexpr std::array<double, 3> kWxyzD50 = {0.96422, 1.0, 0.82521};

  const std::array<double, 3> src_cone = mulMatVec3d(kXyzToLms, w_xyz);
  const std::array<double, 3> dst_cone = mulMatVec3d(kXyzToLms, kWxyzD50);
  if (std::fabs(src_cone[0]) <= 1e-12 || std::fabs(src_cone[1]) <= 1e-12 ||
      std::fabs(src_cone[2]) <= 1e-12) {
    return false;
  }
  const Mat3d cone_scale{{{dst_cone[0] / src_cone[0], 0.0, 0.0},
                          {0.0, dst_cone[1] / src_cone[1], 0.0},
                          {0.0, 0.0, dst_cone[2] / src_cone[2]}}};
  const Mat3d adapt = mulMat3d(kLmsToXyz, mulMat3d(cone_scale, kXyzToLms));
  out_to_xyz = mulMat3d(adapt, to_xyz);
  return invertMat3d(out_to_xyz, out_from_xyz);
}

bool toMat3fChecked(const Mat3d& d, Mat3f& out) {
  for (int r = 0; r < 3; ++r) {
    for (int c = 0; c < 3; ++c) {
      const float v = static_cast<float>(d.m[r][c]);
      if (!std::isfinite(v)) {
        return false;
      }
      out.m[r][c] = v;
    }
  }
  return true;
}

inline Color applyMat3f(const Mat3f& m, const Color& c) {
  return {{{m.m[0][0] * c.r + m.m[0][1] * c.g + m.m[0][2] * c.b,
            m.m[1][0] * c.r + m.m[1][1] * c.g + m.m[1][2] * c.b,
            m.m[2][0] * c.r + m.m[2][1] * c.g + m.m[2][2] * c.b}}};
}

struct PreparedRule {
  smpte2094_50::GainCurve curve;
  float wr = 0.0f;
  float wg = 0.0f;
  float wb = 0.0f;
  float wmax = 0.0f;
  float wmin = 0.0f;
  float wcomp = 0.0f;
  float weight = 0.0f;
};

uhdr_error_info_t prepareActiveRules(const smpte2094_50::DynamicMetadata& hagc, float h_target,
                                     std::array<PreparedRule, 2>& out_rules,
                                     size_t& out_num_rules) {
  out_num_rules = 0;
  struct HeadroomSlot {
    float h = 0.0f;
    int rule_idx = -1;
  };
  std::array<HeadroomSlot, smpte2094_50::DynamicMetadata::kMaxNumAlternateImages + 1> slots{};
  size_t num_slots = 0;
  bool baseline_inserted = false;
  for (size_t i = 0; i < hagc.rules.size(); ++i) {
    if (!baseline_inserted &&
        hagc.baseline_hdr_headroom_log2 < hagc.rules[i].alternate_hdr_headroom_log2) {
      slots[num_slots++] = {hagc.baseline_hdr_headroom_log2, -1};
      baseline_inserted = true;
    }
    slots[num_slots++] = {hagc.rules[i].alternate_hdr_headroom_log2, static_cast<int>(i)};
  }
  if (!baseline_inserted) {
    slots[num_slots++] = {hagc.baseline_hdr_headroom_log2, -1};
  }

  const float h_clamped = std::clamp(h_target, slots[0].h, slots[num_slots - 1].h);
  std::array<std::pair<int, float>, 2> weighted = {{{-1, 0.0f}, {-1, 0.0f}}};
  if (num_slots == 1 || h_clamped <= slots[0].h) {
    weighted[0] = {slots[0].rule_idx, 1.0f};
  } else if (h_clamped >= slots[num_slots - 1].h) {
    weighted[0] = {slots[num_slots - 1].rule_idx, 1.0f};
  } else {
    for (size_t i = 0; i + 1 < num_slots; ++i) {
      if (h_clamped >= slots[i].h && h_clamped <= slots[i + 1].h) {
        const float span = slots[i + 1].h - slots[i].h;
        const float w1 = (span > 0.0f) ? (h_clamped - slots[i].h) / span : 0.0f;
        const float w0 = 1.0f - w1;
        weighted[0] = {slots[i].rule_idx, w0};
        weighted[1] = {slots[i + 1].rule_idx, w1};
        break;
      }
    }
  }

  for (const auto& [r_idx, w] : weighted) {
    if (r_idx < 0 || w <= 0.0f) {
      continue;
    }
    const smpte2094_50::ToneMappingRule& rule = hagc.rules[static_cast<size_t>(r_idx)];
    PreparedRule prep{};
    prep.weight = w;
    const double sum = static_cast<double>(rule.mix.rgb[0]) + static_cast<double>(rule.mix.rgb[1]) +
                       static_cast<double>(rule.mix.rgb[2]) + static_cast<double>(rule.mix.max) +
                       static_cast<double>(rule.mix.min) + static_cast<double>(rule.mix.component);
    if (sum <= 0.0) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM, "ComponentMix weights sum to <= 0");
    }
    const float inv_sum = static_cast<float>(1.0 / sum);
    prep.wr = rule.mix.rgb[0] * inv_sum;
    prep.wg = rule.mix.rgb[1] * inv_sum;
    prep.wb = rule.mix.rgb[2] * inv_sum;
    prep.wmax = rule.mix.max * inv_sum;
    prep.wmin = rule.mix.min * inv_sum;
    prep.wcomp = rule.mix.component * inv_sum;

    std::vector<float> xs(rule.curve.size());
    std::vector<float> ys(rule.curve.size());
    std::vector<float> ms(rule.curve.size());
    for (size_t k = 0; k < rule.curve.size(); ++k) {
      xs[k] = rule.curve[k].x;
      ys[k] = rule.curve[k].y;
      ms[k] = rule.curve[k].m;
    }
    uhdr_error_info_t st = rule.use_pchip_slope
                               ? smpte2094_50::GainCurve::create(xs, ys, prep.curve)
                               : smpte2094_50::GainCurve::create(xs, ys, ms, prep.curve);
    if (st.error_code != UHDR_CODEC_OK) {
      return st;
    }
    out_rules[out_num_rules++] = std::move(prep);
  }
  return g_no_error;
}

inline Color evalRuleLog2Gain(const PreparedRule& r, const Color& c) {
  float common = r.wr * c.r + r.wg * c.g + r.wb * c.b;
  if (r.wmax > 0.0f) {
    common += r.wmax * std::max({c.r, c.g, c.b});
  }
  if (r.wmin > 0.0f) {
    common += r.wmin * std::min({c.r, c.g, c.b});
  }
  if (r.wcomp == 0.0f) {
    const float g = r.curve.interpolate(common);
    return {{{g, g, g}}};
  }
  return {
      {{r.curve.interpolate(common + r.wcomp * c.r), r.curve.interpolate(common + r.wcomp * c.g),
        r.curve.interpolate(common + r.wcomp * c.b)}}};
}

}  // namespace

uhdr_error_info_t parseAndValidateHagcFromIcc(const void* icc_data, size_t icc_size,
                                              smpte2094_50::DynamicMetadata& out_hagc) {
  std::vector<uint8_t> hagc_bytes;
  if (!IccHelper::readIccHagc(icc_data, icc_size, hagc_bytes)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "ICC profile does not contain a valid HAGC tag");
  }
  UHDR_ERR_CHECK(smpte2094_50::parseSt2094_50(hagc_bytes.data(), hagc_bytes.size(), out_hagc));
  if (!out_hagc.has_adaptive_tone_map_flag) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "HAGC metadata has_adaptive_tone_map_flag is false");
  }
  Mat3d app_to_xyz{}, app_from_xyz{};
  Mat3f app_to_xyz_f{}, app_from_xyz_f{};
  if (!primariesToXYZD50(out_hagc.gain_application_space_chromaticities, app_to_xyz,
                         app_from_xyz) ||
      !toMat3fChecked(app_to_xyz, app_to_xyz_f) || !toMat3fChecked(app_from_xyz, app_from_xyz_f)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "HAGC gain_application_space_chromaticities are non-invertible");
  }
  return g_no_error;
}

void populateGainMapMetadataFromHagc(const smpte2094_50::DynamicMetadata& hagc,
                                     uhdr_color_gamut_t base_cg,
                                     uhdr_gainmap_metadata_t* out_metadata) {
  if (out_metadata == nullptr) {
    return;
  }
  const uhdr_color_gamut_t eff_cg = (base_cg == UHDR_CG_UNSPECIFIED) ? UHDR_CG_BT_709 : base_cg;
  float h_min = hagc.baseline_hdr_headroom_log2;
  float h_max = hagc.baseline_hdr_headroom_log2;
  float y_min = 0.0f;
  float y_max = 0.0f;
  for (const auto& rule : hagc.rules) {
    h_min = std::min(h_min, rule.alternate_hdr_headroom_log2);
    h_max = std::max(h_max, rule.alternate_hdr_headroom_log2);
    for (const auto& cp : rule.curve) {
      y_min = std::min(y_min, cp.y);
      y_max = std::max(y_max, cp.y);
    }
  }
  const float min_boost = std::exp2(y_min);
  const float max_boost = std::max(min_boost, std::exp2(y_max));
  for (int c = 0; c < 3; ++c) {
    out_metadata->min_content_boost[c] = min_boost;
    out_metadata->max_content_boost[c] = max_boost;
    out_metadata->gamma[c] = 1.0f;
    out_metadata->offset_sdr[c] = 0.0f;
    out_metadata->offset_hdr[c] = 0.0f;
  }
  out_metadata->hdr_capacity_min = std::max(1.0f, std::exp2(h_min));
  out_metadata->hdr_capacity_max = std::max(out_metadata->hdr_capacity_min, std::exp2(h_max));
  out_metadata->use_base_cg =
      (hagc.gain_application_space_chromaticities == getChromaticitiesForGamut(eff_cg)) ? 1 : 0;
}

uhdr_error_info_t applyHagc(uhdr_raw_image_t* base_img,
                            const smpte2094_50::DynamicMetadata& metadata,
                            uhdr_color_transfer_t output_ct,
                            [[maybe_unused]] uhdr_img_fmt_t output_format, float max_display_boost,
                            bool base_is_601_yuv, uhdr_raw_image_t* dest) {
  if (base_img == nullptr || dest == nullptr) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Null image pointer in applyHagc");
  }
  if (std::isnan(max_display_boost) || max_display_boost < 1.0f) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Invalid max_display_boost %f in applyHagc",
                           max_display_boost);
  }
  UHDR_ERR_CHECK(validateRawImagePlanesAndStrides(base_img, "applyHagc(base_img)"));
  UHDR_ERR_CHECK(validateRawImagePlanesAndStrides(dest, "applyHagc(dest)"));
  if (dest->w != base_img->w || dest->h != base_img->h) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Destination dimensions %ux%u do not match base dimensions %ux%u",
                           dest->w, dest->h, base_img->w, base_img->h);
  }
  if ((output_ct == UHDR_CT_SRGB && dest->fmt != UHDR_IMG_FMT_32bppRGBA8888) ||
      (output_ct == UHDR_CT_LINEAR && dest->fmt != UHDR_IMG_FMT_64bppRGBAHalfFloat) ||
      ((output_ct == UHDR_CT_HLG || output_ct == UHDR_CT_PQ) &&
       dest->fmt != UHDR_IMG_FMT_32bppRGBA1010102) ||
      (output_ct != UHDR_CT_SRGB && output_ct != UHDR_CT_LINEAR && output_ct != UHDR_CT_HLG &&
       output_ct != UHDR_CT_PQ)) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Unsupported output transfer (%d) / format (%d) pair in applyHagc",
                           output_ct, dest->fmt);
  }

  GetPixelFn get_pixel_fn = getPixelFn(base_img->fmt);
  if (get_pixel_fn == nullptr) {
    return makeStatusError(UHDR_CODEC_UNSUPPORTED_FEATURE,
                           "Unsupported base pixel format %d in applyHagc", base_img->fmt);
  }

  smpte2094_50::DynamicMetadata hagc = metadata;
  if (!hagc.has_adaptive_tone_map_flag) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "applyHagc requires has_adaptive_tone_map_flag == true");
  }
  UHDR_ERR_CHECK(smpte2094_50::populateImplicitParameters(hagc));
  UHDR_ERR_CHECK(smpte2094_50::validateDynamicMetadata(hagc));

  const uhdr_color_gamut_t base_cg =
      (base_img->cg == UHDR_CG_UNSPECIFIED) ? UHDR_CG_BT_709 : base_img->cg;
  if (base_cg != UHDR_CG_BT_709 && base_cg != UHDR_CG_DISPLAY_P3 && base_cg != UHDR_CG_BT_2100) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM, "Unsupported base color gamut %d in applyHagc",
                           base_cg);
  }
  const uhdr_color_transfer_t base_ct =
      (base_img->ct == UHDR_CT_UNSPECIFIED) ? UHDR_CT_SRGB : base_img->ct;
  ColorTransformFn inv_oetf_fn = getInverseOetfFn(base_ct);
  if (inv_oetf_fn == nullptr) {
    return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                           "Unsupported base color transfer %d in applyHagc", base_ct);
  }
  LuminanceFn base_luma_fn = getLuminanceFn(base_cg);
  const bool is_rgb = isPixelFormatRgb(base_img->fmt) || base_img->fmt == UHDR_IMG_FMT_24bppRGB888;
  ColorTransformFn yuv_to_rgb_fn = base_is_601_yuv ? p3YuvToRgb : getYuvToRgbFn(base_cg);

  const std::array<float, 8> base_chrom = getChromaticitiesForGamut(base_cg);
  const bool need_gamut_xform = (hagc.gain_application_space_chromaticities != base_chrom);
  Mat3f base_to_app{};
  Mat3f app_to_base{};
  if (need_gamut_xform) {
    Mat3d base_to_xyz{}, base_from_xyz{}, app_to_xyz{}, app_from_xyz{};
    if (!primariesToXYZD50(base_chrom, base_to_xyz, base_from_xyz) ||
        !primariesToXYZD50(hagc.gain_application_space_chromaticities, app_to_xyz, app_from_xyz) ||
        !toMat3fChecked(mulMat3d(app_from_xyz, base_to_xyz), base_to_app) ||
        !toMat3fChecked(mulMat3d(base_from_xyz, app_to_xyz), app_to_base)) {
      return makeStatusError(UHDR_CODEC_INVALID_PARAM,
                             "Failed to construct gamut conversion matrices in applyHagc");
    }
  }

  float h_target = 0.0f;
  if (output_ct != UHDR_CT_SRGB) {
    h_target =
        std::isinf(max_display_boost) ? 6.0f : std::clamp(std::log2(max_display_boost), 0.0f, 6.0f);
  }

  std::array<PreparedRule, 2> active_rules{};
  size_t num_active_rules = 0;
  UHDR_ERR_CHECK(prepareActiveRules(hagc, h_target, active_rules, num_active_rules));

  float input_ref_white_scale = 1.0f;
  if (base_ct == UHDR_CT_PQ) {
    input_ref_white_scale = kPqMaxNits / hagc.hdr_reference_white;
  } else if (base_ct == UHDR_CT_HLG) {
    input_ref_white_scale = kHlgMaxNits / hagc.hdr_reference_white;
  } else if (base_ct == UHDR_CT_LINEAR) {
    input_ref_white_scale = kSdrWhiteNits / hagc.hdr_reference_white;
  }

  const float out_linear_scale = hagc.hdr_reference_white / kSdrWhiteNits;
  const float out_hlg_scale = hagc.hdr_reference_white / kHlgMaxNits;
  const float out_pq_scale = hagc.hdr_reference_white / kPqMaxNits;

  auto processRows = [&](unsigned int y_begin, unsigned int y_end) {
    const unsigned int width = base_img->w;
    const size_t dst_stride = dest->stride[UHDR_PLANE_PACKED];
    for (unsigned int y = y_begin; y < y_end; ++y) {
      for (unsigned int x = 0; x < width; ++x) {
        Color rgb_gamma = get_pixel_fn(base_img, x, y);
        if (!is_rgb) {
          rgb_gamma = yuv_to_rgb_fn(rgb_gamma);
        }
        if (base_ct != UHDR_CT_LINEAR) {
          rgb_gamma = clampPixelFloat(rgb_gamma);
        }

        Color rgb_lin = inv_oetf_fn(rgb_gamma);
        if (base_ct == UHDR_CT_HLG) {
          rgb_lin = hlgOotfApprox(rgb_lin, base_luma_fn);
        }
        if (input_ref_white_scale != 1.0f) {
          rgb_lin = rgb_lin * input_ref_white_scale;
        }

        Color c_app = need_gamut_xform ? applyMat3f(base_to_app, rgb_lin) : rgb_lin;
        if (num_active_rules > 0) {
          Color log2_gain = evalRuleLog2Gain(active_rules[0], c_app) * active_rules[0].weight;
          if (num_active_rules > 1) {
            log2_gain += evalRuleLog2Gain(active_rules[1], c_app) * active_rules[1].weight;
          }
          c_app.r *= std::exp2(log2_gain.r);
          c_app.g *= std::exp2(log2_gain.g);
          c_app.b *= std::exp2(log2_gain.b);
        }
        Color rgb_hdr = need_gamut_xform ? applyMat3f(app_to_base, c_app) : c_app;

        const size_t pixel_idx = static_cast<size_t>(x) + static_cast<size_t>(y) * dst_stride;
        switch (output_ct) {
          case UHDR_CT_SRGB: {
            Color rgb_srgb = srgbOetf(clampPixelFloat(rgb_hdr));
            const uint32_t r8 =
                static_cast<uint32_t>(CLIP3(rgb_srgb.r * 255.0f + 0.5f, 0.0f, 255.0f));
            const uint32_t g8 =
                static_cast<uint32_t>(CLIP3(rgb_srgb.g * 255.0f + 0.5f, 0.0f, 255.0f));
            const uint32_t b8 =
                static_cast<uint32_t>(CLIP3(rgb_srgb.b * 255.0f + 0.5f, 0.0f, 255.0f));
            reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
                r8 | (g8 << 8) | (b8 << 16) | (255u << 24);
            break;
          }
          case UHDR_CT_LINEAR: {
            Color out_c = clampPixelFloatLinear(rgb_hdr * out_linear_scale);
            reinterpret_cast<uint64_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
                colorToRgbaF16(out_c);
            break;
          }
          case UHDR_CT_HLG: {
#if USE_HLG_OETF_LUT
            ColorTransformFn hdr_oetf = hlgOetfLUT;
#else
            ColorTransformFn hdr_oetf = hlgOetf;
#endif
            Color out_c = clampPixelFloat(rgb_hdr * out_hlg_scale);
            out_c = hdr_oetf(hlgInverseOotfApprox(out_c));
            reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
                colorToRgba1010102(out_c);
            break;
          }
          case UHDR_CT_PQ: {
#if USE_PQ_OETF_LUT
            ColorTransformFn hdr_oetf = pqOetfLUT;
#else
            ColorTransformFn hdr_oetf = pqOetf;
#endif
            Color out_c = hdr_oetf(clampPixelFloat(rgb_hdr * out_pq_scale));
            reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
                colorToRgba1010102(out_c);
            break;
          }
          default:
            break;
        }
      }
    }
  };

  const size_t total_pixels = static_cast<size_t>(base_img->w) * static_cast<size_t>(base_img->h);
  const unsigned int hw_threads = std::max(1u, std::thread::hardware_concurrency());
  const unsigned int num_threads =
      (total_pixels >= 16384u) ? std::min({hw_threads, 4u, base_img->h}) : 1u;
  if (num_threads <= 1u) {
    processRows(0u, base_img->h);
  } else {
    std::vector<std::thread> workers;
    workers.reserve(num_threads - 1u);
    const unsigned int rows_per_thread = (base_img->h + num_threads - 1u) / num_threads;
    for (unsigned int t = 0; t < num_threads - 1u; ++t) {
      const unsigned int y0 = std::min(t * rows_per_thread, base_img->h);
      const unsigned int y1 = std::min(y0 + rows_per_thread, base_img->h);
      workers.emplace_back(processRows, y0, y1);
    }
    const unsigned int last_y0 = std::min((num_threads - 1u) * rows_per_thread, base_img->h);
    processRows(last_y0, base_img->h);
    for (auto& w : workers) {
      w.join();
    }
  }

  dest->cg = base_cg;
  dest->ct = output_ct;
  dest->range = UHDR_CR_FULL_RANGE;
  return g_no_error;
}

}  // namespace ultrahdr
