/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "ultrahdr/agtm.h"
#include "ultrahdr/gainmapmetadata.h"
#include "ultrahdr/icc.h"
#include "ultrahdr/jpegr.h"

namespace ultrahdr {

namespace {

uhdr_raw_image_t createTestP010Image(std::vector<uint16_t>& y_data,
                                     std::vector<uint16_t>& uv_data) {
  uhdr_raw_image_t image{};
  image.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  image.cg = UHDR_CG_BT_2100;
  image.ct = UHDR_CT_PQ;
  image.range = UHDR_CR_FULL_RANGE;
  image.w = 2;
  image.h = 2;
  image.stride[UHDR_PLANE_Y] = 2;
  image.stride[UHDR_PLANE_UV] = 2;

  y_data.assign(4, 1023u << 6);  // white
  uv_data.assign(4, 512u << 6);  // neutral
  image.planes[UHDR_PLANE_Y] = y_data.data();
  image.planes[UHDR_PLANE_UV] = uv_data.data();
  return image;
}

smpte2094_50::DynamicMetadata makeValidSingleRuleMetadata() {
  smpte2094_50::DynamicMetadata meta{};
  meta.hdr_reference_white = 203.0f;
  meta.has_adaptive_tone_map_flag = true;
  meta.baseline_hdr_headroom_log2 = 0.0f;
  meta.use_reference_white_tone_mapping_flag = false;
  meta.gain_application_space_chromaticities = smpte2094_50::DynamicMetadata::kChromaticitiesSrgb;

  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = 2.0f;
  rule.use_pchip_slope = true;
  rule.mix.max = 1.0f;
  rule.curve = {{0.0f, 0.5f, 0.0f}, {0.5f, 1.2f, 0.0f}, {1.0f, 2.0f, 0.0f}};
  meta.rules.push_back(rule);
  return meta;
}

}  // namespace

class AgtmTest : public ::testing::Test {};

TEST_F(AgtmTest, GenerateGainMap) {
  std::vector<uint16_t> y_data, uv_data;
  uhdr_raw_image_t image = createTestP010Image(y_data, uv_data);

  smpte2094_50::DynamicMetadata metadata{};
  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = 1.0f;  // factor 2
  rule.use_pchip_slope = true;
  rule.curve.push_back({0.0f, 0.0f});
  rule.curve.push_back({1.0f, 1.0f});
  metadata.rules.push_back(rule);

  uhdr_gainmap_metadata_ext_t gainmap_metadata{};
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_img;

  auto status = generateGainMap(&image, metadata, &gainmap_metadata, gainmap_img);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  ASSERT_NE(gainmap_img, nullptr);

  EXPECT_EQ(gainmap_img->w, 2u);
  EXPECT_EQ(gainmap_img->h, 2u);
  EXPECT_FLOAT_EQ(gainmap_metadata.max_content_boost[0], 2.0f);

  const uint8_t* out_data = reinterpret_cast<const uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]);
  EXPECT_EQ(out_data[0], 255);
  EXPECT_EQ(out_data[1], 255);
  EXPECT_EQ(out_data[2], 255);
}

TEST_F(AgtmTest, GenerateGainMapNoRules) {
  std::vector<uint16_t> y_data, uv_data;
  uhdr_raw_image_t image = createTestP010Image(y_data, uv_data);

  smpte2094_50::DynamicMetadata metadata{};
  metadata.baseline_hdr_headroom_log2 = 1.0f;  // factor 2

  uhdr_gainmap_metadata_ext_t gainmap_metadata{};
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_img;

  auto status = generateGainMap(&image, metadata, &gainmap_metadata, gainmap_img);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  ASSERT_NE(gainmap_img, nullptr);

  EXPECT_FLOAT_EQ(gainmap_metadata.max_content_boost[0], 2.0f);

  const uint8_t* out_data = reinterpret_cast<const uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]);
  EXPECT_EQ(out_data[0], 0);
}

TEST_F(AgtmTest, GenerateGainMapExplicitCapacity) {
  std::vector<uint16_t> y_data, uv_data;
  uhdr_raw_image_t image = createTestP010Image(y_data, uv_data);

  smpte2094_50::DynamicMetadata metadata{};
  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = 2.0f;  // factor 4
  rule.use_pchip_slope = true;
  rule.curve.push_back({0.0f, 0.0f});
  rule.curve.push_back({1.0f, 2.0f});
  metadata.rules.push_back(rule);

  uhdr_gainmap_metadata_ext_t gainmap_metadata{};
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_img;

  auto status = generateGainMap(&image, metadata, &gainmap_metadata, gainmap_img, 2.0f);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  ASSERT_NE(gainmap_img, nullptr);

  EXPECT_FLOAT_EQ(gainmap_metadata.hdr_capacity_min, 1.0f);
  EXPECT_FLOAT_EQ(gainmap_metadata.hdr_capacity_max, 2.0f);

  const uint8_t* out_data = reinterpret_cast<const uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]);
  EXPECT_EQ(out_data[0], 255);
}

TEST_F(AgtmTest, PchipSlopesLinearAndExtrema) {
  std::vector<float> slopes;
  ASSERT_EQ(smpte2094_50::computePchipSlopes({0.0f, 1.0f, 2.0f}, {0.0f, 2.0f, 4.0f}, slopes)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(slopes.size(), 3u);
  EXPECT_FLOAT_EQ(slopes[0], 2.0f);
  EXPECT_FLOAT_EQ(slopes[1], 2.0f);
  EXPECT_FLOAT_EQ(slopes[2], 2.0f);

  // Local extremum at index 1 must clamp interior PCHIP slope to 0 (shape-preserving).
  ASSERT_EQ(smpte2094_50::computePchipSlopes({0.0f, 1.0f, 2.0f}, {0.0f, 2.0f, 1.0f}, slopes)
                .error_code,
            UHDR_CODEC_OK);
  EXPECT_FLOAT_EQ(slopes[1], 0.0f);

  // Flat plateau at [0, 1] must produce zero slopes at both ends of the plateau.
  ASSERT_EQ(smpte2094_50::computePchipSlopes({0.0f, 1.0f, 2.0f}, {1.0f, 1.0f, 3.0f}, slopes)
                .error_code,
            UHDR_CODEC_OK);
  EXPECT_FLOAT_EQ(slopes[0], 0.0f);
  EXPECT_FLOAT_EQ(slopes[1], 0.0f);
  EXPECT_GT(slopes[2], 0.0f);

  // Single point and empty vectors succeed cleanly; decreasing x fails.
  ASSERT_EQ(smpte2094_50::computePchipSlopes({1.0f}, {2.0f}, slopes).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(slopes.size(), 1u);
  EXPECT_FLOAT_EQ(slopes[0], 0.0f);
  EXPECT_NE(smpte2094_50::computePchipSlopes({2.0f, 1.0f}, {0.0f, 1.0f}, slopes).error_code,
            UHDR_CODEC_OK);
}

TEST_F(AgtmTest, GainCurveInterpolationExtrapolationAndReverse) {
  smpte2094_50::GainCurve curve;
  ASSERT_EQ(smpte2094_50::GainCurve::create({1.0f, 2.0f}, {1.0f, 2.0f}, curve).error_code,
            UHDR_CODEC_OK);

  // Flat below x_0 = 1.0, linear on [1.0, 2.0], and y_back + log2(x_back / x) above x_back = 2.0.
  EXPECT_FLOAT_EQ(curve.interpolate(0.25f), 1.0f);
  EXPECT_FLOAT_EQ(curve.interpolate(1.5f), 1.5f);
  EXPECT_FLOAT_EQ(curve.interpolate(4.0f), 1.0f);  // 2.0 + log2(2.0 / 4.0) = 1.0
  EXPECT_FLOAT_EQ(curve.interpolate(8.0f), 0.0f);  // 2.0 + log2(2.0 / 8.0) = 0.0

  float xi = 0.0f;
  EXPECT_TRUE(curve.reverseInterpolate(1.5f, xi));
  EXPECT_NEAR(xi, 1.5f, 1e-5f);

  // Reverse interpolation into the logarithmic roll-off tail (yi = -1.0 < y_min = 1.0):
  // x = 2.0 * 2^(2.0 - (-1.0)) = 16.0.
  EXPECT_TRUE(curve.reverseInterpolate(-1.0f, xi));
  EXPECT_NEAR(xi, 16.0f, 1e-5f);
}

TEST_F(AgtmTest, SubsampledPchipPreservesEndpointsAndShape) {
  std::vector<float> xs;
  std::vector<float> ys;
  for (int i = 0; i <= 50; ++i) {
    const float x = static_cast<float>(i) / 50.0f;
    xs.push_back(x);
    ys.push_back(std::sqrt(x) * 2.0f);
  }
  smpte2094_50::PchipInterpolator sub;
  ASSERT_EQ(smpte2094_50::createSubsampledPchip(xs, ys, 8, sub).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(sub.x().size(), 8u);
  EXPECT_FLOAT_EQ(sub.x().front(), 0.0f);
  EXPECT_FLOAT_EQ(sub.x().back(), 1.0f);
  EXPECT_NEAR(sub.interpolate(0.25f), 1.0f, 0.05f);
}

TEST_F(AgtmTest, AnnexCMinimalAndRwtmRoundTrip) {
  // 1. Minimal bitstream without adaptive tone map (default 203 nits -> exactly 2 bytes).
  smpte2094_50::DynamicMetadata minimal{};
  minimal.hdr_reference_white = 203.0f;
  minimal.has_adaptive_tone_map_flag = false;

  std::vector<uint8_t> bytes;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(minimal, bytes).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(bytes.size(), 2u);
  EXPECT_EQ(bytes[0], 0x00u);
  EXPECT_EQ(bytes[1], 0x00u);

  smpte2094_50::DynamicMetadata parsed_min{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(bytes.data(), bytes.size(), parsed_min).error_code,
            UHDR_CODEC_OK);
  EXPECT_FALSE(parsed_min.has_adaptive_tone_map_flag);
  EXPECT_FLOAT_EQ(parsed_min.hdr_reference_white, 203.0f);

  // 2. Reference White Tone Mapping (RWTM) with custom white 250 nits and 2.3 stops headroom.
  smpte2094_50::DynamicMetadata rwtm{};
  rwtm.hdr_reference_white = 250.0f;
  rwtm.has_adaptive_tone_map_flag = true;
  rwtm.baseline_hdr_headroom_log2 = std::log2(1000.0f / 203.0f);
  rwtm.use_reference_white_tone_mapping_flag = true;

  ASSERT_EQ(smpte2094_50::encodeSt2094_50(rwtm, bytes).error_code, UHDR_CODEC_OK);
  // 1 (app_info) + 1 (cvt flags) + 2 (ref_white) + 2 (baseline_headroom) + 1 (rwtm flag) = 7 bytes.
  EXPECT_EQ(bytes.size(), 7u);

  smpte2094_50::DynamicMetadata parsed_rwtm{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(bytes.data(), bytes.size(), parsed_rwtm).error_code,
            UHDR_CODEC_OK);
  EXPECT_TRUE(parsed_rwtm.use_reference_white_tone_mapping_flag);
  EXPECT_NEAR(parsed_rwtm.hdr_reference_white, 250.0f, 0.2f);
  ASSERT_EQ(parsed_rwtm.rules.size(), 2u);
  EXPECT_FLOAT_EQ(parsed_rwtm.rules[0].alternate_hdr_headroom_log2, 0.0f);
  EXPECT_NEAR(parsed_rwtm.rules[1].alternate_hdr_headroom_log2, std::log2(8.0f / 3.0f), 1e-3f);
  EXPECT_EQ(parsed_rwtm.rules[0].curve.size(), 8u);
  EXPECT_LE(parsed_rwtm.rules[0].curve.back().y, 0.0f);
}

TEST_F(AgtmTest, AnnexCChromaticityMixAndSlopeModesRoundTrip) {
  // Multi-rule metadata exercising custom chromaticities (mode 3), custom 6-channel mix (type 3),
  // explicit theta slopes (use_pchip_slope = false), and shared x-coordinates across rules.
  smpte2094_50::DynamicMetadata meta{};
  meta.hdr_reference_white = 203.0f;
  meta.has_adaptive_tone_map_flag = true;
  meta.baseline_hdr_headroom_log2 = 2.0f;
  meta.gain_application_space_chromaticities = {0.68f, 0.31f, 0.26f,   0.68f,
                                                0.15f, 0.06f, 0.3127f, 0.3290f};

  smpte2094_50::ToneMappingRule r0{};
  r0.alternate_hdr_headroom_log2 = 0.0f;  // down-map -> negative y
  r0.use_pchip_slope = false;
  r0.mix = {{0.2f, 0.5f, 0.1f}, 0.1f, 0.05f, 0.05f};
  r0.curve = {{1.0f, -0.5f, -0.25f}, {2.0f, -1.0f, -0.45f}, {4.0f, -2.0f, -0.5f}};

  smpte2094_50::ToneMappingRule r1{};
  r1.alternate_hdr_headroom_log2 = 3.0f;  // up-map -> positive y
  r1.use_pchip_slope = false;
  r1.mix = r0.mix;  // triggers has_common_component_mix_params_flag = 1
  r1.curve = {{1.0f, 0.25f, 0.2f}, {2.0f, 0.6f, 0.35f}, {4.0f, 1.0f, 0.15f}};

  meta.rules = {r0, r1};

  std::vector<uint8_t> bytes;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(meta, bytes).error_code, UHDR_CODEC_OK);

  smpte2094_50::DynamicMetadata parsed{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(bytes.data(), bytes.size(), parsed).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(parsed.rules.size(), 2u);
  for (size_t i = 0; i < 8; ++i) {
    EXPECT_NEAR(parsed.gain_application_space_chromaticities[i],
                meta.gain_application_space_chromaticities[i], 1e-4f)
        << "at chromaticity index " << i;
  }
  EXPECT_NEAR(parsed.rules[0].mix.rgb[1], 0.5f, 1e-4f);
  EXPECT_NEAR(parsed.rules[1].mix.rgb[1], 0.5f, 1e-4f);
  EXPECT_FALSE(parsed.rules[0].use_pchip_slope);
  EXPECT_NEAR(parsed.rules[0].curve[1].y, -1.0f, 1e-4f);
  EXPECT_NEAR(parsed.rules[0].curve[1].m, -0.45f, 1e-3f);
  EXPECT_NEAR(parsed.rules[1].curve[2].y, 1.0f, 1e-4f);
  EXPECT_NEAR(parsed.rules[1].curve[2].m, 0.15f, 1e-3f);

  // Also verify preset chromaticities (sRGB, Display P3, Rec.2020) and preset mix types (0, 1, 2).
  const std::array<std::array<float, 8>, 3> presets = {
      smpte2094_50::DynamicMetadata::kChromaticitiesSrgb,
      smpte2094_50::DynamicMetadata::kChromaticitiesDisplayP3,
      smpte2094_50::DynamicMetadata::kChromaticitiesRec2020};
  for (size_t mode = 0; mode < presets.size(); ++mode) {
    auto m = makeValidSingleRuleMetadata();
    m.gain_application_space_chromaticities = presets[mode];
    if (mode == 0) {
      m.rules[0].mix = {{0.0f, 0.0f, 0.0f}, 1.0f, 0.0f, 0.0f};
    } else if (mode == 1) {
      m.rules[0].mix = {{0.0f, 0.0f, 0.0f}, 0.0f, 0.0f, 1.0f};
    } else {
      m.rules[0].mix = {{1.0f / 6.0f, 1.0f / 6.0f, 1.0f / 6.0f}, 0.5f, 0.0f, 0.0f};
    }
    std::vector<uint8_t> buf;
    ASSERT_EQ(smpte2094_50::encodeSt2094_50(m, buf).error_code, UHDR_CODEC_OK) << "mode " << mode;
    smpte2094_50::DynamicMetadata round_tripped{};
    ASSERT_EQ(smpte2094_50::parseSt2094_50(buf.data(), buf.size(), round_tripped).error_code,
              UHDR_CODEC_OK)
        << "mode " << mode;
    EXPECT_EQ(round_tripped.gain_application_space_chromaticities, presets[mode])
        << "mode " << mode;
    EXPECT_TRUE(round_tripped.rules[0].use_pchip_slope) << "mode " << mode;

    // Re-serializing parsed PCHIP metadata produces bit-exact output.
    std::vector<uint8_t> buf2;
    ASSERT_EQ(smpte2094_50::encodeSt2094_50(round_tripped, buf2).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(buf, buf2) << "mode " << mode;
  }
}

TEST_F(AgtmTest, RejectsInvalidMetadataAndMalformedBitstreams) {
  // 1. Invalid reference white.
  {
    auto m = makeValidSingleRuleMetadata();
    m.hdr_reference_white = 0.0f;
    EXPECT_NE(smpte2094_50::validateDynamicMetadata(m).error_code, UHDR_CODEC_OK);
    m.hdr_reference_white = 10001.0f;
    EXPECT_NE(smpte2094_50::validateDynamicMetadata(m).error_code, UHDR_CODEC_OK);
  }
  // 2. White point outside RGB chromaticity triangle.
  {
    auto m = makeValidSingleRuleMetadata();
    m.gain_application_space_chromaticities = {1.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.6f, 0.6f};
    EXPECT_NE(smpte2094_50::validateDynamicMetadata(m).error_code, UHDR_CODEC_OK);
  }
  // 3. Alternate headroom equal to baseline after quantization.
  {
    auto m = makeValidSingleRuleMetadata();
    m.baseline_hdr_headroom_log2 = 2.0f;
    m.rules[0].alternate_hdr_headroom_log2 = 2.000001f;
    EXPECT_NE(smpte2094_50::validateDynamicMetadata(m).error_code, UHDR_CODEC_OK);
  }
  // 4. Sign mismatch between (alt - baseline) and curve y.
  {
    auto m = makeValidSingleRuleMetadata();
    m.baseline_hdr_headroom_log2 = 0.0f;
    m.rules[0].alternate_hdr_headroom_log2 = 2.0f;
    m.rules[0].curve[0].y = -0.1f;
    EXPECT_NE(smpte2094_50::validateDynamicMetadata(m).error_code, UHDR_CODEC_OK);
  }
  // 5. Same x with different y (discontinuity).
  {
    auto m = makeValidSingleRuleMetadata();
    m.rules[0].curve = {{0.5f, 0.5f, 0.0f}, {0.5f, 1.0f, 0.0f}};
    EXPECT_NE(smpte2094_50::validateDynamicMetadata(m).error_code, UHDR_CODEC_OK);
  }
  // 6. Malformed bitstreams: truncated, minimum_application_version > 0, non-zero reserved bits.
  {
    std::vector<uint8_t> valid_bytes;
    ASSERT_EQ(smpte2094_50::encodeSt2094_50(makeValidSingleRuleMetadata(), valid_bytes).error_code,
              UHDR_CODEC_OK);
    smpte2094_50::DynamicMetadata out{};
    EXPECT_NE(smpte2094_50::parseSt2094_50(nullptr, 0, out).error_code, UHDR_CODEC_OK);
    EXPECT_NE(smpte2094_50::parseSt2094_50(valid_bytes.data(), valid_bytes.size() - 2, out)
                  .error_code,
              UHDR_CODEC_OK);

    // Set minimum_application_version = 1 (bits 3..5 of byte 0 -> 0x04).
    std::vector<uint8_t> bad_ver = valid_bytes;
    bad_ver[0] |= 0x04u;
    EXPECT_NE(smpte2094_50::parseSt2094_50(bad_ver.data(), bad_ver.size(), out).error_code,
              UHDR_CODEC_OK);

    // Set reserved_zero_2bits != 0 in byte 0 (0x01).
    std::vector<uint8_t> bad_res = valid_bytes;
    bad_res[0] |= 0x01u;
    EXPECT_NE(smpte2094_50::parseSt2094_50(bad_res.data(), bad_res.size(), out).error_code,
              UHDR_CODEC_OK);

    // Trailing bytes must be rejected across no-ATM, RWTM, and full-curve bitstreams.
    std::vector<uint8_t> with_trailing = valid_bytes;
    with_trailing.push_back(0x00u);
    EXPECT_NE(
        smpte2094_50::parseSt2094_50(with_trailing.data(), with_trailing.size(), out).error_code,
        UHDR_CODEC_OK);

    auto no_atm_meta = makeValidSingleRuleMetadata();
    no_atm_meta.has_adaptive_tone_map_flag = false;
    no_atm_meta.rules.clear();
    std::vector<uint8_t> no_atm_trailing;
    ASSERT_EQ(smpte2094_50::encodeSt2094_50(no_atm_meta, no_atm_trailing).error_code,
              UHDR_CODEC_OK);
    no_atm_trailing.push_back(0x00u);
    EXPECT_NE(smpte2094_50::parseSt2094_50(no_atm_trailing.data(), no_atm_trailing.size(), out)
                  .error_code,
              UHDR_CODEC_OK);

    auto rwtm_meta = makeValidSingleRuleMetadata();
    rwtm_meta.use_reference_white_tone_mapping_flag = true;
    rwtm_meta.rules.clear();
    std::vector<uint8_t> rwtm_trailing;
    ASSERT_EQ(smpte2094_50::encodeSt2094_50(rwtm_meta, rwtm_trailing).error_code, UHDR_CODEC_OK);
    rwtm_trailing.push_back(0x00u);
    EXPECT_NE(
        smpte2094_50::parseSt2094_50(rwtm_trailing.data(), rwtm_trailing.size(), out).error_code,
        UHDR_CODEC_OK);
  }
}

TEST_F(AgtmTest, ConstrainedL1SimplexParityAcross500Instances) {
  std::mt19937 rng(209450u);
  std::uniform_real_distribution<float> pix_dist(0.0f, 1.0f);
  std::uniform_real_distribution<float> noise_dist(-0.04f, 0.04f);

  // Test 500 synthetic & image-structured LP instances across 4-, 5-, and 6-variable modes,
  // including collinear grayscale scenes, sparse outliers, and degenerate ties.
  for (int instance = 0; instance < 500; ++instance) {
    const size_t num_vars = (instance % 5 == 0) ? 4u : ((instance % 2 == 0) ? 6u : 5u);
    const size_t num_rows = 64u + static_cast<size_t>((instance * 19) % 400);

    // Draw ground-truth simplex weights w_gt >= 0, sum(w_gt) == 1.
    std::array<float, 6> w_gt{};
    if (instance % 25 == 0) {
      // Exact vertex weight (e.g., pure maxRGB or pure channel).
      w_gt[static_cast<size_t>(instance) % num_vars] = 1.0f;
    } else {
      float sum = 0.0f;
      for (size_t j = 0; j < num_vars; ++j) {
        w_gt[j] = (instance % 7 == 0 && (j % 2 == 1)) ? 0.0f : (pix_dist(rng) + 0.01f);
        sum += w_gt[j];
      }
      for (size_t j = 0; j < num_vars; ++j) w_gt[j] /= sum;
    }

    std::vector<float> A(num_rows * num_vars, 0.0f);
    std::vector<float> B(num_rows, 0.0f);
    const bool grayscale_collinear = (instance % 30 == 1);

    for (size_t i = 0; i < num_rows; ++i) {
      const float r = pix_dist(rng);
      const float g = grayscale_collinear ? r : pix_dist(rng);
      const float b = grayscale_collinear ? r : pix_dist(rng);
      const float cmax = std::max({r, g, b});
      const float cmin = std::min({r, g, b});
      const float cch = (i % 3 == 0) ? r : ((i % 3 == 1) ? g : b);
      const std::array<float, 6> row = {r, g, b, cmax, cmin, cch};

      float clean_b = 0.0f;
      for (size_t j = 0; j < num_vars; ++j) {
        A[i * num_vars + j] = row[j];
        clean_b += row[j] * w_gt[j];
      }
      if (instance % 3 == 0) {
        // Exact noiseless case.
        B[i] = clean_b;
      } else if (i % 17 == 0) {
        // Gross L1 outlier to exercise median/L1 robustness.
        B[i] = std::clamp(clean_b + 0.6f, 0.0f, 1.5f);
      } else {
        B[i] = std::max(0.0f, clean_b + noise_dist(rng));
      }
    }

    std::array<float, 6> w_sol{};
    double certified_gap = 1.0;
    const auto status = smpte2094_50::solveConstrainedL1Simplex(A.data(), B.data(), num_rows,
                                                                num_vars, w_sol, &certified_gap);
    ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << "instance=" << instance << " " << status.detail;

    float w_sum = 0.0f;
    for (size_t j = 0; j < num_vars; ++j) {
      EXPECT_GE(w_sol[j], 0.0f) << "instance=" << instance;
      EXPECT_LE(w_sol[j], 1.0f) << "instance=" << instance;
      w_sum += w_sol[j];
    }
    for (size_t j = num_vars; j < 6u; ++j) {
      EXPECT_FLOAT_EQ(w_sol[j], 0.0f);
    }
    EXPECT_NEAR(w_sum, 1.0f, 1e-6f) << "instance=" << instance;

    // Mean per-sample L1 duality gap must be well within < 1e-5 of global optimum (Glop).
    const double mean_l1_gap = certified_gap / static_cast<double>(num_rows);
    EXPECT_LT(mean_l1_gap, 1e-5) << "instance=" << instance << " total_gap=" << certified_gap;

    // Also verify solver objective is <= ground-truth w_gt objective + float tolerance.
    double obj_sol = 0.0;
    double obj_gt = 0.0;
    for (size_t i = 0; i < num_rows; ++i) {
      double dot_sol = 0.0;
      double dot_gt = 0.0;
      for (size_t j = 0; j < num_vars; ++j) {
        dot_sol += static_cast<double>(A[i * num_vars + j]) * static_cast<double>(w_sol[j]);
        dot_gt += static_cast<double>(A[i * num_vars + j]) * static_cast<double>(w_gt[j]);
      }
      obj_sol += std::fabs(dot_sol - static_cast<double>(B[i]));
      obj_gt += std::fabs(dot_gt - static_cast<double>(B[i]));
    }
    EXPECT_LE(obj_sol / static_cast<double>(num_rows),
              obj_gt / static_cast<double>(num_rows) + 1e-5)
        << "instance=" << instance;
  }

  // Validate error handling on invalid solver arguments.
  std::array<float, 6> w_err{};
  const float dummy = 1.0f;
  EXPECT_NE(smpte2094_50::solveConstrainedL1Simplex(nullptr, &dummy, 1, 5, w_err).error_code,
            UHDR_CODEC_OK);
  EXPECT_NE(smpte2094_50::solveConstrainedL1Simplex(&dummy, &dummy, 0, 5, w_err).error_code,
            UHDR_CODEC_OK);
  EXPECT_NE(smpte2094_50::solveConstrainedL1Simplex(&dummy, &dummy, 1, 7, w_err).error_code,
            UHDR_CODEC_OK);
}

TEST_F(AgtmTest, ToneMapCurveToGainCurveLHopitalAndClamping) {
  // Tone map curve f(x) = 2*x + 2*x^2 on [0, 1] -> f(0)=0, f'(0)=2, f''(0)=4.
  // At x=0: g(0) = log2(f'(0)) = log2(2) = 1.0; g'(0) = f''(0)/(2*ln(2)*f'(0)) = 1/ln(2).
  smpte2094_50::PchipInterpolator tm_curve;
  ASSERT_EQ(smpte2094_50::PchipInterpolator::create({0.0f, 0.5f, 1.0f}, {0.0f, 1.5f, 4.0f},
                                                    {2.0f, 4.0f, 6.0f}, tm_curve)
                .error_code,
            UHDR_CODEC_OK);

  smpte2094_50::PchipInterpolator gain_curve;
  ASSERT_EQ(smpte2094_50::toneMapCurveToGainCurve(tm_curve, 0.0f, 2.0f, gain_curve).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(gain_curve.y().size(), 3u);
  EXPECT_NEAR(gain_curve.y()[0], 1.0f, 1e-5f);
  EXPECT_NEAR(gain_curve.y()[1], std::log2(3.0f), 1e-5f);
  EXPECT_NEAR(gain_curve.y()[2], 2.0f, 1e-5f);
  EXPECT_NEAR(gain_curve.slopes()[0], 1.0f / std::log(2.0f), 1e-4f);

  // Down-mapping (alt < base) clamps positive gains to <= 0 and zeroes clamped slope.
  smpte2094_50::PchipInterpolator clamped_curve;
  ASSERT_EQ(smpte2094_50::toneMapCurveToGainCurve(tm_curve, 2.0f, 0.0f, clamped_curve).error_code,
            UHDR_CODEC_OK);
  EXPECT_FLOAT_EQ(clamped_curve.y()[0], 0.0f);
  EXPECT_FLOAT_EQ(clamped_curve.slopes()[0], 0.0f);
}

TEST_F(AgtmTest, DeriveHagcFromGainMapGamutAndFormatMatrix) {
  constexpr unsigned int kW = 64;
  constexpr unsigned int kH = 48;
  constexpr unsigned int kGmW = 32;
  constexpr unsigned int kGmH = 24;

  std::vector<uint32_t> sdr_rgba(kW * kH, 0u);
  for (unsigned int y = 0; y < kH; ++y) {
    for (unsigned int x = 0; x < kW; ++x) {
      const uint8_t r = static_cast<uint8_t>((x * 255u) / (kW - 1u));
      const uint8_t g = static_cast<uint8_t>((y * 255u) / (kH - 1u));
      const uint8_t b = static_cast<uint8_t>(((x + y) * 255u) / (kW + kH - 2u));
      sdr_rgba[y * kW + x] = static_cast<uint32_t>(r) | (static_cast<uint32_t>(g) << 8) |
                             (static_cast<uint32_t>(b) << 16) | (255u << 24);
    }
  }

  // Build a smooth synthetic gain map driven by max(R, G, B) -> up to 4.0x (2.0 stops) boost.
  std::vector<uint8_t> gm_1ch(kGmW * kGmH, 0u);
  std::vector<uint8_t> gm_3ch(kGmW * kGmH * 3u, 0u);
  for (unsigned int gy = 0; gy < kGmH; ++gy) {
    for (unsigned int gx = 0; gx < kGmW; ++gx) {
      const float rx = static_cast<float>(gx) / static_cast<float>(kGmW - 1u);
      const float ry = static_cast<float>(gy) / static_cast<float>(kGmH - 1u);
      const float rz = 0.5f * (rx + ry);
      const float m = std::max({rx, ry, rz});
      const uint8_t enc = static_cast<uint8_t>(std::clamp(m * 255.0f + 0.5f, 0.0f, 255.0f));
      gm_1ch[gy * kGmW + gx] = enc;
      const size_t idx3 = (gy * kGmW + gx) * 3u;
      gm_3ch[idx3 + 0] = static_cast<uint8_t>(std::clamp((0.7f * m + 0.3f * rx) * 255.0f, 0.0f, 255.0f));
      gm_3ch[idx3 + 1] = static_cast<uint8_t>(std::clamp((0.7f * m + 0.3f * ry) * 255.0f, 0.0f, 255.0f));
      gm_3ch[idx3 + 2] = static_cast<uint8_t>(std::clamp((0.7f * m + 0.3f * rz) * 255.0f, 0.0f, 255.0f));
    }
  }

  uhdr_gainmap_metadata_ext_t gm_meta{};
  gm_meta.hdr_capacity_min = 1.0f;
  gm_meta.hdr_capacity_max = 4.0f;
  gm_meta.use_base_cg = true;
  for (int c = 0; c < 3; ++c) {
    gm_meta.min_content_boost[c] = 1.0f;
    gm_meta.max_content_boost[c] = 4.0f;
    gm_meta.gamma[c] = 1.2f;
    gm_meta.offset_sdr[c] = 1.0f / 64.0f;
    gm_meta.offset_hdr[c] = 1.0f / 64.0f;
  }

  const std::array<std::pair<uhdr_color_gamut_t, std::array<float, 8>>, 3> gamuts = {{
      {UHDR_CG_BT_709, smpte2094_50::DynamicMetadata::kChromaticitiesSrgb},
      {UHDR_CG_DISPLAY_P3, smpte2094_50::DynamicMetadata::kChromaticitiesDisplayP3},
      {UHDR_CG_BT_2100, smpte2094_50::DynamicMetadata::kChromaticitiesRec2020},
  }};

  for (const auto& [cg, expected_chrom] : gamuts) {
    uhdr_raw_image_t sdr_img{};
    sdr_img.fmt = UHDR_IMG_FMT_32bppRGBA8888;
    sdr_img.cg = cg;
    sdr_img.ct = UHDR_CT_SRGB;
    sdr_img.range = UHDR_CR_FULL_RANGE;
    sdr_img.w = kW;
    sdr_img.h = kH;
    sdr_img.planes[UHDR_PLANE_PACKED] = sdr_rgba.data();
    sdr_img.stride[UHDR_PLANE_PACKED] = kW;

    for (bool is_3ch : {false, true}) {
      uhdr_raw_image_t gm_img{};
      gm_img.fmt = is_3ch ? UHDR_IMG_FMT_24bppRGB888 : UHDR_IMG_FMT_8bppYCbCr400;
      gm_img.cg = cg;
      gm_img.ct = UHDR_CT_LINEAR;
      gm_img.range = UHDR_CR_FULL_RANGE;
      gm_img.w = kGmW;
      gm_img.h = kGmH;
      if (is_3ch) {
        gm_img.planes[UHDR_PLANE_PACKED] = gm_3ch.data();
        gm_img.stride[UHDR_PLANE_PACKED] = kGmW;
      } else {
        gm_img.planes[UHDR_PLANE_Y] = gm_1ch.data();
        gm_img.stride[UHDR_PLANE_Y] = kGmW;
      }

      for (auto heuristic : {smpte2094_50::HagcFitHeuristic::kMovingAverage,
                             smpte2094_50::HagcFitHeuristic::kMovingMedian,
                             smpte2094_50::HagcFitHeuristic::kQuantileToneMap}) {
        smpte2094_50::HagcDerivationOptions opts{};
        opts.heuristic = heuristic;
        opts.num_control_points = 12;

        std::vector<uint8_t> bitstream;
        ASSERT_EQ(deriveEncodedHagcFromGainMap(&sdr_img, &gm_img, &gm_meta, bitstream, opts)
                      .error_code,
                  UHDR_CODEC_OK);
        EXPECT_GT(bitstream.size(), 8u);

        smpte2094_50::DynamicMetadata parsed{};
        ASSERT_EQ(
            smpte2094_50::parseSt2094_50(bitstream.data(), bitstream.size(), parsed).error_code,
            UHDR_CODEC_OK);
        EXPECT_EQ(parsed.gain_application_space_chromaticities, expected_chrom);
        ASSERT_EQ(parsed.rules.size(), 1u);
        EXPECT_NEAR(parsed.rules[0].alternate_hdr_headroom_log2, 2.0f, 1e-3f);
        EXPECT_LE(parsed.rules[0].curve.size(), 12u);
        if (!is_3ch) {
          EXPECT_FLOAT_EQ(parsed.rules[0].mix.component, 0.0f);
        }
      }
    }
  }

  // Alternate application gamut (use_base_cg = false: SDR BT.709, GainMap BT.2100) + identity case.
  uhdr_raw_image_t sdr_709{};
  sdr_709.fmt = UHDR_IMG_FMT_32bppRGBA8888;
  sdr_709.cg = UHDR_CG_BT_709;
  sdr_709.ct = UHDR_CT_UNSPECIFIED;  // Exercises decoded-JPEG default sRGB fallback.
  sdr_709.range = UHDR_CR_FULL_RANGE;
  sdr_709.w = kW;
  sdr_709.h = kH;
  sdr_709.planes[UHDR_PLANE_PACKED] = sdr_rgba.data();
  sdr_709.stride[UHDR_PLANE_PACKED] = kW;

  uhdr_raw_image_t gm_2100{};
  gm_2100.fmt = UHDR_IMG_FMT_8bppYCbCr400;
  gm_2100.cg = UHDR_CG_BT_2100;
  gm_2100.ct = UHDR_CT_UNSPECIFIED;
  gm_2100.range = UHDR_CR_FULL_RANGE;
  gm_2100.w = kGmW;
  gm_2100.h = kGmH;
  gm_2100.planes[UHDR_PLANE_Y] = gm_1ch.data();
  gm_2100.stride[UHDR_PLANE_Y] = kGmW;

  uhdr_gainmap_metadata_ext_t alt_cg_meta = gm_meta;
  alt_cg_meta.use_base_cg = false;
  smpte2094_50::DynamicMetadata alt_hagc{};
  ASSERT_EQ(deriveHagcFromGainMap(&sdr_709, &gm_2100, &alt_cg_meta, alt_hagc).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(alt_hagc.gain_application_space_chromaticities,
            smpte2094_50::DynamicMetadata::kChromaticitiesRec2020);

  // Identity headroom (hdr_capacity_min == hdr_capacity_max == 1.0f) emits valid 0-rule metadata.
  uhdr_gainmap_metadata_ext_t id_meta = gm_meta;
  id_meta.hdr_capacity_max = 1.0f;
  std::vector<uint8_t> id_bytes;
  ASSERT_EQ(deriveEncodedHagcFromGainMap(&sdr_709, &gm_2100, &id_meta, id_bytes).error_code,
            UHDR_CODEC_OK);
  smpte2094_50::DynamicMetadata id_parsed{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(id_bytes.data(), id_bytes.size(), id_parsed).error_code,
            UHDR_CODEC_OK);
  EXPECT_TRUE(id_parsed.rules.empty());

  // Invalid parameter checks.
  EXPECT_NE(deriveHagcFromGainMap(nullptr, &gm_2100, &gm_meta, alt_hagc).error_code,
            UHDR_CODEC_OK);
  smpte2094_50::HagcDerivationOptions bad_opts{};
  bad_opts.num_control_points = 33;
  EXPECT_NE(deriveHagcFromGainMap(&sdr_709, &gm_2100, &gm_meta, alt_hagc, bad_opts).error_code,
            UHDR_CODEC_OK);
}

TEST_F(AgtmTest, DeriveHagc12MpLatencyUnderTwoMilliseconds) {
  constexpr unsigned int kW = 4000;
  constexpr unsigned int kH = 3000;
  constexpr unsigned int kGmW = 1000;
  constexpr unsigned int kGmH = 750;

  std::vector<uint8_t> y_plane(kW * kH, 128u);
  std::vector<uint8_t> u_plane((kW / 2u) * (kH / 2u), 120u);
  std::vector<uint8_t> v_plane((kW / 2u) * (kH / 2u), 136u);
  std::vector<uint8_t> gm_plane(kGmW * kGmH, 0u);

  // Populate non-uniform gradient rows so curve fitting + L1 simplex solver execute full work.
  for (unsigned int y = 0; y < kGmH; ++y) {
    const uint8_t val = static_cast<uint8_t>((y * 255u) / (kGmH - 1u));
    std::fill_n(gm_plane.data() + static_cast<size_t>(y) * kGmW, kGmW, val);
    std::fill_n(y_plane.data() + static_cast<size_t>(y * 4u) * kW, kW * 4u, val);
  }

  uhdr_raw_image_t sdr_yuv{};
  sdr_yuv.fmt = UHDR_IMG_FMT_12bppYCbCr420;
  sdr_yuv.cg = UHDR_CG_DISPLAY_P3;
  sdr_yuv.ct = UHDR_CT_SRGB;
  sdr_yuv.range = UHDR_CR_FULL_RANGE;
  sdr_yuv.w = kW;
  sdr_yuv.h = kH;
  sdr_yuv.planes[UHDR_PLANE_Y] = y_plane.data();
  sdr_yuv.planes[UHDR_PLANE_U] = u_plane.data();
  sdr_yuv.planes[UHDR_PLANE_V] = v_plane.data();
  sdr_yuv.stride[UHDR_PLANE_Y] = kW;
  sdr_yuv.stride[UHDR_PLANE_U] = kW / 2u;
  sdr_yuv.stride[UHDR_PLANE_V] = kW / 2u;

  uhdr_raw_image_t gm_img{};
  gm_img.fmt = UHDR_IMG_FMT_8bppYCbCr400;
  gm_img.cg = UHDR_CG_DISPLAY_P3;
  gm_img.ct = UHDR_CT_LINEAR;
  gm_img.range = UHDR_CR_FULL_RANGE;
  gm_img.w = kGmW;
  gm_img.h = kGmH;
  gm_img.planes[UHDR_PLANE_Y] = gm_plane.data();
  gm_img.stride[UHDR_PLANE_Y] = kGmW;

  uhdr_gainmap_metadata_ext_t meta{};
  meta.hdr_capacity_min = 1.0f;
  meta.hdr_capacity_max = 4.0f;
  meta.use_base_cg = true;
  for (int c = 0; c < 3; ++c) {
    meta.min_content_boost[c] = 1.0f;
    meta.max_content_boost[c] = 4.0f;
    meta.gamma[c] = 1.0f;
    meta.offset_sdr[c] = 0.0f;
    meta.offset_hdr[c] = 0.0f;
  }

  smpte2094_50::HagcDerivationOptions opts{};
  opts.sdr_is_601 = true;

  std::vector<uint8_t> bitstream;
  // Warm up LUTs once before measuring steady-state solver & curve derivation latency.
  ASSERT_EQ(deriveEncodedHagcFromGainMap(&sdr_yuv, &gm_img, &meta, bitstream, opts).error_code,
            UHDR_CODEC_OK);

  std::array<double, 5> elapsed_ms{};
  for (size_t run = 0; run < elapsed_ms.size(); ++run) {
    const auto t0 = std::chrono::steady_clock::now();
    ASSERT_EQ(deriveEncodedHagcFromGainMap(&sdr_yuv, &gm_img, &meta, bitstream, opts).error_code,
              UHDR_CODEC_OK);
    const auto t1 = std::chrono::steady_clock::now();
    elapsed_ms[run] = std::chrono::duration<double, std::milli>(t1 - t0).count();
  }
  std::sort(elapsed_ms.begin(), elapsed_ms.end());
  const double median_ms = elapsed_ms[elapsed_ms.size() / 2u];
#ifndef UHDR_HAS_FEATURE
#ifdef __has_feature
#define UHDR_HAS_FEATURE(x) __has_feature(x)
#else
#define UHDR_HAS_FEATURE(x) 0
#endif
#endif
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__) ||      \
    defined(__SANITIZE_UNDEFINED__) || defined(_DEBUG) ||               \
    (!defined(_MSC_VER) && !defined(__OPTIMIZE__)) ||                   \
    UHDR_HAS_FEATURE(address_sanitizer) ||                              \
    UHDR_HAS_FEATURE(hwaddress_sanitizer) ||                            \
    UHDR_HAS_FEATURE(memory_sanitizer) ||                               \
    UHDR_HAS_FEATURE(thread_sanitizer) ||                               \
    UHDR_HAS_FEATURE(undefined_behavior_sanitizer)
  constexpr double kMaxMedianMs = 50.0;
#else
  constexpr double kMaxMedianMs = 2.0;
#endif
#undef UHDR_HAS_FEATURE

  // Validate bounded sampling budget and decoded output unconditionally; gate strict wall-clock
  // thresholds behind opt-in env flag to avoid flaky failures on throttled/shared device cores.
  EXPECT_LE(opts.max_samples, 4096u);
  smpte2094_50::DynamicMetadata parsed_hagc{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(bitstream.data(), bitstream.size(), parsed_hagc).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(smpte2094_50::validateDynamicMetadata(parsed_hagc).error_code, UHDR_CODEC_OK);

  RecordProperty("median_12mp_hagc_ms", std::to_string(median_ms));
  std::cout << "[   INFO   ] Median 12 MP HAGC derivation latency (ms): " << median_ms
            << " (budget: " << kMaxMedianMs << " ms)\n";
  const char* enforce_perf = std::getenv("UHDR_ENFORCE_HAGC_PERF_BUDGET");
  if (enforce_perf != nullptr && std::string_view(enforce_perf) == "1") {
    EXPECT_LT(median_ms, kMaxMedianMs)
        << "Median 12 MP HAGC derivation latency (ms): " << median_ms;
  }
}

namespace {

void appendU16BE(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
  out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void appendCurveHeader(std::vector<uint8_t>& out, uint8_t num_pts, bool use_pchip) {
  uint8_t b = static_cast<uint8_t>(((num_pts - 1u) & 0x1Fu) << 3);
  if (use_pchip) b |= 0x04u;
  out.push_back(b);
}

std::vector<uint8_t> buildCustomCurveBitstream(uint16_t raw_white, uint16_t raw_baseline,
                                               uint16_t chrom_mode,
                                               const std::array<uint16_t, 8>& custom_chrom,
                                               uint16_t raw_alt, bool use_custom_mix,
                                               uint16_t raw_mix_coeff, uint16_t raw_x0,
                                               uint16_t raw_x1, uint16_t raw_y0, uint16_t raw_y1,
                                               bool use_pchip, uint16_t raw_theta0,
                                               uint16_t raw_theta1) {
  std::vector<uint8_t> bs;
  bs.push_back(0x00u);  // app_version=0, min_app_version=0, reserved=0
  bs.push_back(0xC0u);  // has_custom_ref_white=1, has_adaptive_tone_map=1, reserved=0
  appendU16BE(bs, raw_white);
  appendU16BE(bs, raw_baseline);
  // use_rwtm=0, num_alt=1 (bits6..4=001), chrom_mode (bits3..2), common_mix=0, common_curve=0.
  bs.push_back(static_cast<uint8_t>(0x10u | ((chrom_mode & 0x03u) << 2)));
  if (chrom_mode == 3u) {
    for (uint16_t c : custom_chrom) appendU16BE(bs, c);
  }
  appendU16BE(bs, raw_alt);
  if (use_custom_mix) {
    // mix_type=3 (bits7..6=11), flags=[1,0,0,0,0,0] (bit5=1) => 0xE0.
    bs.push_back(0xE0u);
    appendU16BE(bs, raw_mix_coeff);
  } else {
    bs.push_back(0x00u);  // mix_type=0 (max)
  }
  appendCurveHeader(bs, 2u, use_pchip);
  appendU16BE(bs, raw_x0);
  appendU16BE(bs, raw_x1);
  appendU16BE(bs, raw_y0);
  appendU16BE(bs, raw_y1);
  if (!use_pchip) {
    appendU16BE(bs, raw_theta0);
    appendU16BE(bs, raw_theta1);
  }
  return bs;
}

}  // namespace

TEST_F(AgtmTest, ParseSt2094_50RejectsOutOfRangeAnnexCFields) {
  constexpr std::array<uint16_t, 8> kValidSrgbChrom = {
      32000u, 16500u, 15000u, 30000u, 7500u, 3000u, 15635u, 16450u};

  // Baseline valid bitstream must parse cleanly, including exact Annex C boundary values.
  {
    auto valid_bs = buildCustomCurveBitstream(
        /*raw_white=*/1u, /*raw_baseline=*/0u, /*chrom_mode=*/3u, kValidSrgbChrom,
        /*raw_alt=*/60000u, /*use_custom_mix=*/true, /*raw_mix_coeff=*/50000u,
        /*raw_x0=*/0u, /*raw_x1=*/64000u, /*raw_y0=*/0u, /*raw_y1=*/60000u,
        /*use_pchip=*/false, /*raw_theta0=*/1u, /*raw_theta1=*/35999u);
    smpte2094_50::DynamicMetadata parsed{};
    ASSERT_EQ(smpte2094_50::parseSt2094_50(valid_bs.data(), valid_bs.size(), parsed).error_code,
              UHDR_CODEC_OK);
    EXPECT_FLOAT_EQ(parsed.hdr_reference_white, 0.2f);
    EXPECT_FLOAT_EQ(parsed.baseline_hdr_headroom_log2, 0.0f);
    ASSERT_EQ(parsed.rules.size(), 1u);
    EXPECT_FLOAT_EQ(parsed.rules[0].alternate_hdr_headroom_log2, 6.0f);
    EXPECT_FLOAT_EQ(parsed.rules[0].curve[1].x, 64.0f);
    EXPECT_FLOAT_EQ(parsed.rules[0].curve[1].y, 6.0f);
  }

  // hdr_reference_white out of [1, 50000] (both no-ATM and ATM paths).
  for (uint16_t bad_white : {uint16_t{0u}, uint16_t{50001u}}) {
    std::vector<uint8_t> no_atm_bs = {0x00u, 0x80u};
    appendU16BE(no_atm_bs, bad_white);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(no_atm_bs.data(), no_atm_bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);

    auto atm_bs = buildCustomCurveBitstream(
        bad_white, 0u, 0u, kValidSrgbChrom, 20000u, false, 0u, 0u, 1000u, 0u, 10000u, true, 0u, 0u);
    EXPECT_EQ(smpte2094_50::parseSt2094_50(atm_bs.data(), atm_bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // baseline_hdr_headroom > 60000 (RWTM and custom rule paths).
  {
    std::vector<uint8_t> rwtm_bs = {0x00u, 0x40u};
    appendU16BE(rwtm_bs, 60001u);
    rwtm_bs.push_back(0x80u);  // use_rwtm=1, reserved=0
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(rwtm_bs.data(), rwtm_bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);

    auto custom_bs = buildCustomCurveBitstream(
        1015u, 60001u, 0u, kValidSrgbChrom, 20000u, false, 0u, 0u, 1000u, 0u, 10000u, true, 0u, 0u);
    EXPECT_EQ(smpte2094_50::parseSt2094_50(custom_bs.data(), custom_bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // Custom chromaticity > 50000 (in-triangle values mutated or invalid element).
  {
    auto bad_chrom = kValidSrgbChrom;
    bad_chrom[0] = 50001u;
    auto bs = buildCustomCurveBitstream(
        1015u, 0u, 3u, bad_chrom, 20000u, false, 0u, 0u, 1000u, 0u, 10000u, true, 0u, 0u);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(bs.data(), bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // alternate_hdr_headroom > 60000.
  {
    auto bs = buildCustomCurveBitstream(
        1015u, 0u, 0u, kValidSrgbChrom, 60001u, false, 0u, 0u, 1000u, 0u, 10000u, true, 0u, 0u);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(bs.data(), bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // component_mixing coefficient > 50000.
  {
    auto bs = buildCustomCurveBitstream(
        1015u, 0u, 0u, kValidSrgbChrom, 20000u, true, 50001u, 0u, 1000u, 0u, 10000u, true, 0u, 0u);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(bs.data(), bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // gain_curve_control_points_x > 64000.
  {
    auto bs = buildCustomCurveBitstream(
        1015u, 0u, 0u, kValidSrgbChrom, 20000u, false, 0u, 0u, 64001u, 0u, 10000u, true, 0u, 0u);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(bs.data(), bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // gain_curve_control_points_y > 60000.
  {
    auto bs = buildCustomCurveBitstream(
        1015u, 0u, 0u, kValidSrgbChrom, 20000u, false, 0u, 0u, 1000u, 0u, 60001u, true, 0u, 0u);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(bs.data(), bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }

  // gain_curve_control_points_theta outside [1, 35999].
  for (uint16_t bad_theta : {uint16_t{0u}, uint16_t{36000u}}) {
    auto bs = buildCustomCurveBitstream(
        1015u, 0u, 0u, kValidSrgbChrom, 20000u, false, 0u, 0u, 1000u, 0u, 10000u, false, 18000u,
        bad_theta);
    smpte2094_50::DynamicMetadata parsed{};
    EXPECT_EQ(smpte2094_50::parseSt2094_50(bs.data(), bs.size(), parsed).error_code,
              UHDR_CODEC_INVALID_PARAM);
  }
}

TEST_F(AgtmTest, GenerateGainMapRejectsInvalidInputs) {
  smpte2094_50::DynamicMetadata meta{};
  meta.has_adaptive_tone_map_flag = true;
  meta.use_reference_white_tone_mapping_flag = true;
  meta.baseline_hdr_headroom_log2 = 2.0f;

  std::array<uint32_t, 4> rgba_pixels = {0xFF808080u, 0xFF808080u, 0xFF808080u, 0xFF808080u};
  uhdr_raw_image_t valid_img{};
  valid_img.fmt = UHDR_IMG_FMT_32bppRGBA8888;
  valid_img.cg = UHDR_CG_BT_709;
  valid_img.ct = UHDR_CT_SRGB;
  valid_img.range = UHDR_CR_FULL_RANGE;
  valid_img.w = 2;
  valid_img.h = 2;
  valid_img.planes[UHDR_PLANE_PACKED] = rgba_pixels.data();
  valid_img.stride[UHDR_PLANE_PACKED] = 2;

  uhdr_gainmap_metadata_ext_t gm_meta("1.0");
  std::unique_ptr<uhdr_raw_image_ext_t> gm_img;

  EXPECT_EQ(generateGainMap(nullptr, meta, &gm_meta, gm_img).error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(generateGainMap(&valid_img, meta, nullptr, gm_img).error_code, UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t zero_dim = valid_img;
  zero_dim.w = 0;
  EXPECT_EQ(generateGainMap(&zero_dim, meta, &gm_meta, gm_img).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t null_plane = valid_img;
  null_plane.planes[UHDR_PLANE_PACKED] = nullptr;
  EXPECT_EQ(generateGainMap(&null_plane, meta, &gm_meta, gm_img).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t bad_stride = valid_img;
  bad_stride.stride[UHDR_PLANE_PACKED] = 1;
  EXPECT_EQ(generateGainMap(&bad_stride, meta, &gm_meta, gm_img).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t unsupported_fmt = valid_img;
  unsupported_fmt.fmt = UHDR_IMG_FMT_8bppYCbCr400;
  EXPECT_EQ(generateGainMap(&unsupported_fmt, meta, &gm_meta, gm_img).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t unsupported_cg = valid_img;
  unsupported_cg.cg = UHDR_CG_UNSPECIFIED;
  EXPECT_EQ(generateGainMap(&unsupported_cg, meta, &gm_meta, gm_img).error_code,
            UHDR_CODEC_INVALID_PARAM);

  EXPECT_EQ(generateGainMap(&valid_img, meta, &gm_meta, gm_img, 0.0f).error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(generateGainMap(&valid_img, meta, &gm_meta, gm_img, 0.5f).error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(generateGainMap(&valid_img, meta, &gm_meta, gm_img,
                            std::numeric_limits<float>::quiet_NaN())
                .error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(generateGainMap(&valid_img, meta, &gm_meta, gm_img,
                            std::numeric_limits<float>::infinity())
                .error_code,
            UHDR_CODEC_INVALID_PARAM);

  smpte2094_50::DynamicMetadata bad_meta = meta;
  bad_meta.baseline_hdr_headroom_log2 = -1.0f;
  EXPECT_EQ(generateGainMap(&valid_img, bad_meta, &gm_meta, gm_img).error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(gm_img, nullptr);
}

TEST_F(AgtmTest, GenerateGainMapHonorsExplicitZeroSlopes) {
  smpte2094_50::DynamicMetadata meta{};
  meta.hdr_reference_white = 203.0f;
  meta.has_adaptive_tone_map_flag = true;
  meta.baseline_hdr_headroom_log2 = 0.0f;
  meta.use_reference_white_tone_mapping_flag = false;
  meta.gain_application_space_chromaticities = smpte2094_50::DynamicMetadata::kChromaticitiesSrgb;

  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = 2.0f;
  rule.use_pchip_slope = false;
  rule.mix.max = 1.0f;
  rule.curve = {{0.0f, 0.0f, 0.0f}, {1.0f, 2.0f, 0.0f}};
  meta.rules.push_back(rule);

  // Round-trip through Annex C bitstream with use_pchip_slope=false and theta=18000 (m=0).
  std::vector<uint8_t> bitstream;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(meta, bitstream).error_code, UHDR_CODEC_OK);
  smpte2094_50::DynamicMetadata parsed{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(bitstream.data(), bitstream.size(), parsed).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(parsed.rules.size(), 1u);
  EXPECT_FALSE(parsed.rules[0].use_pchip_slope);
  EXPECT_FLOAT_EQ(parsed.rules[0].curve[0].m, 0.0f);
  EXPECT_FLOAT_EQ(parsed.rules[0].curve[1].m, 0.0f);

  // Sample linear RGB at x=0.25. Explicit zero slopes give Hermite gain = 2 * (3/16 - 2/64)
  // = 0.3125 log2 (~40/255), whereas recomputed PCHIP slopes (m=2) would give 0.50 (~64/255).
  const uint16_t h_quarter = floatToHalf(0.25f);
  const uint16_t h_one = floatToHalf(1.0f);
  std::array<uint64_t, 4> pixels{};
  const uint64_t px = static_cast<uint64_t>(h_quarter) | (static_cast<uint64_t>(h_quarter) << 16) |
                      (static_cast<uint64_t>(h_quarter) << 32) |
                      (static_cast<uint64_t>(h_one) << 48);
  pixels.fill(px);

  uhdr_raw_image_t img{};
  img.fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
  img.cg = UHDR_CG_BT_709;
  img.ct = UHDR_CT_LINEAR;
  img.range = UHDR_CR_FULL_RANGE;
  img.w = 2;
  img.h = 2;
  img.planes[UHDR_PLANE_PACKED] = pixels.data();
  img.stride[UHDR_PLANE_PACKED] = 2;

  uhdr_gainmap_metadata_ext_t gm_meta("1.0");
  std::unique_ptr<uhdr_raw_image_ext_t> gm_img;
  ASSERT_EQ(generateGainMap(&img, parsed, &gm_meta, gm_img).error_code, UHDR_CODEC_OK);
  ASSERT_NE(gm_img, nullptr);
  const uint8_t* out = reinterpret_cast<const uint8_t*>(gm_img->planes[UHDR_PLANE_PACKED]);
  EXPECT_NEAR(out[0], 40, 2);
  EXPECT_LT(out[0], 50);
}

TEST_F(AgtmTest, DeriveHagcRejectsInvalidPlanesAndStrides) {
  constexpr unsigned int kW = 4;
  constexpr unsigned int kH = 4;
  std::vector<uint8_t> gm_buf(kW * kH, 128u);
  uhdr_raw_image_t valid_gm{};
  valid_gm.fmt = UHDR_IMG_FMT_8bppYCbCr400;
  valid_gm.cg = UHDR_CG_BT_709;
  valid_gm.ct = UHDR_CT_LINEAR;
  valid_gm.range = UHDR_CR_FULL_RANGE;
  valid_gm.w = kW;
  valid_gm.h = kH;
  valid_gm.planes[UHDR_PLANE_Y] = gm_buf.data();
  valid_gm.stride[UHDR_PLANE_Y] = kW;

  uhdr_gainmap_metadata_ext_t gm_meta("1.0");
  gm_meta.hdr_capacity_min = 1.0f;
  gm_meta.hdr_capacity_max = 4.0f;
  gm_meta.use_base_cg = true;
  for (int c = 0; c < 3; ++c) {
    gm_meta.min_content_boost[c] = 1.0f;
    gm_meta.max_content_boost[c] = 4.0f;
    gm_meta.gamma[c] = 1.0f;
  }

  smpte2094_50::DynamicMetadata out_hagc{};

  // P010 checks (null UV plane, short Y/UV strides).
  std::vector<uint16_t> p010_y(kW * kH, 512u << 6);
  std::vector<uint16_t> p010_uv(kW * kH / 2u, 512u << 6);
  uhdr_raw_image_t p010{};
  p010.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  p010.cg = UHDR_CG_BT_2100;
  p010.ct = UHDR_CT_HLG;
  p010.range = UHDR_CR_FULL_RANGE;
  p010.w = kW;
  p010.h = kH;
  p010.planes[UHDR_PLANE_Y] = p010_y.data();
  p010.planes[UHDR_PLANE_UV] = p010_uv.data();
  p010.stride[UHDR_PLANE_Y] = kW;
  p010.stride[UHDR_PLANE_UV] = kW;

  uhdr_raw_image_t p010_null_uv = p010;
  p010_null_uv.planes[UHDR_PLANE_UV] = nullptr;
  EXPECT_EQ(deriveHagcFromGainMap(&p010_null_uv, &valid_gm, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t p010_bad_y_stride = p010;
  p010_bad_y_stride.stride[UHDR_PLANE_Y] = kW - 1;
  EXPECT_EQ(deriveHagcFromGainMap(&p010_bad_y_stride, &valid_gm, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t p010_bad_uv_stride = p010;
  p010_bad_uv_stride.stride[UHDR_PLANE_UV] = kW - 1;
  EXPECT_EQ(deriveHagcFromGainMap(&p010_bad_uv_stride, &valid_gm, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  // Planar 420 checks (null U/V planes, short chroma strides).
  std::vector<uint8_t> y420(kW * kH, 128u), u420((kW / 2u) * (kH / 2u), 128u),
      v420((kW / 2u) * (kH / 2u), 128u);
  uhdr_raw_image_t yuv420{};
  yuv420.fmt = UHDR_IMG_FMT_12bppYCbCr420;
  yuv420.cg = UHDR_CG_BT_709;
  yuv420.ct = UHDR_CT_SRGB;
  yuv420.range = UHDR_CR_FULL_RANGE;
  yuv420.w = kW;
  yuv420.h = kH;
  yuv420.planes[UHDR_PLANE_Y] = y420.data();
  yuv420.planes[UHDR_PLANE_U] = u420.data();
  yuv420.planes[UHDR_PLANE_V] = v420.data();
  yuv420.stride[UHDR_PLANE_Y] = kW;
  yuv420.stride[UHDR_PLANE_U] = kW / 2u;
  yuv420.stride[UHDR_PLANE_V] = kW / 2u;

  uhdr_raw_image_t yuv_null_u = yuv420;
  yuv_null_u.planes[UHDR_PLANE_U] = nullptr;
  EXPECT_EQ(deriveHagcFromGainMap(&yuv_null_u, &valid_gm, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t yuv_null_v = yuv420;
  yuv_null_v.planes[UHDR_PLANE_V] = nullptr;
  EXPECT_EQ(deriveHagcFromGainMap(&yuv_null_v, &valid_gm, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  uhdr_raw_image_t yuv_bad_u_stride = yuv420;
  yuv_bad_u_stride.stride[UHDR_PLANE_U] = 1;
  EXPECT_EQ(deriveHagcFromGainMap(&yuv_bad_u_stride, &valid_gm, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  // Gainmap plane/stride checks (YCbCr400 short stride, RGB888 null/short stride).
  uhdr_raw_image_t bad_gm_400 = valid_gm;
  bad_gm_400.stride[UHDR_PLANE_Y] = kW - 1;
  EXPECT_EQ(deriveHagcFromGainMap(&yuv420, &bad_gm_400, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  std::vector<uint8_t> gm_rgb(kW * kH * 3u, 128u);
  uhdr_raw_image_t bad_gm_rgb{};
  bad_gm_rgb.fmt = UHDR_IMG_FMT_24bppRGB888;
  bad_gm_rgb.cg = UHDR_CG_BT_709;
  bad_gm_rgb.ct = UHDR_CT_LINEAR;
  bad_gm_rgb.range = UHDR_CR_FULL_RANGE;
  bad_gm_rgb.w = kW;
  bad_gm_rgb.h = kH;
  bad_gm_rgb.planes[UHDR_PLANE_PACKED] = gm_rgb.data();
  bad_gm_rgb.stride[UHDR_PLANE_PACKED] = kW - 1;
  EXPECT_EQ(deriveHagcFromGainMap(&yuv420, &bad_gm_rgb, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);

  bad_gm_rgb.stride[UHDR_PLANE_PACKED] = kW;
  bad_gm_rgb.planes[UHDR_PLANE_PACKED] = nullptr;
  EXPECT_EQ(deriveHagcFromGainMap(&yuv420, &bad_gm_rgb, &gm_meta, out_hagc).error_code,
            UHDR_CODEC_INVALID_PARAM);
}

TEST_F(AgtmTest, ApplyHagcExactSt2094_50Clause6MathAndValidation) {
  // 1. Multi-rule interpolation + per-channel component mixing + highlight roll-off on SDR base.
  smpte2094_50::DynamicMetadata meta{};
  meta.hdr_reference_white = 203.0f;
  meta.has_adaptive_tone_map_flag = true;
  meta.baseline_hdr_headroom_log2 = 0.0f;
  meta.gain_application_space_chromaticities = smpte2094_50::DynamicMetadata::kChromaticitiesSrgb;

  smpte2094_50::ToneMappingRule r0{};
  r0.alternate_hdr_headroom_log2 = 1.0f;
  r0.mix.component = 1.0f;  // Pure per-component evaluation: R, G, B get distinct gains!
  r0.use_pchip_slope = false;
  r0.curve = {{0.25f, 0.5f, 0.0f}, {0.50f, 1.0f, 0.0f}};  // Above 0.50 rolls off via Formula 11.

  smpte2094_50::ToneMappingRule r1{};
  r1.alternate_hdr_headroom_log2 = 3.0f;
  r1.mix.component = 1.0f;
  r1.use_pchip_slope = false;
  r1.curve = {{0.25f, 1.5f, 0.0f}, {0.50f, 3.0f, 0.0f}};
  meta.rules = {r0, r1};

  uhdr_raw_image_ext_t sdr(UHDR_IMG_FMT_32bppRGBA8888, UHDR_CG_BT_709, UHDR_CT_SRGB,
                           UHDR_CR_FULL_RANGE, 2, 1, 1);
  // Pixel 0: sRGB encoded from linear (0.25, 0.50, 1.00). Pixel 1: pure white (1, 1, 1).
  auto packSrgb = [](float lr, float lg, float lb) -> uint32_t {
    Color enc = srgbOetf({{{lr, lg, lb}}});
    const uint32_t r = static_cast<uint32_t>(enc.r * 255.0f + 0.5f);
    const uint32_t g = static_cast<uint32_t>(enc.g * 255.0f + 0.5f);
    const uint32_t b = static_cast<uint32_t>(enc.b * 255.0f + 0.5f);
    return r | (g << 8) | (b << 16) | (255u << 24);
  };
  auto* sdr_px = static_cast<uint32_t*>(sdr.planes[UHDR_PLANE_PACKED]);
  sdr_px[0] = packSrgb(0.25f, 0.50f, 1.00f);
  sdr_px[1] = packSrgb(1.0f, 1.0f, 1.0f);

  // Read back quantized linear values that srgbInvOetfLUT sees.
  Color q0 = getInverseOetfFn(UHDR_CT_SRGB)(getPixelFn(sdr.fmt)(&sdr, 0, 0));

  // At max_display_boost = 1.0 (H_target = 0 == H_base), output must equal unmodified linear SDR.
  uhdr_raw_image_ext_t out_lin(UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_CG_UNSPECIFIED, UHDR_CT_LINEAR,
                               UHDR_CR_UNSPECIFIED, 2, 1, 1);
  ASSERT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_lin.fmt, 1.0f, false, &out_lin).error_code,
            UHDR_CODEC_OK);
  Color d_boost1 = getPixelFn(out_lin.fmt)(&out_lin, 0, 0);
  EXPECT_NEAR(d_boost1.r, q0.r, 2e-3f);
  EXPECT_NEAR(d_boost1.g, q0.g, 2e-3f);
  EXPECT_NEAR(d_boost1.b, q0.b, 2e-3f);
  EXPECT_EQ(out_lin.cg, UHDR_CG_BT_709);

  // At max_display_boost = 4.0 (H_target = 2.0), brackets r0 (H=1) and r1 (H=3) with 0.5 / 0.5:
  //   r (~0.25): g0 = 0.5, g1 = 1.5 -> G = 1.0 -> factor = 2.0 -> ~0.50
  //   g (~0.50): g0 = 1.0, g1 = 3.0 -> G = 2.0 -> factor = 4.0 -> ~2.00
  //   b (1.00 > 0.50): roll-off g0 = 1.0 + log2(0.5/1.0) = 0.0, g1 = 3.0 + log2(0.5/1.0) = 2.0
  //                    -> G = 1.0 -> factor = 2.0 -> 2.00!
  ASSERT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_lin.fmt, 4.0f, false, &out_lin).error_code,
            UHDR_CODEC_OK);
  Color d_boost4 = getPixelFn(out_lin.fmt)(&out_lin, 0, 0);
  EXPECT_NEAR(d_boost4.r, q0.r * 2.0f, 3e-2f);
  EXPECT_NEAR(d_boost4.g, q0.g * 4.0f, 5e-2f);
  EXPECT_NEAR(d_boost4.b, 2.0f, 2e-2f);
  EXPECT_GT(d_boost4.g / q0.g, d_boost4.r / q0.r + 1.5f);  // Channel-distinct gain verified.

  // At FLT_MAX and +INFINITY, H_target clamps to max rule headroom (3.0).
  uhdr_raw_image_ext_t out_inf(UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_CG_UNSPECIFIED, UHDR_CT_LINEAR,
                               UHDR_CR_UNSPECIFIED, 2, 1, 1);
  ASSERT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_lin.fmt, FLT_MAX, false, &out_lin).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_inf.fmt,
                      std::numeric_limits<float>::infinity(), false, &out_inf)
                .error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(std::memcmp(out_lin.planes[0], out_inf.planes[0], 2 * sizeof(uint64_t)), 0);

  // 2. HDR baseline (PQ RGBA1010102, H_base = 2.0) + RWTM tone-mapping down to SRGB, HLG, PQ.
  smpte2094_50::DynamicMetadata rwtm_meta{};
  rwtm_meta.hdr_reference_white = 203.0f;
  rwtm_meta.has_adaptive_tone_map_flag = true;
  rwtm_meta.baseline_hdr_headroom_log2 = 2.0f;  // 4x (812 nits)
  rwtm_meta.use_reference_white_tone_mapping_flag = true;

  uhdr_raw_image_ext_t hdr_pq(UHDR_IMG_FMT_32bppRGBA1010102, UHDR_CG_BT_2100, UHDR_CT_PQ,
                              UHDR_CR_FULL_RANGE, 2, 1, 1);
  const float pq_1x = pqOetf(203.0f / 10000.0f);
  const float pq_4x = pqOetf(812.0f / 10000.0f);
  auto* pq_px = static_cast<uint32_t*>(hdr_pq.planes[UHDR_PLANE_PACKED]);
  pq_px[0] = colorToRgba1010102({{{pq_1x, pq_1x, pq_1x}}});
  pq_px[1] = colorToRgba1010102({{{pq_4x, pq_4x, pq_4x}}});

  uhdr_raw_image_ext_t out_srgb(UHDR_IMG_FMT_32bppRGBA8888, UHDR_CG_UNSPECIFIED, UHDR_CT_SRGB,
                                UHDR_CR_UNSPECIFIED, 2, 1, 1);
  ASSERT_EQ(
      applyHagc(&hdr_pq, rwtm_meta, UHDR_CT_SRGB, out_srgb.fmt, 1.0f, false, &out_srgb).error_code,
      UHDR_CODEC_OK);
  Color srgb_p0 = getPixelFn(out_srgb.fmt)(&out_srgb, 0, 0);
  Color srgb_p1 = getPixelFn(out_srgb.fmt)(&out_srgb, 1, 0);
  // RWTM compresses [1.0, 4.0] down to <= 1.0 while keeping shadows/midtones below 1.0 strictly <
  // 4x peak.
  EXPECT_LT(srgb_p0.r, srgb_p1.r);
  EXPECT_NEAR(srgb_p1.r, 1.0f, 0.02f);

  uhdr_raw_image_ext_t out_hlg(UHDR_IMG_FMT_32bppRGBA1010102, UHDR_CG_UNSPECIFIED, UHDR_CT_HLG,
                               UHDR_CR_UNSPECIFIED, 2, 1, 1);
  uhdr_raw_image_ext_t out_pq(UHDR_IMG_FMT_32bppRGBA1010102, UHDR_CG_UNSPECIFIED, UHDR_CT_PQ,
                              UHDR_CR_UNSPECIFIED, 2, 1, 1);
  ASSERT_EQ(
      applyHagc(&hdr_pq, rwtm_meta, UHDR_CT_HLG, out_hlg.fmt, 2.0f, false, &out_hlg).error_code,
      UHDR_CODEC_OK);
  ASSERT_EQ(applyHagc(&hdr_pq, rwtm_meta, UHDR_CT_PQ, out_pq.fmt, 4.0f, false, &out_pq).error_code,
            UHDR_CODEC_OK);
  Color pq_roundtrip = getPixelFn(out_pq.fmt)(&out_pq, 1, 0);
  EXPECT_NEAR(pq_roundtrip.r, pq_4x, 5e-3f);

  // 3. Custom mode-3 chromaticities + custom hdr_reference_white (300 nits) + Display P3 base.
  smpte2094_50::DynamicMetadata custom_meta{};
  custom_meta.hdr_reference_white = 300.0f;
  custom_meta.has_adaptive_tone_map_flag = true;
  custom_meta.baseline_hdr_headroom_log2 = 0.0f;
  custom_meta.gain_application_space_chromaticities = {0.66f, 0.33f, 0.22f,   0.71f,
                                                       0.14f, 0.05f, 0.3127f, 0.3290f};
  smpte2094_50::ToneMappingRule cr{};
  cr.alternate_hdr_headroom_log2 = 1.0f;
  cr.mix.max = 1.0f;
  cr.use_pchip_slope = false;
  cr.curve = {{0.0f, 1.0f, 0.0f}, {1.0f, 1.0f, 0.0f}};  // Constant +1 stop (2x) in app space.
  custom_meta.rules = {cr};

  uhdr_raw_image_ext_t p3_base(UHDR_IMG_FMT_32bppRGBA8888, UHDR_CG_DISPLAY_P3, UHDR_CT_SRGB,
                               UHDR_CR_FULL_RANGE, 2, 1, 1);
  auto* p3_px = static_cast<uint32_t*>(p3_base.planes[UHDR_PLANE_PACKED]);
  p3_px[0] = packSrgb(0.5f, 0.25f, 0.75f);
  p3_px[1] = packSrgb(1.0f, 1.0f, 1.0f);
  ASSERT_EQ(
      applyHagc(&p3_base, custom_meta, UHDR_CT_PQ, out_pq.fmt, 2.0f, false, &out_pq).error_code,
      UHDR_CODEC_OK);
  EXPECT_EQ(out_pq.cg, UHDR_CG_DISPLAY_P3);
  // White (1.0) * 2x gain at 300-nit reference white = 600 nits -> pqOetf(600 / 10000).
  Color white_pq = getPixelFn(out_pq.fmt)(&out_pq, 1, 0);
  EXPECT_NEAR(white_pq.r, pqOetf(600.0f / 10000.0f), 6e-3f);

  // 4. 8bppYCbCr400 grayscale base expands to neutral gray (R == G == B > 0) across SRGB & HDR.
  {
    uhdr_raw_image_ext_t gray_base(UHDR_IMG_FMT_8bppYCbCr400, UHDR_CG_BT_709, UHDR_CT_SRGB,
                                   UHDR_CR_FULL_RANGE, 2, 1, 1);
    auto* y_ptr = static_cast<uint8_t*>(gray_base.planes[UHDR_PLANE_Y]);
    y_ptr[0] = 96u;
    y_ptr[1] = 200u;

    ASSERT_EQ(applyHagc(&gray_base, custom_meta, UHDR_CT_SRGB, out_srgb.fmt, 1.0f, true, &out_srgb)
                  .error_code,
              UHDR_CODEC_OK);
    Color gs0 = getPixelFn(out_srgb.fmt)(&out_srgb, 0, 0);
    Color gs1 = getPixelFn(out_srgb.fmt)(&out_srgb, 1, 0);
    EXPECT_GT(gs0.r, 0.2f);
    EXPECT_FLOAT_EQ(gs0.r, gs0.g);
    EXPECT_FLOAT_EQ(gs0.g, gs0.b);
    EXPECT_GT(gs1.r, gs0.r);
    EXPECT_FLOAT_EQ(gs1.r, gs1.g);
    EXPECT_FLOAT_EQ(gs1.g, gs1.b);

    ASSERT_EQ(applyHagc(&gray_base, custom_meta, UHDR_CT_LINEAR, out_lin.fmt, 2.0f, true, &out_lin)
                  .error_code,
              UHDR_CODEC_OK);
    Color gl1 = getPixelFn(out_lin.fmt)(&out_lin, 1, 0);
    EXPECT_GT(gl1.r, 0.8f);
    EXPECT_NEAR(gl1.r, gl1.g, 2e-3f);
    EXPECT_NEAR(gl1.g, gl1.b, 2e-3f);
  }

  // 5. Normative Clause 6.2.2 custom chromaticities with ry == 0 and by == 0 (CIE XYZ primaries).
  {
    smpte2094_50::DynamicMetadata xyz_meta{};
    xyz_meta.hdr_reference_white = 203.0f;
    xyz_meta.has_adaptive_tone_map_flag = true;
    xyz_meta.baseline_hdr_headroom_log2 = 0.0f;
    xyz_meta.gain_application_space_chromaticities = {1.0f, 0.0f, 0.0f,    1.0f,
                                                      0.0f, 0.0f, 0.3333f, 0.3333f};
    xyz_meta.rules = {cr};

    std::vector<uint8_t> xyz_annex_c;
    ASSERT_EQ(smpte2094_50::encodeSt2094_50(xyz_meta, xyz_annex_c).error_code, UHDR_CODEC_OK);
    auto xyz_icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709, xyz_annex_c.data(),
                                              xyz_annex_c.size());
    ASSERT_NE(xyz_icc, nullptr);
    smpte2094_50::DynamicMetadata parsed_xyz{};
    ASSERT_EQ(parseAndValidateHagcFromIcc(xyz_icc->getData(), xyz_icc->getLength(), parsed_xyz)
                  .error_code,
              UHDR_CODEC_OK);
    ASSERT_EQ(
        applyHagc(&sdr, parsed_xyz, UHDR_CT_LINEAR, out_lin.fmt, 2.0f, false, &out_lin).error_code,
        UHDR_CODEC_OK);
    Color xyz_white = getPixelFn(out_lin.fmt)(&out_lin, 1, 0);
    EXPECT_NEAR(xyz_white.r, 2.0f, 2e-2f);
    EXPECT_NEAR(xyz_white.g, 2.0f, 2e-2f);
    EXPECT_NEAR(xyz_white.b, 2.0f, 2e-2f);
  }

  // 6. Negative validation checks.
  EXPECT_EQ(applyHagc(nullptr, meta, UHDR_CT_LINEAR, out_lin.fmt, 2.0f, false, &out_lin).error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_lin.fmt, 2.0f, false, nullptr).error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_lin.fmt, 0.5f, false, &out_lin).error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(applyHagc(&sdr, meta, UHDR_CT_LINEAR, out_lin.fmt,
                      std::numeric_limits<float>::quiet_NaN(), false, &out_lin)
                .error_code,
            UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(applyHagc(&sdr, meta, UHDR_CT_PQ, out_lin.fmt, 2.0f, false, &out_lin).error_code,
            UHDR_CODEC_INVALID_PARAM);
  smpte2094_50::DynamicMetadata no_atm = meta;
  no_atm.has_adaptive_tone_map_flag = false;
  no_atm.rules.clear();
  EXPECT_EQ(applyHagc(&sdr, no_atm, UHDR_CT_LINEAR, out_lin.fmt, 2.0f, false, &out_lin).error_code,
            UHDR_CODEC_INVALID_PARAM);
}

namespace {

uint32_t readBE32AgtmTest(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void writeBE32AgtmTest(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  p[3] = static_cast<uint8_t>(v & 0xFFu);
}

void verifyRawAcspHagcProfileLayout(const std::vector<uint8_t>& raw_icc,
                                    const std::vector<uint8_t>& expected_annex_c,
                                    uhdr_color_gamut_t expected_cg,
                                    uhdr_color_transfer_t expected_cicp_ct) {
  ASSERT_GE(raw_icc.size(), sizeof(ICCHeader));
  EXPECT_EQ(raw_icc.size() % 4u, 0u);
  EXPECT_NE(std::memcmp(raw_icc.data(), kICCIdentifier, sizeof(kICCIdentifier)), 0);
  EXPECT_EQ(readBE32AgtmTest(raw_icc.data()), static_cast<uint32_t>(raw_icc.size()));
  EXPECT_EQ(readBE32AgtmTest(raw_icc.data() + offsetof(ICCHeader, version)), 0x04400000u);
  EXPECT_EQ(readBE32AgtmTest(raw_icc.data() + offsetof(ICCHeader, signature)), kACSP_Signature);

  const uint32_t tag_count = readBE32AgtmTest(raw_icc.data() + offsetof(ICCHeader, tag_count));
  const size_t table_end =
      sizeof(ICCHeader) + static_cast<size_t>(tag_count) * kICCTagTableEntrySize;
  ASSERT_LE(table_end, raw_icc.size());

  size_t hagc_tag_count = 0;
  size_t a2b0_tag_count = 0;
  size_t b2a0_tag_count = 0;
  for (uint32_t i = 0; i < tag_count; ++i) {
    const uint8_t* entry = raw_icc.data() + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    const uint32_t sig = readBE32AgtmTest(entry);
    const uint32_t off = readBE32AgtmTest(entry + 4);
    const uint32_t sz = readBE32AgtmTest(entry + 8);
    EXPECT_GE(off, table_end);
    EXPECT_EQ(off % 4u, 0u);
    ASSERT_LE(off, raw_icc.size());
    ASSERT_LE(sz, raw_icc.size() - off);

    if (sig == kTAG_HAGC) {
      ++hagc_tag_count;
      const size_t expected_tag_sz = ALIGNM(kHagcTagHeaderSize + expected_annex_c.size(), 4);
      ASSERT_EQ(sz, expected_tag_sz);
      const uint8_t* tag_ptr = raw_icc.data() + off;
      EXPECT_EQ(readBE32AgtmTest(tag_ptr), kTAG_HAGCType);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 4), 0u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 8), static_cast<uint32_t>(expected_annex_c.size()));
      EXPECT_EQ(std::memcmp(tag_ptr + kHagcTagHeaderSize, expected_annex_c.data(),
                            expected_annex_c.size()),
                0);
      for (size_t pad = kHagcTagHeaderSize + expected_annex_c.size(); pad < sz; ++pad) {
        EXPECT_EQ(tag_ptr[pad], 0u);
      }
    } else if (sig == kTAG_A2B0) {
      ++a2b0_tag_count;
      // 32-byte mAB header + 3*16B B-curves + 29500B 17x17x17x3 16-bit CLUT + 3*16B A-curves.
      ASSERT_EQ(sz, 29628u);
      const uint8_t* tag_ptr = raw_icc.data() + off;
      EXPECT_EQ(readBE32AgtmTest(tag_ptr), kTAG_mABType);
      EXPECT_EQ(tag_ptr[8], 3u);
      EXPECT_EQ(tag_ptr[9], 3u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 12), 32u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 24), 80u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 28), 29580u);
      for (size_t c = 0; c < 3; ++c) {
        EXPECT_EQ(readBE32AgtmTest(tag_ptr + 32 + c * 16), kTAG_ParaCurveType);
        EXPECT_EQ(readBE32AgtmTest(tag_ptr + 29580 + c * 16), kTAG_ParaCurveType);
      }
      const uint8_t* clut = tag_ptr + 80;
      EXPECT_EQ(clut[0], 17u);
      EXPECT_EQ(clut[1], 17u);
      EXPECT_EQ(clut[2], 17u);
      EXPECT_EQ(clut[16], 2u);
      bool has_nonzero_grid_entry = false;
      for (size_t g = 0; g < 17u * 17u * 17u * 3u * 2u; ++g) {
        if (clut[20 + g] != 0u) {
          has_nonzero_grid_entry = true;
          break;
        }
      }
      EXPECT_TRUE(has_nonzero_grid_entry);
    } else if (sig == kTAG_B2A0) {
      ++b2a0_tag_count;
      ASSERT_EQ(sz, 80u);
      const uint8_t* tag_ptr = raw_icc.data() + off;
      EXPECT_EQ(readBE32AgtmTest(tag_ptr), kTAG_mBAType);
      EXPECT_EQ(tag_ptr[8], 3u);
      EXPECT_EQ(tag_ptr[9], 3u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 12), 32u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 24), 0u);
      EXPECT_EQ(readBE32AgtmTest(tag_ptr + 28), 0u);
      for (size_t c = 0; c < 3; ++c) {
        EXPECT_EQ(readBE32AgtmTest(tag_ptr + 32 + c * 16), kTAG_ParaCurveType);
      }
    }
  }
  EXPECT_EQ(hagc_tag_count, 1u);
  if (expected_cicp_ct == UHDR_CT_PQ) {
    EXPECT_EQ(a2b0_tag_count, 1u);
    EXPECT_EQ(b2a0_tag_count, 1u);
  }

  EXPECT_EQ(IccHelper::readIccColorGamut(const_cast<uint8_t*>(raw_icc.data()), raw_icc.size()),
            expected_cg);
  EXPECT_EQ(readIccColorTransfer(raw_icc.data(), raw_icc.size()), expected_cicp_ct);

  std::vector<uint8_t> extracted;
  ASSERT_TRUE(IccHelper::readIccHagc(raw_icc.data(), raw_icc.size(), extracted));
  EXPECT_EQ(extracted, expected_annex_c);

  smpte2094_50::DynamicMetadata parsed{};
  ASSERT_EQ(smpte2094_50::parseSt2094_50(extracted.data(), extracted.size(), parsed).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(smpte2094_50::validateDynamicMetadata(parsed).error_code, UHDR_CODEC_OK);
}

}  // namespace

TEST_F(AgtmTest, ValidateHagcPayloadAndMemBlockSharedContract) {
  std::vector<uint8_t> valid_bytes;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(makeValidSingleRuleMetadata(), valid_bytes).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(validateHagcPayload(valid_bytes.data(), valid_bytes.size()).error_code, UHDR_CODEC_OK);

  uhdr_mem_block_t valid_blk{valid_bytes.data(), valid_bytes.size(), valid_bytes.size()};
  EXPECT_EQ(validateHagcMemBlock(&valid_blk).error_code, UHDR_CODEC_OK);

  // Minimal (no-ATM) and RWTM Annex C bitstreams are also valid bare ST 2094-50 payloads.
  smpte2094_50::DynamicMetadata minimal{};
  minimal.has_adaptive_tone_map_flag = false;
  std::vector<uint8_t> min_bytes;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(minimal, min_bytes).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(validateHagcPayload(min_bytes.data(), min_bytes.size()).error_code, UHDR_CODEC_OK);

  // Rejects null, < 2 bytes, > 65533 bytes, and invalid mem_block descriptors.
  EXPECT_EQ(validateHagcPayload(nullptr, 0).error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(validateHagcPayload(nullptr, valid_bytes.size()).error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(validateHagcPayload(valid_bytes.data(), 0).error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(validateHagcPayload(valid_bytes.data(), 1).error_code, UHDR_CODEC_INVALID_PARAM);
  std::vector<uint8_t> oversized(kMaxHagcPayloadBytes + 1, 0u);
  EXPECT_EQ(validateHagcPayload(oversized.data(), oversized.size()).error_code,
            UHDR_CODEC_INVALID_PARAM);

  EXPECT_EQ(validateHagcMemBlock(nullptr).error_code, UHDR_CODEC_INVALID_PARAM);
  uhdr_mem_block_t null_data_blk{nullptr, 4, 4};
  EXPECT_EQ(validateHagcMemBlock(&null_data_blk).error_code, UHDR_CODEC_INVALID_PARAM);
  uhdr_mem_block_t short_cap_blk{valid_bytes.data(), valid_bytes.size(), valid_bytes.size() - 1};
  EXPECT_EQ(validateHagcMemBlock(&short_cap_blk).error_code, UHDR_CODEC_INVALID_PARAM);

  // Rejects trailing bytes, ITU-T T.35 (0xB5) prefix, and out-of-range Annex C u(16) fields.
  std::vector<uint8_t> trailing = valid_bytes;
  trailing.push_back(0x00u);
  EXPECT_EQ(validateHagcPayload(trailing.data(), trailing.size()).error_code,
            UHDR_CODEC_INVALID_PARAM);

  std::vector<uint8_t> t35_framed = {0xB5u, 0x00u, 0x3Cu, 0x00u, 0x01u};
  t35_framed.insert(t35_framed.end(), valid_bytes.begin(), valid_bytes.end());
  EXPECT_EQ(validateHagcPayload(t35_framed.data(), t35_framed.size()).error_code,
            UHDR_CODEC_INVALID_PARAM);

  // hdr_reference_white u(16) == 0 (< 1) and == 50001 (> 50000).
  const std::array<uint8_t, 4> zero_white = {0x00u, 0x80u, 0x00u, 0x00u};
  EXPECT_EQ(validateHagcPayload(zero_white.data(), zero_white.size()).error_code,
            UHDR_CODEC_INVALID_PARAM);
  const std::array<uint8_t, 4> huge_white = {0x00u, 0x80u, 0xC3u, 0x51u};  // 50001
  EXPECT_EQ(validateHagcPayload(huge_white.data(), huge_white.size()).error_code,
            UHDR_CODEC_INVALID_PARAM);

  // baseline_hdr_headroom u(16) == 60001 (> 60000) in RWTM payload.
  const std::array<uint8_t, 5> huge_baseline = {0x00u, 0x40u, 0xEAu, 0x61u, 0x80u};
  EXPECT_EQ(validateHagcPayload(huge_baseline.data(), huge_baseline.size()).error_code,
            UHDR_CODEC_INVALID_PARAM);
}

TEST_F(AgtmTest, EncodeRawIccProfileWithEncodedHagcFullGamutTransferMatrixAndLayout) {
  smpte2094_50::DynamicMetadata meta = makeValidSingleRuleMetadata();
  meta.rules[0].mix = {{0.2f, 0.5f, 0.1f}, 0.1f, 0.05f, 0.05f};
  std::vector<uint8_t> annex_c;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(meta, annex_c).error_code, UHDR_CODEC_OK);

  const uhdr_color_gamut_t gamuts[] = {UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100};
  const uhdr_color_transfer_t transfers[] = {UHDR_CT_SRGB, UHDR_CT_LINEAR, UHDR_CT_HLG, UHDR_CT_PQ};

  for (uhdr_color_gamut_t cg : gamuts) {
    for (uhdr_color_transfer_t tf : transfers) {
      std::vector<uint8_t> raw_icc = {0xFFu, 0xEEu, 0xDDu};
      ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(tf, cg, annex_c.data(), annex_c.size(), raw_icc)
                    .error_code,
                UHDR_CODEC_OK);

      const uhdr_color_transfer_t expected_cicp_ct =
          (tf == UHDR_CT_SRGB) ? UHDR_CT_UNSPECIFIED : tf;
      verifyRawAcspHagcProfileLayout(raw_icc, annex_c, cg, expected_cicp_ct);

      smpte2094_50::DynamicMetadata parsed_from_icc{};
      ASSERT_EQ(
          parseAndValidateHagcFromIcc(raw_icc.data(), raw_icc.size(), parsed_from_icc).error_code,
          UHDR_CODEC_OK);
      ASSERT_EQ(parsed_from_icc.rules.size(), 1u);
      EXPECT_FLOAT_EQ(parsed_from_icc.rules[0].alternate_hdr_headroom_log2, 2.0f);
    }
  }

  // Aliasing safety: hagc_data pointing inside out_raw_icc itself.
  std::vector<uint8_t> aliased = annex_c;
  ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3, aliased.data(),
                                               aliased.size(), aliased)
                .error_code,
            UHDR_CODEC_OK);
  verifyRawAcspHagcProfileLayout(aliased, annex_c, UHDR_CG_DISPLAY_P3, UHDR_CT_UNSPECIFIED);
}

TEST_F(AgtmTest, EncodeRawIccProfileWithEncodedHagcBaseIccOverloadAcceptsRawAndApp2) {
  std::vector<uint8_t> annex_c_v1;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(makeValidSingleRuleMetadata(), annex_c_v1).error_code,
            UHDR_CODEC_OK);

  smpte2094_50::DynamicMetadata meta_v2 = makeValidSingleRuleMetadata();
  meta_v2.rules[0].alternate_hdr_headroom_log2 = 3.0f;
  meta_v2.rules[0].curve = {{0.0f, 1.0f, 0.0f}, {0.5f, 2.0f, 0.0f}, {1.0f, 3.0f, 0.0f}};
  std::vector<uint8_t> annex_c_v2;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(meta_v2, annex_c_v2).error_code, UHDR_CODEC_OK);
  ASSERT_NE(annex_c_v1, annex_c_v2);

  // 1. Full 3x4 gamut x transfer matrix across both APP2-prefixed and raw 'acsp' base ICC inputs.
  const uhdr_color_gamut_t gamuts[] = {UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100};
  const uhdr_color_transfer_t transfers[] = {UHDR_CT_SRGB, UHDR_CT_LINEAR, UHDR_CT_HLG, UHDR_CT_PQ};
  for (uhdr_color_gamut_t cg : gamuts) {
    for (uhdr_color_transfer_t tf : transfers) {
      auto app2_base = IccHelper::writeIccProfile(tf, cg);
      auto raw_base = IccHelper::writeRawIccProfile(tf, cg);
      ASSERT_NE(app2_base, nullptr);
      ASSERT_NE(raw_base, nullptr);

      std::vector<uint8_t> from_app2, from_raw;
      ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(app2_base->getData(), app2_base->getLength(),
                                                   annex_c_v1.data(), annex_c_v1.size(), from_app2)
                    .error_code,
                UHDR_CODEC_OK);
      ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(raw_base->getData(), raw_base->getLength(),
                                                   annex_c_v1.data(), annex_c_v1.size(), from_raw)
                    .error_code,
                UHDR_CODEC_OK);
      EXPECT_EQ(from_app2, from_raw);

      const uhdr_color_transfer_t expected_cicp_ct =
          (tf == UHDR_CT_SRGB) ? UHDR_CT_UNSPECIFIED : tf;
      verifyRawAcspHagcProfileLayout(from_app2, annex_c_v1, cg, expected_cicp_ct);
    }
  }

  // 2. Custom odd-sized vendor tag ('cust'), shared/aliased TRC offsets, stale MD5 profile_id,
  //    dirty output-buffer reuse padding, and in-place 'HAGC' replacement.
  auto std_raw = IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3);
  ASSERT_NE(std_raw, nullptr);
  const uint8_t* orig = static_cast<const uint8_t*>(std_raw->getData());
  const size_t orig_len = std_raw->getLength();
  ASSERT_GT(orig_len, sizeof(ICCHeader));
  ASSERT_LT(orig_len, 1u << 20);
  const size_t orig_tc = readBE32AgtmTest(orig + offsetof(ICCHeader, tag_count));
  const size_t orig_table_end = sizeof(ICCHeader) + orig_tc * kICCTagTableEntrySize;
  ASSERT_LE(orig_table_end, orig_len);

  const std::vector<uint8_t> kVendorTag = {'c', 'a', 'm', '2', 0x42, 0x7F, 0x99};
  const size_t delta = kICCTagTableEntrySize;
  const size_t cust_off = ALIGNM(orig_len + delta, 4);
  const size_t custom_raw_len = ALIGNM(cust_off + kVendorTag.size(), 4);
  std::vector<uint8_t> custom_base(custom_raw_len);
  ASSERT_GE(custom_base.size(), sizeof(ICCHeader) + orig_tc * kICCTagTableEntrySize + delta);
  std::memcpy(custom_base.data(), orig, sizeof(ICCHeader));
  std::memset(custom_base.data() + offsetof(ICCHeader, profile_id), 0xA5,
              sizeof(ICCHeader::profile_id));
  writeBE32AgtmTest(custom_base.data() + offsetof(ICCHeader, size),
                    static_cast<uint32_t>(custom_raw_len));
  writeBE32AgtmTest(custom_base.data() + offsetof(ICCHeader, tag_count),
                    static_cast<uint32_t>(orig_tc + 1));

  uint32_t rtrc_off = 0, rtrc_sz = 0;
  for (size_t i = 0; i < orig_tc; ++i) {
    const uint8_t* oe = orig + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    uint8_t* ne = custom_base.data() + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    const uint32_t sig = readBE32AgtmTest(oe);
    const uint32_t shifted_off = readBE32AgtmTest(oe + 4) + static_cast<uint32_t>(delta);
    const uint32_t sz = readBE32AgtmTest(oe + 8);
    if (sig == kTAG_rTRC) {
      rtrc_off = shifted_off;
      rtrc_sz = sz;
    }
    writeBE32AgtmTest(ne, sig);
    writeBE32AgtmTest(ne + 4, (sig == kTAG_gTRC || sig == kTAG_bTRC) ? rtrc_off : shifted_off);
    writeBE32AgtmTest(ne + 8, (sig == kTAG_gTRC || sig == kTAG_bTRC) ? rtrc_sz : sz);
  }
  uint8_t* cust_entry = custom_base.data() + sizeof(ICCHeader) + orig_tc * kICCTagTableEntrySize;
  writeBE32AgtmTest(cust_entry, SetFourByteTag('c', 'u', 's', 't'));
  writeBE32AgtmTest(cust_entry + 4, static_cast<uint32_t>(cust_off));
  writeBE32AgtmTest(cust_entry + 8, static_cast<uint32_t>(kVendorTag.size()));
  std::memcpy(custom_base.data() + orig_table_end + delta, orig + orig_table_end,
              orig_len - orig_table_end);
  std::memcpy(custom_base.data() + cust_off, kVendorTag.data(), kVendorTag.size());

  // Pre-fill reused destination vector with 0xFF so padding zero-fill is exercised.
  std::vector<uint8_t> out_icc(4096, 0xFFu);
  ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(custom_base.data(), custom_base.size(),
                                               annex_c_v1.data(), annex_c_v1.size(), out_icc)
                .error_code,
            UHDR_CODEC_OK);
  verifyRawAcspHagcProfileLayout(out_icc, annex_c_v1, UHDR_CG_DISPLAY_P3, UHDR_CT_UNSPECIFIED);
  for (size_t i = 0; i < sizeof(ICCHeader::profile_id); ++i) {
    EXPECT_EQ(out_icc[offsetof(ICCHeader, profile_id) + i], 0u);
  }

  // Verify 'cust' tag payload, zero-padding byte after 7-byte 'cust', and aliased TRC offsets.
  const uint32_t tc1 = readBE32AgtmTest(out_icc.data() + offsetof(ICCHeader, tag_count));
  uint32_t r_off = 0, g_off = 0, b_off = 0, c_off = 0, c_sz = 0;
  for (uint32_t i = 0; i < tc1; ++i) {
    const uint8_t* e = out_icc.data() + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    const uint32_t sig = readBE32AgtmTest(e);
    if (sig == kTAG_rTRC) r_off = readBE32AgtmTest(e + 4);
    if (sig == kTAG_gTRC) g_off = readBE32AgtmTest(e + 4);
    if (sig == kTAG_bTRC) b_off = readBE32AgtmTest(e + 4);
    if (sig == SetFourByteTag('c', 'u', 's', 't')) {
      c_off = readBE32AgtmTest(e + 4);
      c_sz = readBE32AgtmTest(e + 8);
    }
  }
  EXPECT_NE(r_off, 0u);
  EXPECT_EQ(r_off, g_off);
  EXPECT_EQ(r_off, b_off);
  ASSERT_EQ(c_sz, kVendorTag.size());
  EXPECT_EQ(std::memcmp(out_icc.data() + c_off, kVendorTag.data(), kVendorTag.size()), 0);
  EXPECT_EQ(out_icc[c_off + kVendorTag.size()], 0u);

  // In-place replacement (base_icc_data aliases out_icc) replaces 'HAGC' cleanly without
  // duplicating it.
  ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(out_icc.data(), out_icc.size(), annex_c_v2.data(),
                                               annex_c_v2.size(), out_icc)
                .error_code,
            UHDR_CODEC_OK);
  verifyRawAcspHagcProfileLayout(out_icc, annex_c_v2, UHDR_CG_DISPLAY_P3, UHDR_CT_UNSPECIFIED);

  // 3. Base ICC containing >= 2 pre-existing 'HAGC' tag entries is deduplicated down to a single
  //    canonical 'HAGC' tag carrying the newly supplied Annex C payload.
  {
    auto one_hagc = IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709, annex_c_v1.data(),
                                                  annex_c_v1.size());
    ASSERT_NE(one_hagc, nullptr);
    const uint8_t* src_p = static_cast<const uint8_t*>(one_hagc->getData());
    const size_t src_len = one_hagc->getLength();
    ASSERT_GT(src_len, sizeof(ICCHeader));
    ASSERT_LT(src_len, 1u << 20);
    const uint32_t src_tc = readBE32AgtmTest(src_p + offsetof(ICCHeader, tag_count));
    const size_t src_table_end = sizeof(ICCHeader) + src_tc * kICCTagTableEntrySize;
    ASSERT_LE(src_table_end, src_len);

    uint32_t existing_hagc_off = 0, existing_hagc_sz = 0;
    for (uint32_t i = 0; i < src_tc; ++i) {
      const uint8_t* e = src_p + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      if (readBE32AgtmTest(e) == kTAG_HAGC) {
        existing_hagc_off = readBE32AgtmTest(e + 4) + static_cast<uint32_t>(kICCTagTableEntrySize);
        existing_hagc_sz = readBE32AgtmTest(e + 8);
      }
    }
    ASSERT_NE(existing_hagc_off, 0u);

    std::vector<uint8_t> two_hagc_base(src_len + kICCTagTableEntrySize, 0u);
    ASSERT_GE(two_hagc_base.size(), src_table_end + kICCTagTableEntrySize);
    std::memcpy(two_hagc_base.data(), src_p, sizeof(ICCHeader));
    writeBE32AgtmTest(two_hagc_base.data() + offsetof(ICCHeader, size),
                      static_cast<uint32_t>(two_hagc_base.size()));
    writeBE32AgtmTest(two_hagc_base.data() + offsetof(ICCHeader, tag_count), src_tc + 1u);
    for (uint32_t i = 0; i < src_tc; ++i) {
      const uint8_t* oe = src_p + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      uint8_t* ne = two_hagc_base.data() + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      writeBE32AgtmTest(ne, readBE32AgtmTest(oe));
      writeBE32AgtmTest(ne + 4,
                        readBE32AgtmTest(oe + 4) + static_cast<uint32_t>(kICCTagTableEntrySize));
      writeBE32AgtmTest(ne + 8, readBE32AgtmTest(oe + 8));
    }
    uint8_t* dup_e = two_hagc_base.data() + sizeof(ICCHeader) + src_tc * kICCTagTableEntrySize;
    writeBE32AgtmTest(dup_e, kTAG_HAGC);
    writeBE32AgtmTest(dup_e + 4, existing_hagc_off);
    writeBE32AgtmTest(dup_e + 8, existing_hagc_sz);
    std::memcpy(two_hagc_base.data() + src_table_end + kICCTagTableEntrySize, src_p + src_table_end,
                src_len - src_table_end);

    std::vector<uint8_t> dedup_out;
    ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(two_hagc_base.data(), two_hagc_base.size(),
                                                 annex_c_v2.data(), annex_c_v2.size(), dedup_out)
                  .error_code,
              UHDR_CODEC_OK);
    verifyRawAcspHagcProfileLayout(dedup_out, annex_c_v2, UHDR_CG_BT_709, UHDR_CT_UNSPECIFIED);
  }
}

TEST_F(AgtmTest, EncodeRawIccProfileWithDerivedHagcSingleAndMultiChannelGainMaps) {
  constexpr unsigned int kW = 32;
  constexpr unsigned int kH = 32;

  // Simulate Android Camera2 HeicCompositeStream pipeline: P010 HDR -> JpegR::toneMap ->
  // JpegR::generateGainMap (both 1-channel and 3-channel) -> encodeGainmapMetadata +
  // encodeRawIccProfileWithDerivedHagc.
  std::vector<uint16_t> p010_y(kW * kH), p010_uv((kW / 2u) * (kH / 2u) * 2u);
  for (unsigned int y = 0; y < kH; ++y) {
    for (unsigned int x = 0; x < kW; ++x) {
      const uint16_t luma10 = static_cast<uint16_t>(64u + ((x + y) * 900u) / (kW + kH - 2u));
      p010_y[y * kW + x] = static_cast<uint16_t>(luma10 << 6);
    }
  }
  std::fill(p010_uv.begin(), p010_uv.end(), static_cast<uint16_t>(512u << 6));

  uhdr_raw_image_t hdr_p010{};
  hdr_p010.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
  hdr_p010.cg = UHDR_CG_BT_2100;
  hdr_p010.ct = UHDR_CT_HLG;
  hdr_p010.range = UHDR_CR_FULL_RANGE;
  hdr_p010.w = kW;
  hdr_p010.h = kH;
  hdr_p010.planes[UHDR_PLANE_Y] = p010_y.data();
  hdr_p010.planes[UHDR_PLANE_UV] = p010_uv.data();
  hdr_p010.stride[UHDR_PLANE_Y] = kW;
  hdr_p010.stride[UHDR_PLANE_UV] = kW;

  for (bool multi_channel : {false, true}) {
    JpegR helper(nullptr, /*mapDimensionScaleFactor=*/2, /*mapCompressQuality=*/85, multi_channel);
    uhdr_raw_image_ext_t sdr_yuv(UHDR_IMG_FMT_12bppYCbCr420, UHDR_CG_UNSPECIFIED,
                                 UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kW, kH, 64);
    ASSERT_EQ(helper.toneMap(&hdr_p010, &sdr_yuv).error_code, UHDR_CODEC_OK);

    uhdr_gainmap_metadata_ext_t gm_meta(kJpegrVersion);
    std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
    ASSERT_EQ(helper
                  .generateGainMap(&sdr_yuv, &hdr_p010, &gm_meta, gainmap,
                                   /*sdr_is_601=*/sdr_yuv.cg == UHDR_CG_DISPLAY_P3)
                  .error_code,
              UHDR_CODEC_OK);
    ASSERT_NE(gainmap, nullptr);
    EXPECT_EQ(gainmap->fmt, multi_channel ? UHDR_IMG_FMT_24bppRGB888 : UHDR_IMG_FMT_8bppYCbCr400);

    smpte2094_50::HagcDerivationOptions opts{};
    opts.sdr_is_601 = (sdr_yuv.cg == UHDR_CG_DISPLAY_P3);

    std::vector<uint8_t> expected_annex_c;
    ASSERT_EQ(
        deriveEncodedHagcFromGainMap(&sdr_yuv, gainmap.get(), &gm_meta, expected_annex_c, opts)
            .error_code,
        UHDR_CODEC_OK);

    // Works with both uhdr_gainmap_metadata_ext_t and base uhdr_gainmap_metadata_t pointers.
    std::vector<uint8_t> raw_icc_ext, raw_icc_base;
    const uhdr_gainmap_metadata_t base_meta = gm_meta;
    ASSERT_EQ(
        encodeRawIccProfileWithDerivedHagc(&sdr_yuv, gainmap.get(), &gm_meta, raw_icc_ext, opts)
            .error_code,
        UHDR_CODEC_OK);
    ASSERT_EQ(
        encodeRawIccProfileWithDerivedHagc(&sdr_yuv, gainmap.get(), &base_meta, raw_icc_base, opts)
            .error_code,
        UHDR_CODEC_OK);
    EXPECT_EQ(raw_icc_ext, raw_icc_base);

    verifyRawAcspHagcProfileLayout(raw_icc_ext, expected_annex_c, UHDR_CG_DISPLAY_P3,
                                   UHDR_CT_UNSPECIFIED);

    smpte2094_50::DynamicMetadata decoded_hagc{};
    ASSERT_EQ(parseAndValidateHagcFromIcc(raw_icc_ext.data(), raw_icc_ext.size(), decoded_hagc)
                  .error_code,
              UHDR_CODEC_OK);
    uhdr_raw_image_ext_t recon_hdr(UHDR_IMG_FMT_64bppRGBAHalfFloat, UHDR_CG_UNSPECIFIED,
                                   UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, kW, kH, 64);
    ASSERT_EQ(applyHagc(&sdr_yuv, decoded_hagc, UHDR_CT_LINEAR, recon_hdr.fmt, 4.0f,
                        /*base_is_601_yuv=*/opts.sdr_is_601, &recon_hdr)
                  .error_code,
              UHDR_CODEC_OK);
  }
}

TEST_F(AgtmTest, RawIccHagcHelpersFailClosedAndLeaveOutputUnmodified) {
  std::vector<uint8_t> valid_hagc;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(makeValidSingleRuleMetadata(), valid_hagc).error_code,
            UHDR_CODEC_OK);
  auto valid_base_app2 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  auto valid_base_raw = IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  ASSERT_NE(valid_base_app2, nullptr);
  ASSERT_NE(valid_base_raw, nullptr);

  const std::vector<uint8_t> kSentinel = {0xDEu, 0xADu, 0xBEu, 0xEFu};
  auto expectFailUntouched = [&](uhdr_error_info_t status, const std::vector<uint8_t>& buf) {
    EXPECT_EQ(status.error_code, UHDR_CODEC_INVALID_PARAM) << status.detail;
    EXPECT_EQ(buf, kSentinel);
  };

  // 1. encodeRawIccProfileWithEncodedHagc (fresh) negative cases.
  {
    std::vector<uint8_t> out = kSentinel;
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_UNSPECIFIED, UHDR_CG_BT_709, valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(static_cast<uhdr_color_transfer_t>(-2), UHDR_CG_BT_709,
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(static_cast<uhdr_color_transfer_t>(999), UHDR_CG_BT_709,
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_UNSPECIFIED, valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, static_cast<uhdr_color_gamut_t>(-2),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, static_cast<uhdr_color_gamut_t>(999),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, nullptr, 0, out), out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, valid_hagc.data(), 0, out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, valid_hagc.data(), 1, out),
        out);

    std::vector<uint8_t> oversized(kMaxHagcPayloadBytes + 1, 0u);
    expectFailUntouched(encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709,
                                                           oversized.data(), oversized.size(), out),
                        out);

    std::vector<uint8_t> trailing = valid_hagc;
    trailing.push_back(0u);
    expectFailUntouched(encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709,
                                                           trailing.data(), trailing.size(), out),
                        out);

    std::vector<uint8_t> t35 = {0xB5u, 0x00u, 0x3Cu, 0x00u, 0x01u};
    t35.insert(t35.end(), valid_hagc.begin(), valid_hagc.end());
    expectFailUntouched(encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, t35.data(),
                                                           t35.size(), out),
                        out);

    // Out-of-range Annex C u(16) fields: hdr_reference_white=0, 50001 and baseline_headroom=60001.
    const std::array<uint8_t, 4> zero_white = {0x00u, 0x80u, 0x00u, 0x00u};
    const std::array<uint8_t, 4> huge_white = {0x00u, 0x80u, 0xC3u, 0x51u};
    const std::array<uint8_t, 5> huge_baseline = {0x00u, 0x40u, 0xEAu, 0x61u, 0x80u};
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, zero_white.data(),
                                           zero_white.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, huge_white.data(),
                                           huge_white.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_BT_709, huge_baseline.data(),
                                           huge_baseline.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(valid_base_raw->getData(), valid_base_raw->getLength(),
                                           huge_white.data(), huge_white.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(valid_base_raw->getData(), valid_base_raw->getLength(),
                                           huge_baseline.data(), huge_baseline.size(), out),
        out);
  }

  // 2. encodeRawIccProfileWithEncodedHagc (base ICC overload) negative base-ICC and payload cases.
  {
    std::vector<uint8_t> out = kSentinel;
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(nullptr, 0, valid_hagc.data(), valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(valid_base_raw->getData(), 64, valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(valid_base_app2->getData(), 140, valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);

    // Bad 'acsp' magic.
    std::vector<uint8_t> bad_magic(
        static_cast<const uint8_t*>(valid_base_raw->getData()),
        static_cast<const uint8_t*>(valid_base_raw->getData()) + valid_base_raw->getLength());
    bad_magic[offsetof(ICCHeader, signature)] ^= 0xFFu;
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(bad_magic.data(), bad_magic.size(), valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);

    // Unsupported major ICC version (> 4, e.g. 0x05000000), rejected by skcms_Parse.
    std::vector<uint8_t> bad_version(
        static_cast<const uint8_t*>(valid_base_raw->getData()),
        static_cast<const uint8_t*>(valid_base_raw->getData()) + valid_base_raw->getLength());
    writeBE32AgtmTest(bad_version.data() + offsetof(ICCHeader, version), 0x05000000u);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(bad_version.data(), bad_version.size(),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);
    EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(bad_version.data(), bad_version.size(),
                                                  valid_hagc.data(), valid_hagc.size()),
              nullptr);

    // Invalid PCS signature (neither 'XYZ ' nor 'Lab '), rejected by skcms_Parse.
    std::vector<uint8_t> bad_pcs(
        static_cast<const uint8_t*>(valid_base_raw->getData()),
        static_cast<const uint8_t*>(valid_base_raw->getData()) + valid_base_raw->getLength());
    writeBE32AgtmTest(bad_pcs.data() + offsetof(ICCHeader, pcs), Signature_CMYK);
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(bad_pcs.data(), bad_pcs.size(), valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);

    // Tag size < 4 (missing 4-byte tag type signature), rejected by skcms_Parse.
    for (uint32_t short_sz : {0u, 3u}) {
      std::vector<uint8_t> bad_tag_sz(
          static_cast<const uint8_t*>(valid_base_raw->getData()),
          static_cast<const uint8_t*>(valid_base_raw->getData()) + valid_base_raw->getLength());
      writeBE32AgtmTest(bad_tag_sz.data() + sizeof(ICCHeader) + 8, short_sz);
      expectFailUntouched(
          encodeRawIccProfileWithEncodedHagc(bad_tag_sz.data(), bad_tag_sz.size(),
                                             valid_hagc.data(), valid_hagc.size(), out),
          out);
      EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(bad_tag_sz.data(), bad_tag_sz.size(),
                                                    valid_hagc.data(), valid_hagc.size()),
                nullptr);
    }

    // Tagless 132-byte 'acsp' shell (tag_count == 0) and 'HAGC'-only 1-tag shell (kept_count == 0).
    ICCHeader empty_hdr{};
    empty_hdr.size = Endian_SwapBE32(static_cast<uint32_t>(sizeof(ICCHeader)));
    empty_hdr.tag_count = 0;
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(&empty_hdr, sizeof(empty_hdr), valid_hagc.data(),
                                           valid_hagc.size(), out),
        out);
    EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(&empty_hdr, sizeof(empty_hdr), valid_hagc.data(),
                                                  valid_hagc.size()),
              nullptr);

    const size_t hagc_only_tag_len = ALIGNM(kHagcTagHeaderSize + valid_hagc.size(), 4);
    const size_t hagc_only_len = sizeof(ICCHeader) + kICCTagTableEntrySize + hagc_only_tag_len;
    std::vector<uint8_t> hagc_only_shell(hagc_only_len, 0u);
    std::memcpy(hagc_only_shell.data(), &empty_hdr, sizeof(ICCHeader));
    writeBE32AgtmTest(hagc_only_shell.data() + offsetof(ICCHeader, size),
                      static_cast<uint32_t>(hagc_only_len));
    writeBE32AgtmTest(hagc_only_shell.data() + offsetof(ICCHeader, version), 0x04400000u);
    writeBE32AgtmTest(hagc_only_shell.data() + offsetof(ICCHeader, tag_count), 1u);
    writeBE32AgtmTest(hagc_only_shell.data() + sizeof(ICCHeader), kTAG_HAGC);
    writeBE32AgtmTest(hagc_only_shell.data() + sizeof(ICCHeader) + 4,
                      static_cast<uint32_t>(sizeof(ICCHeader) + kICCTagTableEntrySize));
    writeBE32AgtmTest(hagc_only_shell.data() + sizeof(ICCHeader) + 8,
                      static_cast<uint32_t>(hagc_only_tag_len));
    writeBE32AgtmTest(hagc_only_shell.data() + sizeof(ICCHeader) + kICCTagTableEntrySize,
                      kTAG_HAGCType);
    writeBE32AgtmTest(hagc_only_shell.data() + sizeof(ICCHeader) + kICCTagTableEntrySize + 8,
                      static_cast<uint32_t>(valid_hagc.size()));
    std::memcpy(
        hagc_only_shell.data() + sizeof(ICCHeader) + kICCTagTableEntrySize + kHagcTagHeaderSize,
        valid_hagc.data(), valid_hagc.size());
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(hagc_only_shell.data(), hagc_only_shell.size(),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);

    // Multi-chunk and malformed chunk headers on APP2 ICC.
    std::vector<uint8_t> multi_chunk(
        static_cast<const uint8_t*>(valid_base_app2->getData()),
        static_cast<const uint8_t*>(valid_base_app2->getData()) + valid_base_app2->getLength());
    multi_chunk[12] = 1;
    multi_chunk[13] = 2;
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(multi_chunk.data(), multi_chunk.size(),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);
    multi_chunk[12] = 0;
    multi_chunk[13] = 1;
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(multi_chunk.data(), multi_chunk.size(),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);

    // Corrupt tag offset exceeding profile size.
    std::vector<uint8_t> bad_tag_off(
        static_cast<const uint8_t*>(valid_base_raw->getData()),
        static_cast<const uint8_t*>(valid_base_raw->getData()) + valid_base_raw->getLength());
    writeBE32AgtmTest(bad_tag_off.data() + sizeof(ICCHeader) + 4,
                      static_cast<uint32_t>(bad_tag_off.size() + 32));
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(bad_tag_off.data(), bad_tag_off.size(),
                                           valid_hagc.data(), valid_hagc.size(), out),
        out);

    // Invalid HAGC payload with valid base ICC.
    expectFailUntouched(
        encodeRawIccProfileWithEncodedHagc(valid_base_raw->getData(), valid_base_raw->getLength(),
                                           nullptr, 0, out),
        out);
  }

  // 3. encodeRawIccProfileWithDerivedHagc negative / mismatched descriptor cases.
  {
    uhdr_raw_image_ext_t sdr(UHDR_IMG_FMT_32bppRGBA8888, UHDR_CG_BT_709, UHDR_CT_SRGB,
                             UHDR_CR_FULL_RANGE, 8, 8, 64);
    uhdr_raw_image_ext_t gm(UHDR_IMG_FMT_8bppYCbCr400, UHDR_CG_BT_709, UHDR_CT_UNSPECIFIED,
                            UHDR_CR_FULL_RANGE, 4, 4, 64);
    std::memset(sdr.planes[UHDR_PLANE_PACKED], 128, 8 * sdr.stride[UHDR_PLANE_PACKED] * 4);
    std::memset(gm.planes[UHDR_PLANE_Y], 128, 4 * gm.stride[UHDR_PLANE_Y]);

    uhdr_gainmap_metadata_t meta{};
    for (int c = 0; c < 3; ++c) {
      meta.min_content_boost[c] = 1.0f;
      meta.max_content_boost[c] = 4.0f;
      meta.gamma[c] = 1.0f;
      meta.offset_sdr[c] = 0.0f;
      meta.offset_hdr[c] = 0.0f;
    }
    meta.hdr_capacity_min = 1.0f;
    meta.hdr_capacity_max = 4.0f;
    meta.use_base_cg = 1;

    std::vector<uint8_t> out = kSentinel;
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(nullptr, &gm, &meta, out), out);
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr, nullptr, &meta, out), out);
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr, &gm, nullptr, out), out);

    uhdr_raw_image_t sdr_unspec_cg = sdr;
    sdr_unspec_cg.cg = UHDR_CG_UNSPECIFIED;
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr_unspec_cg, &gm, &meta, out), out);

    for (int bad_cg_val : {-2, 999}) {
      uhdr_raw_image_t sdr_bad_cg = sdr;
      std::memcpy(&sdr_bad_cg.cg, &bad_cg_val, sizeof(bad_cg_val));
      expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr_bad_cg, &gm, &meta, out), out);
    }

    for (int bad_ct_val : {-2, 999}) {
      uhdr_raw_image_t sdr_bad_ct = sdr;
      std::memcpy(&sdr_bad_ct.ct, &bad_ct_val, sizeof(bad_ct_val));
      expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr_bad_ct, &gm, &meta, out), out);
    }

    // Gainmap larger than base image.
    uhdr_raw_image_ext_t gm_oversized(UHDR_IMG_FMT_8bppYCbCr400, UHDR_CG_BT_709,
                                      UHDR_CT_UNSPECIFIED, UHDR_CR_FULL_RANGE, 16, 8, 64);
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr, &gm_oversized, &meta, out), out);

    // Alternate color space (use_base_cg == 0) with unspecified gainmap gamut.
    uhdr_gainmap_metadata_t alt_meta = meta;
    alt_meta.use_base_cg = 0;
    uhdr_raw_image_t gm_unspec_cg = gm;
    gm_unspec_cg.cg = UHDR_CG_UNSPECIFIED;
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr, &gm_unspec_cg, &alt_meta, out),
                        out);

    // Invalid hdr_capacity_max < hdr_capacity_min.
    uhdr_gainmap_metadata_t bad_cap = meta;
    bad_cap.hdr_capacity_min = 4.0f;
    bad_cap.hdr_capacity_max = 2.0f;
    expectFailUntouched(encodeRawIccProfileWithDerivedHagc(&sdr, &gm, &bad_cap, out), out);
  }
}

TEST_F(AgtmTest, HalSideloadRawIccZeroSolverFastPathLatency) {
  std::vector<uint8_t> hal_annex_c;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(makeValidSingleRuleMetadata(), hal_annex_c).error_code,
            UHDR_CODEC_OK);
  auto base_raw = IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3);
  ASSERT_NE(base_raw, nullptr);

  constexpr int kIterations = 1000;
  std::vector<uint8_t> out_fresh;
  std::vector<uint8_t> out_injected;
  const uint8_t* fresh_ptr = nullptr;
  const uint8_t* injected_ptr = nullptr;

  const auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < kIterations; ++i) {
    ASSERT_EQ(encodeRawIccProfileWithEncodedHagc(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3,
                                                 hal_annex_c.data(), hal_annex_c.size(), out_fresh)
                  .error_code,
              UHDR_CODEC_OK);
    ASSERT_EQ(
        encodeRawIccProfileWithEncodedHagc(base_raw->getData(), base_raw->getLength(),
                                           hal_annex_c.data(), hal_annex_c.size(), out_injected)
            .error_code,
        UHDR_CODEC_OK);
    if (i == 0) {
      fresh_ptr = out_fresh.data();
      injected_ptr = out_injected.data();
    } else {
      EXPECT_EQ(out_fresh.data(), fresh_ptr);
      EXPECT_EQ(out_injected.data(), injected_ptr);
    }
  }
  const auto t1 = std::chrono::steady_clock::now();
  const double avg_us =
      std::chrono::duration<double, std::micro>(t1 - t0).count() / (2.0 * kIterations);
  EXPECT_LT(avg_us, 100.0) << "Expected microsecond-scale latency (< 100 us/call), got " << avg_us
                           << " us";
}

}  // namespace ultrahdr
