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

#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <vector>

#include "ultrahdr/agtm.h"

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
  }
}

}  // namespace ultrahdr
