/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#ifdef UHDR_ENABLE_SMPTE2094_50
#include <vector>
#include <memory>

#include "ultrahdr/agtm.h"
#include "smpte2094_50/smpte2094_50.h"

namespace ultrahdr {

class AgtmTest : public testing::Test {
 public:
  uhdr_raw_image_t createTestImage(std::vector<uint16_t>& y_data, std::vector<uint16_t>& uv_data) {
    uhdr_raw_image_t image;
    image.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    image.cg = UHDR_CG_BT_2100;
    image.ct = UHDR_CT_PQ;
    image.range = UHDR_CR_FULL_RANGE;
    image.w = 2;
    image.h = 2;
    image.stride[UHDR_PLANE_Y] = 2;
    image.stride[UHDR_PLANE_UV] = 2;

    y_data.assign(4, 1023 << 6);  // white
    uv_data.assign(4, 512 << 6);  // neutral
    image.planes[UHDR_PLANE_Y] = y_data.data();
    image.planes[UHDR_PLANE_UV] = uv_data.data();
    return image;
  }
};

TEST_F(AgtmTest, GenerateGainMap) {
  std::vector<uint16_t> y_data, uv_data;
  uhdr_raw_image_t image = createTestImage(y_data, uv_data);

  smpte2094_50::DynamicMetadata metadata{};
  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = 1.0f; // factor 2
  rule.curve.push_back({0.0f, 0.0f});
  rule.curve.push_back({1.0f, 1.0f});
  metadata.rules.push_back(rule);

  uhdr_gainmap_metadata_ext_t gainmap_metadata;
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_img;

  auto status = generateGainMap(&image, metadata, &gainmap_metadata, gainmap_img);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  ASSERT_NE(gainmap_img, nullptr);

  EXPECT_EQ(gainmap_img->w, 2);
  EXPECT_EQ(gainmap_img->h, 2);
  EXPECT_FLOAT_EQ(gainmap_metadata.max_content_boost[0], 2.0f);

  uint8_t* out_data = reinterpret_cast<uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]);
  // RGB888, so 3 bytes per pixel.
  EXPECT_EQ(out_data[0], 255);
  EXPECT_EQ(out_data[1], 255);
  EXPECT_EQ(out_data[2], 255);
}

TEST_F(AgtmTest, GenerateGainMapNoRules) {
  std::vector<uint16_t> y_data, uv_data;
  uhdr_raw_image_t image = createTestImage(y_data, uv_data);

  smpte2094_50::DynamicMetadata metadata{};
  metadata.baseline_hdr_headroom_log2 = 1.0f; // factor 2

  uhdr_gainmap_metadata_ext_t gainmap_metadata;
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_img;

  auto status = generateGainMap(&image, metadata, &gainmap_metadata, gainmap_img);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  ASSERT_NE(gainmap_img, nullptr);

  EXPECT_FLOAT_EQ(gainmap_metadata.max_content_boost[0], 2.0f);

  uint8_t* out_data = reinterpret_cast<uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]);
  // gain factor should be 1.0 because no rules were provided.
  // affineMapGain(log2(1.0), 0.0, 1.0, 1.0) = (0 - 0) / (1 - 0) * 255 = 0
  EXPECT_EQ(out_data[0], 0);
}

TEST_F(AgtmTest, GenerateGainMapExplicitCapacity) {
  std::vector<uint16_t> y_data, uv_data;
  uhdr_raw_image_t image = createTestImage(y_data, uv_data);

  smpte2094_50::DynamicMetadata metadata{};
  smpte2094_50::ToneMappingRule rule{};
  rule.alternate_hdr_headroom_log2 = 2.0f; // factor 4
  rule.curve.push_back({0.0f, 0.0f});
  rule.curve.push_back({1.0f, 2.0f});
  metadata.rules.push_back(rule);

  uhdr_gainmap_metadata_ext_t gainmap_metadata;
  std::unique_ptr<uhdr_raw_image_ext_t> gainmap_img;

  // Explicitly set capacity to factor 2 (log2 = 1.0)
  auto status = generateGainMap(&image, metadata, &gainmap_metadata, gainmap_img, 2.0f);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  ASSERT_NE(gainmap_img, nullptr);

  EXPECT_FLOAT_EQ(gainmap_metadata.hdr_capacity_min, 1.0f);
  EXPECT_FLOAT_EQ(gainmap_metadata.hdr_capacity_max, 2.0f);

  // Target headroom log2(2.0) = 1.0.
  // Interpolation: H0=0 (baseline), H1=2 (rule), target=1.
  // w1 = (1-0)/(2-0) = 0.5.
  // gy = 0.5 * 0 + 0.5 * 2 = 1.
  // gainFactor = exp2(1) = 2.
  // affineMapGain(log2(2), log2(1), log2(2), 1) = (1 - 0) / (1 - 0) * 255 = 255
  uint8_t* out_data = reinterpret_cast<uint8_t*>(gainmap_img->planes[UHDR_PLANE_PACKED]);
  EXPECT_EQ(out_data[0], 255);
}

} // namespace ultrahdr
#endif
