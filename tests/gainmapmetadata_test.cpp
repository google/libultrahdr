/*
 * Copyright 2024 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <vector>

#include "ultrahdr/gainmapmetadata.h"

namespace ultrahdr {

class GainMapMetadataTest : public testing::Test {
 public:
  GainMapMetadataTest();
  ~GainMapMetadataTest();

 protected:
  virtual void SetUp();
  virtual void TearDown();
};

GainMapMetadataTest::GainMapMetadataTest() {}

GainMapMetadataTest::~GainMapMetadataTest() {}

void GainMapMetadataTest::SetUp() {}

void GainMapMetadataTest::TearDown() {}

const std::string kIso = "urn:iso:std:iso:ts:21496:-1";

TEST_F(GainMapMetadataTest, encodeMetadataThenDecode) {
  uhdr_gainmap_metadata_ext_t expected("1.0");
  for (int i = 0; i < 3; i++) {
    expected.max_content_boost[i] = 100.5f + i;
    expected.min_content_boost[i] = 1.5f + i * 0.1f;
    expected.gamma[i] = 1.0f + i * 0.01f;
    expected.offset_sdr[i] = 0.0625f + i * 0.025f;
    expected.offset_hdr[i] = 0.0625f + i * 0.025f;
  }
  expected.hdr_capacity_min = 1.0f;
  expected.hdr_capacity_max = 10000.0f / 203.0f;
  expected.use_base_cg = false;

  uhdr_gainmap_metadata_frac metadata;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata).error_code,
      UHDR_CODEC_OK);
  //  metadata.dump();

  std::vector<uint8_t> data;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data).error_code,
            UHDR_CODEC_OK);

  uhdr_gainmap_metadata_frac decodedMetadata;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata).error_code,
            UHDR_CODEC_OK);

  uhdr_gainmap_metadata_ext_t decodedUHdrMetadata;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
                                                                       &decodedUHdrMetadata)
                .error_code,
            UHDR_CODEC_OK);

  for (int i = 0; i < 3; i++) {
    EXPECT_FLOAT_EQ(expected.max_content_boost[i], decodedUHdrMetadata.max_content_boost[i]);
    EXPECT_FLOAT_EQ(expected.min_content_boost[i], decodedUHdrMetadata.min_content_boost[i]);
    EXPECT_FLOAT_EQ(expected.gamma[i], decodedUHdrMetadata.gamma[i]);
    EXPECT_FLOAT_EQ(expected.offset_sdr[i], decodedUHdrMetadata.offset_sdr[i]);
    EXPECT_FLOAT_EQ(expected.offset_hdr[i], decodedUHdrMetadata.offset_hdr[i]);
  }
  EXPECT_FLOAT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
  EXPECT_FLOAT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
  EXPECT_EQ(expected.use_base_cg, decodedUHdrMetadata.use_base_cg);

  data.clear();
  for (int i = 0; i < 3; i++) {
    expected.min_content_boost[i] = 0.000578369f + i * 0.001f;
    expected.offset_sdr[i] = -0.0625f + i * 0.001f;
    expected.offset_hdr[i] = -0.0625f + i * 0.001f;
  }
  expected.hdr_capacity_max = 1000.0f / 203.0f;
  expected.use_base_cg = true;

  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata).error_code,
      UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
                                                                       &decodedUHdrMetadata)
                .error_code,
            UHDR_CODEC_OK);

  for (int i = 0; i < 3; i++) {
    EXPECT_FLOAT_EQ(expected.max_content_boost[i], decodedUHdrMetadata.max_content_boost[i]);
    EXPECT_FLOAT_EQ(expected.min_content_boost[i], decodedUHdrMetadata.min_content_boost[i]);
    EXPECT_FLOAT_EQ(expected.gamma[i], decodedUHdrMetadata.gamma[i]);
    EXPECT_FLOAT_EQ(expected.offset_sdr[i], decodedUHdrMetadata.offset_sdr[i]);
    EXPECT_FLOAT_EQ(expected.offset_hdr[i], decodedUHdrMetadata.offset_hdr[i]);
  }
  EXPECT_FLOAT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
  EXPECT_FLOAT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
  EXPECT_EQ(expected.use_base_cg, decodedUHdrMetadata.use_base_cg);
}

}  // namespace ultrahdr
