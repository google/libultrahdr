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
  expected.max_content_boost = 100.5f;
  expected.min_content_boost = 1.5f;
  expected.gamma = 1.0f;
  expected.offset_sdr = 0.0f;
  expected.offset_hdr = 0.0f;
  expected.hdr_capacity_min = 1.0f;
  expected.hdr_capacity_max = expected.max_content_boost;

  uhdr_gainmap_metadata_frac metadata;
  uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata);
  //  metadata.dump();

  std::vector<uint8_t> data;
  uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data);

  uhdr_gainmap_metadata_frac decodedMetadata;
  uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata);

  uhdr_gainmap_metadata_ext_t decodedUHdrMetadata;
  uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
                                                             &decodedUHdrMetadata);

  EXPECT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
  EXPECT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
  EXPECT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
  EXPECT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
  EXPECT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
  EXPECT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
  EXPECT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
}
}  // namespace ultrahdr
