/*
 * Copyright 2022 The Android Open Source Project
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
  ultrahdr_metadata_struct expected;
  expected.version = "1.0";
  expected.maxContentBoost = 100.0f;
  expected.minContentBoost = 1.0f;
  expected.gamma = 1.0f;
  expected.offsetSdr = 0.0f;
  expected.offsetHdr = 0.0f;
  expected.hdrCapacityMin = 1.0f;
  expected.hdrCapacityMax = expected.maxContentBoost;

  gain_map_metadata metadata;
  gain_map_metadata::gainmapMetadataFloatToFraction(&expected, &metadata);
//  metadata.dump();

  std::vector<uint8_t> data;
  gain_map_metadata::encodeGainmapMetadata(&metadata, data);

  gain_map_metadata decodedMetadata;
  gain_map_metadata::decodeGainmapMetadata(data, &decodedMetadata);

  ultrahdr_metadata_struct decodedUHdrMetadata;
  gain_map_metadata::gainmapMetadataFractionToFloat(&decodedMetadata, &decodedUHdrMetadata);

  EXPECT_EQ(expected.maxContentBoost, decodedUHdrMetadata.maxContentBoost);
  EXPECT_EQ(expected.minContentBoost, decodedUHdrMetadata.minContentBoost);
  EXPECT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
  EXPECT_EQ(expected.offsetSdr, decodedUHdrMetadata.offsetSdr);
  EXPECT_EQ(expected.offsetHdr, decodedUHdrMetadata.offsetHdr);
  EXPECT_EQ(expected.hdrCapacityMin, decodedUHdrMetadata.hdrCapacityMin);
  EXPECT_EQ(expected.hdrCapacityMax, decodedUHdrMetadata.hdrCapacityMax);


//  const std::string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";
//  printf("[dichenzhang] sizeof(kIsoNameSpace)=%zu\n", sizeof(kIsoNameSpace));


  printf("[dichenzhang] sizefdasof(kIso)=%zu\n", kIso.size());
}
}  // namespace ultrahdr
