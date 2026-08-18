/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <gtest/gtest.h>
#include <climits>
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

static uhdr_gainmap_metadata_frac makeValidFractionMetadata() {
  uhdr_gainmap_metadata_frac metadata{};
  metadata.baseHdrHeadroomD = 1;
  metadata.alternateHdrHeadroomN = 3;
  metadata.alternateHdrHeadroomD = 1;
  for (int i = 0; i < 3; ++i) {
    metadata.gainMapMinD[i] = 1;
    metadata.gainMapMaxN[i] = 2;
    metadata.gainMapMaxD[i] = 1;
    metadata.gainMapGammaN[i] = 1;
    metadata.gainMapGammaD[i] = 1;
    metadata.baseOffsetD[i] = 1;
    metadata.alternateOffsetD[i] = 1;
  }
  return metadata;
}

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

TEST_F(GainMapMetadataTest, fractionToFloatRejectsInvalidValues) {
  uhdr_gainmap_metadata_ext_t converted;

  uhdr_gainmap_metadata_frac metadata = makeValidFractionMetadata();
  metadata.gainMapGammaD[0] = 0;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);

  metadata = makeValidFractionMetadata();
  metadata.gainMapGammaN[0] = 0;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);

  metadata = makeValidFractionMetadata();
  metadata.gainMapMaxN[0] = INT32_MAX;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);

  metadata = makeValidFractionMetadata();
  metadata.gainMapMinN[0] = INT32_MIN;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);

  metadata = makeValidFractionMetadata();
  metadata.alternateHdrHeadroomN = UINT32_MAX;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);

  metadata = makeValidFractionMetadata();
  metadata.gainMapMinN[0] = 2;
  metadata.gainMapMaxN[0] = 1;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);

  // These fractions are ordered incorrectly but both round to 1.0f. Validate their exact rational
  // values so float precision cannot hide the invalid range.
  metadata = makeValidFractionMetadata();
  metadata.gainMapMinN[0] = 16777217;
  metadata.gainMapMinD[0] = 16777216;
  metadata.gainMapMaxN[0] = 1;
  metadata.gainMapMaxD[0] = 1;
  EXPECT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_INVALID_PARAM);
}

TEST_F(GainMapMetadataTest, fractionToFloatAcceptsNegativeOffsets) {
  uhdr_gainmap_metadata_frac metadata = makeValidFractionMetadata();
  for (int i = 0; i < 3; ++i) {
    metadata.baseOffsetN[i] = -1;
    metadata.baseOffsetD[i] = 16;
    metadata.alternateOffsetN[i] = -1;
    metadata.alternateOffsetD[i] = 16;
  }

  uhdr_gainmap_metadata_ext_t converted;
  ASSERT_EQ(
      uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&metadata, &converted).error_code,
      UHDR_CODEC_OK);
  for (int i = 0; i < 3; ++i) {
    EXPECT_FLOAT_EQ(converted.offset_sdr[i], -0.0625f);
    EXPECT_FLOAT_EQ(converted.offset_hdr[i], -0.0625f);
  }
}

}  // namespace ultrahdr
