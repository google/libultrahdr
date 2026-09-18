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
    expected.offset_sdr[i] = 0.0625f + i * 0.001f;
    expected.offset_hdr[i] = 0.0625f + i * 0.001f;
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

TEST(GainmapMetadataTest, RejectsMalformedISO21496_1Ratios) {
  uhdr_gainmap_metadata_frac frac{};
  for (int i = 0; i < 3; ++i) {
    frac.gainMapMaxN[i] = 1;
    frac.gainMapMaxD[i] = 1;
    frac.gainMapMinN[i] = 0;
    frac.gainMapMinD[i] = 1;
    frac.gainMapGammaN[i] = 1;
    frac.gainMapGammaD[i] = 1;
    frac.baseOffsetN[i] = 0;
    frac.baseOffsetD[i] = 1;
    frac.alternateOffsetN[i] = 0;
    frac.alternateOffsetD[i] = 1;
  }
  frac.baseHdrHeadroomN = 0;
  frac.baseHdrHeadroomD = 1;
  frac.alternateHdrHeadroomN = 1;
  frac.alternateHdrHeadroomD = 1;

  // Test 1: max_content_boost < min_content_boost
  frac.gainMapMaxN[0] = 0; // log2(max_boost) = 0 -> max_boost = 1.0
  frac.gainMapMinN[0] = 2; // log2(min_boost) = 2 -> min_boost = 4.0
  uhdr_gainmap_metadata_ext_t float_meta;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&frac, &float_meta).error_code,
            UHDR_CODEC_INVALID_PARAM);

  // Test 2: Inverted HDR capacity range (max <= min)
  frac.gainMapMaxN[0] = 1;
  frac.gainMapMinN[0] = 0;
  frac.alternateHdrHeadroomN = 0; // log2(headroom_max) = 0 -> 1.0
  frac.baseHdrHeadroomN = 1;      // log2(headroom_min) = 1 -> 2.0
  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&frac, &float_meta).error_code,
            UHDR_CODEC_INVALID_PARAM);

  // These fractions are ordered incorrectly but both round to 1.0f. Validate their exact rational
  // values so float precision cannot hide the invalid range.
  frac.alternateHdrHeadroomN = 1;
  frac.baseHdrHeadroomN = 0;
  frac.gainMapMinN[0] = 16777217;
  frac.gainMapMinD[0] = 16777216;
  frac.gainMapMaxN[0] = 1;
  frac.gainMapMaxD[0] = 1;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&frac, &float_meta).error_code,
            UHDR_CODEC_INVALID_PARAM);
}


TEST_F(GainMapMetadataTest, EncodedFlagsClearsReservedBit3) {
  uhdr_gainmap_metadata_frac frac{};
  frac.baseHdrHeadroomN = 0;
  frac.baseHdrHeadroomD = 1000;
  frac.alternateHdrHeadroomN = 1000;
  frac.alternateHdrHeadroomD = 1000;
  for (int c = 0; c < 3; ++c) {
    frac.gainMapMinN[c] = 0;
    frac.gainMapMinD[c] = 1000;
    frac.gainMapMaxN[c] = 1000;
    frac.gainMapMaxD[c] = 1000;
    frac.gainMapGammaN[c] = 1000;
    frac.gainMapGammaD[c] = 1000;
    frac.baseOffsetN[c] = 0;
    frac.baseOffsetD[c] = 1000;
    frac.alternateOffsetN[c] = 0;
    frac.alternateOffsetD[c] = 1000;
  }

  std::vector<uint8_t> data;
  ASSERT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&frac, data).error_code, UHDR_CODEC_OK);

  // Byte 4 is the flags byte (after 2 bytes min_version + 2 bytes writer_version)
  ASSERT_GE(data.size(), 5u);
  uint8_t flags = data[4];
  EXPECT_EQ(flags & 0x08, 0) << "Bit 3 is reserved in ISO/IEC 21496-1 and must not be set";
}

TEST_F(GainMapMetadataTest, RejectsZeroDenominatorDuringEncoding) {
  uhdr_gainmap_metadata_frac frac{};
  frac.baseHdrHeadroomD = 0; // Invalid zero denominator

  std::vector<uint8_t> data;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&frac, data).error_code,
            UHDR_CODEC_INVALID_PARAM);
}

TEST_F(GainMapMetadataTest, DecodesLegacyCommonDenominatorStream) {
  // Synthetic legacy stream with bit 3 set (common denominator = 1000)
  const std::vector<uint8_t> legacy_data = {
      0x00, 0x00,             // min_version = 0
      0x00, 0x00,             // writer_version = 0
      0x08,                   // flags: bit 3 set (useCommonDenominator), 1 channel
      0x00, 0x00, 0x03, 0xe8, // commonDenominator = 1000
      0x00, 0x00, 0x00, 0x00, // baseHdrHeadroomN = 0
      0x00, 0x00, 0x03, 0xe8, // alternateHdrHeadroomN = 1000
      0x00, 0x00, 0x00, 0x00, // gainMapMinN = 0
      0x00, 0x00, 0x03, 0xe8, // gainMapMaxN = 1000
      0x00, 0x00, 0x03, 0xe8, // gainMapGammaN = 1000
      0x00, 0x00, 0x00, 0x00, // baseOffsetN = 0
      0x00, 0x00, 0x00, 0x00  // alternateOffsetN = 0
  };

  uhdr_gainmap_metadata_frac decoded;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(legacy_data, &decoded).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(decoded.baseHdrHeadroomD, 1000u);
  EXPECT_EQ(decoded.alternateHdrHeadroomD, 1000u);
}

}  // namespace ultrahdr
