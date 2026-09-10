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
#include <cstdint>
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

namespace {

void setChannel(uhdr_gainmap_metadata_frac& metadata, int channel, int32_t gain_min_n,
                int32_t gain_max_n, uint32_t gamma_n, int32_t base_offset_n,
                int32_t alternate_offset_n, uint32_t denominator) {
  metadata.gainMapMinN[channel] = gain_min_n;
  metadata.gainMapMinD[channel] = denominator;
  metadata.gainMapMaxN[channel] = gain_max_n;
  metadata.gainMapMaxD[channel] = denominator;
  metadata.gainMapGammaN[channel] = gamma_n;
  metadata.gainMapGammaD[channel] = denominator;
  metadata.baseOffsetN[channel] = base_offset_n;
  metadata.baseOffsetD[channel] = denominator;
  metadata.alternateOffsetN[channel] = alternate_offset_n;
  metadata.alternateOffsetD[channel] = denominator;
}

uhdr_gainmap_metadata_frac singleEqualDenominators() {
  uhdr_gainmap_metadata_frac metadata;
  metadata.baseHdrHeadroomN = 0;
  metadata.baseHdrHeadroomD = 64;
  metadata.alternateHdrHeadroomN = 192;
  metadata.alternateHdrHeadroomD = 64;
  for (int channel = 0; channel < 3; ++channel) {
    setChannel(metadata, channel, -64, 128, 64, 1, 2, 64);
  }
  metadata.useBaseColorSpace = true;
  return metadata;
}

uhdr_gainmap_metadata_frac singleMixedDenominators() {
  uhdr_gainmap_metadata_frac metadata;
  metadata.baseHdrHeadroomN = 0;
  metadata.baseHdrHeadroomD = 1;
  metadata.alternateHdrHeadroomN = 7;
  metadata.alternateHdrHeadroomD = 2;
  for (int channel = 0; channel < 3; ++channel) {
    metadata.gainMapMinN[channel] = -1;
    metadata.gainMapMinD[channel] = 3;
    metadata.gainMapMaxN[channel] = 5;
    metadata.gainMapMaxD[channel] = 4;
    metadata.gainMapGammaN[channel] = 6;
    metadata.gainMapGammaD[channel] = 5;
    metadata.baseOffsetN[channel] = -1;
    metadata.baseOffsetD[channel] = 7;
    metadata.alternateOffsetN[channel] = 2;
    metadata.alternateOffsetD[channel] = 9;
  }
  metadata.useBaseColorSpace = false;
  return metadata;
}

uhdr_gainmap_metadata_frac threeEqualDenominators() {
  uhdr_gainmap_metadata_frac metadata = singleEqualDenominators();
  setChannel(metadata, 1, -32, 160, 72, 3, 4, 64);
  setChannel(metadata, 2, -16, 192, 80, 5, 6, 64);
  return metadata;
}

uhdr_gainmap_metadata_frac threeMixedDenominators() {
  uhdr_gainmap_metadata_frac metadata = singleMixedDenominators();
  metadata.useBaseColorSpace = true;
  metadata.gainMapMaxN[1] = 6;
  metadata.gainMapMaxD[1] = 5;
  metadata.gainMapGammaN[2] = 8;
  metadata.gainMapGammaD[2] = 7;
  metadata.baseOffsetN[2] = -2;
  metadata.baseOffsetD[2] = 11;
  return metadata;
}

void expectEncodedBytes(const uhdr_gainmap_metadata_frac& metadata,
                        const std::vector<uint8_t>& expected) {
  std::vector<uint8_t> encoded;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, encoded).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(encoded.size(), expected.size());
  EXPECT_EQ(encoded, expected);
}

const std::vector<uint8_t> kSingleEqualDenominators = {
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x40, 0xff, 0xff, 0xff,
    0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x40,
};

const std::vector<uint8_t> kSingleMixedDenominators = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x09,
};

const std::vector<uint8_t> kThreeEqualDenominators = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x40, 0xff, 0xff, 0xff,
    0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x40, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0xa0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x40, 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x50, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x40,
};

const std::vector<uint8_t> kThreeMixedDenominators = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
    0x09, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x05, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x09, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00,
    0x0b, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x09,
};

const std::vector<uint8_t> kLegacySingleEqualDenominators = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02,
};

const std::vector<uint8_t> kLegacyThreeEqualDenominators = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xc0, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0xff, 0xff, 0xff, 0xe0, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0xff, 0xff, 0xff,
    0xf0, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x06,
};

}  // namespace

TEST(GainmapMetadataTest, EncodesSingleChannelEqualDenominatorsWithFinalLayout) {
  EXPECT_EQ(kSingleEqualDenominators.size(), 61u);
  expectEncodedBytes(singleEqualDenominators(), kSingleEqualDenominators);
}

TEST(GainmapMetadataTest, EncodesSingleChannelMixedDenominatorsWithFinalLayout) {
  EXPECT_EQ(kSingleMixedDenominators.size(), 61u);
  expectEncodedBytes(singleMixedDenominators(), kSingleMixedDenominators);
}

TEST(GainmapMetadataTest, EncodesThreeChannelsEqualDenominatorsWithFinalLayout) {
  EXPECT_EQ(kThreeEqualDenominators.size(), 141u);
  expectEncodedBytes(threeEqualDenominators(), kThreeEqualDenominators);
}

TEST(GainmapMetadataTest, EncodesThreeChannelsMixedDenominatorsWithFinalLayout) {
  EXPECT_EQ(kThreeMixedDenominators.size(), 141u);
  expectEncodedBytes(threeMixedDenominators(), kThreeMixedDenominators);
}

TEST(GainmapMetadataTest, DecodesLegacyCompactSingleChannelMetadata) {
  uhdr_gainmap_metadata_frac decoded;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(kLegacySingleEqualDenominators,
                                                               &decoded)
                .error_code,
            UHDR_CODEC_OK);
  EXPECT_TRUE(decoded.useBaseColorSpace);
  EXPECT_FALSE(decoded.backwardDirection);
  EXPECT_EQ(decoded.baseHdrHeadroomN, 0u);
  EXPECT_EQ(decoded.baseHdrHeadroomD, 64u);
  EXPECT_EQ(decoded.alternateHdrHeadroomN, 192u);
  EXPECT_EQ(decoded.alternateHdrHeadroomD, 64u);
  for (int channel = 0; channel < 3; ++channel) {
    EXPECT_EQ(decoded.gainMapMinN[channel], -64);
    EXPECT_EQ(decoded.gainMapMinD[channel], 64u);
    EXPECT_EQ(decoded.gainMapMaxN[channel], 128);
    EXPECT_EQ(decoded.gainMapMaxD[channel], 64u);
    EXPECT_EQ(decoded.gainMapGammaN[channel], 64u);
    EXPECT_EQ(decoded.gainMapGammaD[channel], 64u);
    EXPECT_EQ(decoded.baseOffsetN[channel], 1);
    EXPECT_EQ(decoded.baseOffsetD[channel], 64u);
    EXPECT_EQ(decoded.alternateOffsetN[channel], 2);
    EXPECT_EQ(decoded.alternateOffsetD[channel], 64u);
  }
}

TEST(GainmapMetadataTest, DecodesLegacyCompactThreeChannelMetadata) {
  uhdr_gainmap_metadata_frac decoded;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(kLegacyThreeEqualDenominators,
                                                               &decoded)
                .error_code,
            UHDR_CODEC_OK);
  EXPECT_TRUE(decoded.useBaseColorSpace);
  EXPECT_FALSE(decoded.backwardDirection);
  EXPECT_EQ(decoded.baseHdrHeadroomN, 0u);
  EXPECT_EQ(decoded.baseHdrHeadroomD, 64u);
  EXPECT_EQ(decoded.alternateHdrHeadroomN, 192u);
  EXPECT_EQ(decoded.alternateHdrHeadroomD, 64u);
  const int32_t gain_min_n[] = {-64, -32, -16};
  const int32_t gain_max_n[] = {128, 160, 192};
  const uint32_t gamma_n[] = {64, 72, 80};
  const int32_t base_offset_n[] = {1, 3, 5};
  const int32_t alternate_offset_n[] = {2, 4, 6};
  for (int channel = 0; channel < 3; ++channel) {
    EXPECT_EQ(decoded.gainMapMinN[channel], gain_min_n[channel]);
    EXPECT_EQ(decoded.gainMapMinD[channel], 64u);
    EXPECT_EQ(decoded.gainMapMaxN[channel], gain_max_n[channel]);
    EXPECT_EQ(decoded.gainMapMaxD[channel], 64u);
    EXPECT_EQ(decoded.gainMapGammaN[channel], gamma_n[channel]);
    EXPECT_EQ(decoded.gainMapGammaD[channel], 64u);
    EXPECT_EQ(decoded.baseOffsetN[channel], base_offset_n[channel]);
    EXPECT_EQ(decoded.baseOffsetD[channel], 64u);
    EXPECT_EQ(decoded.alternateOffsetN[channel], alternate_offset_n[channel]);
    EXPECT_EQ(decoded.alternateOffsetD[channel], 64u);
  }
}

TEST(GainmapMetadataTest, RejectsBackwardDirectionBeforeWriting) {
  uhdr_gainmap_metadata_frac metadata = singleEqualDenominators();
  metadata.backwardDirection = true;
  const std::vector<uint8_t> expected = {0xa5, 0x5a};
  std::vector<uint8_t> output = expected;

  const uhdr_error_info_t status =
      uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, output);
  EXPECT_EQ(status.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  EXPECT_EQ(output, expected);
}

TEST(GainmapMetadataTest, LegacyBackwardDirectionStillRejectsFloatConversion) {
  std::vector<uint8_t> legacy = kLegacySingleEqualDenominators;
  legacy[4] |= 4;
  uhdr_gainmap_metadata_frac decoded;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(legacy, &decoded).error_code,
            UHDR_CODEC_OK);
  EXPECT_TRUE(decoded.backwardDirection);

  uhdr_gainmap_metadata_ext_t float_metadata;
  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decoded, &float_metadata)
                .error_code,
            UHDR_CODEC_UNSUPPORTED_FEATURE);
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

}  // namespace ultrahdr
