/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <gtest/gtest.h>

#include "ultrahdr/icc.h"

namespace ultrahdr {

class IccHelperTest : public testing::Test {
 public:
  IccHelperTest();
  ~IccHelperTest();

 protected:
  virtual void SetUp();
  virtual void TearDown();
};

IccHelperTest::IccHelperTest() {}

IccHelperTest::~IccHelperTest() {}

void IccHelperTest::SetUp() {}

void IccHelperTest::TearDown() {}

TEST_F(IccHelperTest, iccWriteThenRead) {
  std::shared_ptr<DataStruct> iccBt709 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  ASSERT_NE(iccBt709->getLength(), 0);
  ASSERT_NE(iccBt709->getData(), nullptr);
  EXPECT_EQ(IccHelper::readIccColorGamut(iccBt709->getData(), iccBt709->getLength()),
            UHDR_CG_BT_709);

  std::shared_ptr<DataStruct> iccP3 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3);
  ASSERT_NE(iccP3->getLength(), 0);
  ASSERT_NE(iccP3->getData(), nullptr);
  EXPECT_EQ(IccHelper::readIccColorGamut(iccP3->getData(), iccP3->getLength()), UHDR_CG_DISPLAY_P3);

  std::shared_ptr<DataStruct> iccBt2100 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_2100);
  ASSERT_NE(iccBt2100->getLength(), 0);
  ASSERT_NE(iccBt2100->getData(), nullptr);
  EXPECT_EQ(IccHelper::readIccColorGamut(iccBt2100->getData(), iccBt2100->getLength()),
            UHDR_CG_BT_2100);
}

TEST_F(IccHelperTest, iccEndianness) {
  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  size_t profile_size = icc->getLength() - kICCIdentifierSize;

  uint8_t* icc_bytes = reinterpret_cast<uint8_t*>(icc->getData()) + kICCIdentifierSize;
  uint32_t encoded_size =
      static_cast<uint32_t>(icc_bytes[0]) << 24 | static_cast<uint32_t>(icc_bytes[1]) << 16 |
      static_cast<uint32_t>(icc_bytes[2]) << 8 | static_cast<uint32_t>(icc_bytes[3]);

  EXPECT_EQ(static_cast<size_t>(encoded_size), profile_size);
}

TEST_F(IccHelperTest, iccIntegerOverflowOffset) {
  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  ASSERT_NE(icc->getLength(), 0);
  ASSERT_NE(icc->getData(), nullptr);

  // 1. Mutate cicp tag offset to cause integer overflow when added to identifier size.
  std::vector<uint8_t> buffer_cicp(reinterpret_cast<uint8_t*>(icc->getData()),
                                   reinterpret_cast<uint8_t*>(icc->getData()) + icc->getLength());
  uint8_t* icc_bytes = buffer_cicp.data() + kICCIdentifierSize;
  uint32_t tag_count_be;
  memcpy(&tag_count_be, icc_bytes + offsetof(ICCHeader, tag_count), sizeof(tag_count_be));
  size_t tag_count = Endian_SwapBE32(tag_count_be);
  for (size_t tag_idx = 0; tag_idx < tag_count; ++tag_idx) {
    size_t entry_offset = sizeof(ICCHeader) + tag_idx * 12;
    uint32_t sig_be;
    memcpy(&sig_be, icc_bytes + entry_offset, sizeof(sig_be));
    if (sig_be == Endian_SwapBE32(kTAG_cicp)) {
      uint32_t bad_offset_be = Endian_SwapBE32(0xfffffff1U);
      memcpy(icc_bytes + entry_offset + 4, &bad_offset_be, sizeof(bad_offset_be));
      break;
    }
  }
  // With overflow-safe bounds checks, cicp is ignored and fallback matrix tags return BT_709 cleanly without crash.
  EXPECT_EQ(IccHelper::readIccColorGamut(buffer_cicp.data(), buffer_cicp.size()), UHDR_CG_BT_709);

  // 2. Mutate red colorant tag offset to cause integer overflow.
  std::vector<uint8_t> buffer_rxyz(reinterpret_cast<uint8_t*>(icc->getData()),
                                   reinterpret_cast<uint8_t*>(icc->getData()) + icc->getLength());
  icc_bytes = buffer_rxyz.data() + kICCIdentifierSize;
  for (size_t tag_idx = 0; tag_idx < tag_count; ++tag_idx) {
    size_t entry_offset = sizeof(ICCHeader) + tag_idx * 12;
    uint32_t sig_be;
    memcpy(&sig_be, icc_bytes + entry_offset, sizeof(sig_be));
    if (sig_be == Endian_SwapBE32(kTAG_rXYZ)) {
      uint32_t bad_offset_be = Endian_SwapBE32(0xfffffff1U);
      memcpy(icc_bytes + entry_offset + 4, &bad_offset_be, sizeof(bad_offset_be));
      break;
    }
  }
  // With overflow-safe bounds checks, invalid colorant offset returns UHDR_CG_UNSPECIFIED without crash.
  EXPECT_EQ(IccHelper::readIccColorGamut(buffer_rxyz.data(), buffer_rxyz.size()), UHDR_CG_UNSPECIFIED);
}

TEST_F(IccHelperTest, iccPqA2B0AndB2A0Populated) {
  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_PQ, UHDR_CG_BT_2100);
  ASSERT_NE(icc, nullptr);
  ASSERT_GT(icc->getLength(), kICCIdentifierSize + sizeof(ICCHeader));
  EXPECT_EQ(IccHelper::readIccColorGamut(icc->getData(), icc->getLength()), UHDR_CG_BT_2100);

  const uint8_t* icc_bytes =
      reinterpret_cast<const uint8_t*>(icc->getData()) + kICCIdentifierSize;
  const size_t profile_size = icc->getLength() - kICCIdentifierSize;
  uint32_t tag_count_be = 0;
  memcpy(&tag_count_be, icc_bytes + offsetof(ICCHeader, tag_count), sizeof(tag_count_be));
  const size_t tag_count = Endian_SwapBE32(tag_count_be);
  ASSERT_LE(tag_count, (profile_size - sizeof(ICCHeader)) / 12u);

  bool found_a2b0 = false;
  bool found_b2a0 = false;
  for (size_t tag_idx = 0; tag_idx < tag_count; ++tag_idx) {
    const size_t entry_offset = sizeof(ICCHeader) + tag_idx * 12;
    uint32_t sig_be = 0, off_be = 0, sz_be = 0;
    memcpy(&sig_be, icc_bytes + entry_offset, 4);
    memcpy(&off_be, icc_bytes + entry_offset + 4, 4);
    memcpy(&sz_be, icc_bytes + entry_offset + 8, 4);
    const uint32_t sig = Endian_SwapBE32(sig_be);
    const size_t off = Endian_SwapBE32(off_be);
    const size_t sz = Endian_SwapBE32(sz_be);
    ASSERT_LE(off, profile_size);
    ASSERT_LE(sz, profile_size - off);

    if (sig == kTAG_A2B0) {
      found_a2b0 = true;
      ASSERT_GE(sz, 32u);
      const uint8_t* tag = icc_bytes + off;
      uint32_t b_off_be = 0, clut_off_be = 0, a_off_be = 0;
      memcpy(&b_off_be, tag + 12, 4);
      memcpy(&clut_off_be, tag + 24, 4);
      memcpy(&a_off_be, tag + 28, 4);
      const size_t b_off = Endian_SwapBE32(b_off_be);
      const size_t clut_off = Endian_SwapBE32(clut_off_be);
      const size_t a_off = Endian_SwapBE32(a_off_be);

      constexpr size_t kCurvesBytes = 3u * 16u;
      constexpr size_t kClutHeaderBytes = 20u;
      constexpr size_t kClutTableBytes = 17u * 17u * 17u * 6u;
      ASSERT_LE(b_off, sz);
      ASSERT_LE(kCurvesBytes, sz - b_off);
      ASSERT_LE(clut_off, sz);
      ASSERT_LE(kClutHeaderBytes + kClutTableBytes, sz - clut_off);
      ASSERT_LE(a_off, sz);
      ASSERT_LE(kCurvesBytes, sz - a_off);

      // All 3 B-curves must be written (each is a 16-byte 'para' curve).
      for (size_t c = 0; c < 3; ++c) {
        uint32_t curve_sig_be = 0;
        memcpy(&curve_sig_be, tag + b_off + c * 16, 4);
        EXPECT_EQ(Endian_SwapBE32(curve_sig_be), kTAG_ParaCurveType);
      }
      // CLUT header must encode 17x17x17 grid dimensions and 16-bit precision, with non-zero table
      // entries.
      EXPECT_EQ(tag[clut_off + 0], 17u);
      EXPECT_EQ(tag[clut_off + 1], 17u);
      EXPECT_EQ(tag[clut_off + 2], 17u);
      EXPECT_EQ(tag[clut_off + 16], 2u);
      const size_t clut_data_off = clut_off + kClutHeaderBytes;
      bool has_nonzero_clut = false;
      for (size_t i = 0; i < kClutTableBytes; ++i) {
        if (tag[clut_data_off + i] != 0) {
          has_nonzero_clut = true;
          break;
        }
      }
      EXPECT_TRUE(has_nonzero_clut);
      // Verify mid-gray PQ RGB (0.5, 0.5, 0.5) at grid index (8, 8, 8) decodes via pqInvOetf and
      // tone-maps to ~L* 62.7 (neutral a*, b*), rather than near-white (~99.9).
      auto read_lab_at = [&](size_t r, size_t g, size_t b, float& L_out, float& a_out,
                             float& b_out) {
        const size_t entry_off = clut_data_off + ((r * 17u + g) * 17u + b) * 6u;
        uint16_t l_be = 0, a_be = 0, b_be = 0;
        memcpy(&l_be, tag + entry_off + 0, 2);
        memcpy(&a_be, tag + entry_off + 2, 2);
        memcpy(&b_be, tag + entry_off + 4, 2);
        L_out = (Endian_SwapBE16(l_be) / 65535.0f) * 100.0f;
        a_out = (Endian_SwapBE16(a_be) / 65535.0f) * 255.0f - 128.0f;
        b_out = (Endian_SwapBE16(b_be) / 65535.0f) * 255.0f - 128.0f;
      };
      float L_mid = 0.0f, a_mid = 0.0f, b_mid = 0.0f;
      read_lab_at(8, 8, 8, L_mid, a_mid, b_mid);
      EXPECT_NEAR(L_mid, 62.7f, 0.5f);
      EXPECT_NEAR(a_mid, 0.0f, 1.0f);
      EXPECT_NEAR(b_mid, 0.0f, 1.0f);

      float L_black = 0.0f, a_black = 0.0f, b_black = 0.0f;
      read_lab_at(0, 0, 0, L_black, a_black, b_black);
      EXPECT_NEAR(L_black, 0.0f, 0.5f);

      float L_white = 0.0f, a_white = 0.0f, b_white = 0.0f;
      read_lab_at(16, 16, 16, L_white, a_white, b_white);
      EXPECT_NEAR(L_white, 100.0f, 0.5f);
      // All 3 A-curves must be written.
      for (size_t c = 0; c < 3; ++c) {
        uint32_t curve_sig_be = 0;
        memcpy(&curve_sig_be, tag + a_off + c * 16, 4);
        EXPECT_EQ(Endian_SwapBE32(curve_sig_be), kTAG_ParaCurveType);
      }
    } else if (sig == kTAG_B2A0) {
      found_b2a0 = true;
      ASSERT_GE(sz, 32u + 3u * 16u);
      const uint8_t* tag = icc_bytes + off;
      uint32_t b_off_be = 0;
      memcpy(&b_off_be, tag + 12, 4);
      const size_t b_off = Endian_SwapBE32(b_off_be);
      ASSERT_LE(b_off, sz);
      ASSERT_LE(3u * 16u, sz - b_off);
      for (size_t c = 0; c < 3; ++c) {
        uint32_t curve_sig_be = 0;
        memcpy(&curve_sig_be, tag + b_off + c * 16, 4);
        EXPECT_EQ(Endian_SwapBE32(curve_sig_be), kTAG_ParaCurveType);
      }
    }
  }
  EXPECT_TRUE(found_a2b0);
  EXPECT_TRUE(found_b2a0);
}

}  // namespace ultrahdr
