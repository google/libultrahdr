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

TEST_F(IccHelperTest, iccUnalignedColorantOffset) {
  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  ASSERT_NE(icc->getLength(), 0);
  ASSERT_NE(icc->getData(), nullptr);

  // Shift rXYZ tag offset by +1 byte (unaligned, still in-bounds) and verify alignment-safe read.
  std::vector<uint8_t> buffer(reinterpret_cast<uint8_t*>(icc->getData()),
                              reinterpret_cast<uint8_t*>(icc->getData()) + icc->getLength());
  buffer.push_back(0);
  uint8_t* icc_bytes = buffer.data() + kICCIdentifierSize;
  uint32_t tag_count_be;
  memcpy(&tag_count_be, icc_bytes + offsetof(ICCHeader, tag_count), sizeof(tag_count_be));
  size_t tag_count = Endian_SwapBE32(tag_count_be);
  for (size_t tag_idx = 0; tag_idx < tag_count; ++tag_idx) {
    size_t entry_offset = sizeof(ICCHeader) + tag_idx * 12;
    uint32_t sig_be, off_be;
    memcpy(&sig_be, icc_bytes + entry_offset, sizeof(sig_be));
    if (sig_be == Endian_SwapBE32(kTAG_rXYZ)) {
      memcpy(&off_be, icc_bytes + entry_offset + 4, sizeof(off_be));
      uint32_t unaligned_be = Endian_SwapBE32(Endian_SwapBE32(off_be) + 1);
      memcpy(icc_bytes + entry_offset + 4, &unaligned_be, sizeof(unaligned_be));
      break;
    }
  }
  EXPECT_EQ(IccHelper::readIccColorGamut(buffer.data(), buffer.size()), UHDR_CG_UNSPECIFIED);

  // Also verify unaligned input buffer (+1 byte) parses cleanly without UB.
  std::vector<uint8_t> shifted(icc->getLength() + 1, 0);
  memcpy(shifted.data() + 1, icc->getData(), icc->getLength());
  EXPECT_EQ(IccHelper::readIccColorGamut(shifted.data() + 1, icc->getLength()), UHDR_CG_BT_709);

  // Also verify unaligned cicp tag offset on an HLG profile parses cleanly without UB.
  std::shared_ptr<DataStruct> hlg = IccHelper::writeIccProfile(UHDR_CT_HLG, UHDR_CG_BT_2100);
  ASSERT_NE(hlg->getLength(), 0);
  ASSERT_NE(hlg->getData(), nullptr);
  std::vector<uint8_t> hlg_buf(reinterpret_cast<uint8_t*>(hlg->getData()),
                               reinterpret_cast<uint8_t*>(hlg->getData()) + hlg->getLength());
  hlg_buf.push_back(0);
  uint8_t* hlg_bytes = hlg_buf.data() + kICCIdentifierSize;
  memcpy(&tag_count_be, hlg_bytes + offsetof(ICCHeader, tag_count), sizeof(tag_count_be));
  tag_count = Endian_SwapBE32(tag_count_be);
  for (size_t tag_idx = 0; tag_idx < tag_count; ++tag_idx) {
    size_t entry_offset = sizeof(ICCHeader) + tag_idx * 12;
    uint32_t sig_be, off_be;
    memcpy(&sig_be, hlg_bytes + entry_offset, sizeof(sig_be));
    if (sig_be == Endian_SwapBE32(kTAG_cicp)) {
      memcpy(&off_be, hlg_bytes + entry_offset + 4, sizeof(off_be));
      uint32_t unaligned_be = Endian_SwapBE32(Endian_SwapBE32(off_be) + 1);
      memcpy(hlg_bytes + entry_offset + 4, &unaligned_be, sizeof(unaligned_be));
      break;
    }
  }
  EXPECT_EQ(IccHelper::readIccColorGamut(hlg_buf.data(), hlg_buf.size()), UHDR_CG_BT_2100);
}

}  // namespace ultrahdr
