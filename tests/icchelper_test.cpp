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

}  // namespace ultrahdr
