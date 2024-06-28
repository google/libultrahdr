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

}  // namespace ultrahdr
