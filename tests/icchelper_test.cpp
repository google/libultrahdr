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

#include <cstring>
#include <vector>

#include "ultrahdr/agtm.h"
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

namespace {

uint32_t readBE32IccTest(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void writeBE32IccTest(uint8_t* p, uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFFu);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFFu);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFFu);
  p[3] = static_cast<uint8_t>(v & 0xFFu);
}

size_t countTagOccurrences(const uint8_t* prof, size_t prof_len, uint32_t target_sig) {
  if (prof_len < sizeof(ICCHeader)) return 0;
  const size_t tag_cnt = readBE32IccTest(prof + offsetof(ICCHeader, tag_count));
  if (sizeof(ICCHeader) + tag_cnt * kICCTagTableEntrySize > prof_len) return 0;
  size_t count = 0;
  for (size_t i = 0; i < tag_cnt; ++i) {
    const uint8_t* e = prof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    if (readBE32IccTest(e) == target_sig) ++count;
  }
  return count;
}

bool findTagEntry(const uint8_t* prof, size_t prof_len, uint32_t target_sig, uint32_t& out_off,
                  uint32_t& out_sz) {
  if (prof_len < sizeof(ICCHeader)) return false;
  const size_t tag_cnt = readBE32IccTest(prof + offsetof(ICCHeader, tag_count));
  if (sizeof(ICCHeader) + tag_cnt * kICCTagTableEntrySize > prof_len) return false;
  for (size_t i = 0; i < tag_cnt; ++i) {
    const uint8_t* e = prof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    if (readBE32IccTest(e) == target_sig) {
      out_off = readBE32IccTest(e + 4);
      out_sz = readBE32IccTest(e + 8);
      return true;
    }
  }
  return false;
}

}  // namespace

TEST_F(IccHelperTest, WriteIccProfileDefaultIsBitIdentical) {
  const uhdr_color_gamut_t gamuts[] = {UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100};
  const uhdr_color_transfer_t transfers[] = {UHDR_CT_SRGB, UHDR_CT_HLG, UHDR_CT_PQ,
                                             UHDR_CT_LINEAR};
  for (uhdr_color_gamut_t cg : gamuts) {
    for (uhdr_color_transfer_t tf : transfers) {
      auto def_icc = IccHelper::writeIccProfile(tf, cg);
      auto null_icc = IccHelper::writeIccProfile(tf, cg, nullptr, 0);
      ASSERT_NE(def_icc, nullptr);
      ASSERT_NE(null_icc, nullptr);
      ASSERT_EQ(def_icc->getLength(), null_icc->getLength());
      EXPECT_EQ(std::memcmp(def_icc->getData(), null_icc->getData(), def_icc->getLength()), 0);

      std::vector<uint8_t> hagc_out;
      EXPECT_FALSE(IccHelper::readIccHagc(def_icc->getData(), def_icc->getLength(), hagc_out));

      const uint8_t* prof =
          static_cast<const uint8_t*>(def_icc->getData()) + kICCIdentifierSize;
      if (tf == UHDR_CT_SRGB) {
        EXPECT_EQ(readBE32IccTest(prof + offsetof(ICCHeader, version)), 0x04300000u);
      }
    }
  }
}

TEST_F(IccHelperTest, WriteIccProfileWithHagcMatchesSkiaLayout) {
  smpte2094_50::DynamicMetadata rwtm;
  rwtm.baseline_hdr_headroom_log2 = 0.0f;
  smpte2094_50::populateUsingRwtm(rwtm);
  std::vector<uint8_t> rwtm_bytes;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(rwtm, rwtm_bytes).error_code, UHDR_CODEC_OK);

  std::vector<std::vector<uint8_t>> payloads = {
      rwtm_bytes,
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
       0x0F},
      {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
       0x1F, 0x20},
      {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
       0x30, 0x31, 0x32},
      {0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
       0x42, 0x43, 0x44, 0x45},
  };

  const uhdr_color_gamut_t gamuts[] = {UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100};
  for (uhdr_color_gamut_t cg : gamuts) {
    for (size_t idx = 0; idx < payloads.size(); ++idx) {
      const auto& payload = payloads[idx];
      auto icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, cg, payload.data(), payload.size());
      ASSERT_NE(icc, nullptr);
      ASSERT_GT(icc->getLength(), kICCIdentifierSize + sizeof(ICCHeader));

      const uint8_t* raw_bytes = static_cast<const uint8_t*>(icc->getData());
      const uint8_t* prof = raw_bytes + kICCIdentifierSize;
      const size_t prof_len = icc->getLength() - kICCIdentifierSize;

      // Must upgrade header version to ICC v4.4 and never emit legacy 'ADGC'.
      EXPECT_EQ(readBE32IccTest(prof + offsetof(ICCHeader, version)), 0x04400000u);
      EXPECT_EQ(countTagOccurrences(prof, prof_len, SetFourByteTag('A', 'D', 'G', 'C')), 0u);
      EXPECT_EQ(countTagOccurrences(prof, prof_len, kTAG_HAGC), 1u);

      uint32_t hagc_off = 0, hagc_sz = 0;
      ASSERT_TRUE(findTagEntry(prof, prof_len, kTAG_HAGC, hagc_off, hagc_sz));
      EXPECT_EQ(hagc_off % 4u, 0u);
      const size_t expected_tag_sz = ALIGNM(kHagcTagHeaderSize + payload.size(), 4);
      ASSERT_EQ(hagc_sz, expected_tag_sz);
      ASSERT_LE(hagc_off + hagc_sz, prof_len);

      // Verify Skia HAGC_Layout: [type='hagc'(4), reserved=0(4), size=BE32(4), payload, zero-pad].
      const uint8_t* tag_ptr = prof + hagc_off;
      EXPECT_EQ(readBE32IccTest(tag_ptr), kTAG_HAGCType);
      EXPECT_EQ(readBE32IccTest(tag_ptr + 4), 0u);
      EXPECT_EQ(readBE32IccTest(tag_ptr + 8), static_cast<uint32_t>(payload.size()));
      EXPECT_EQ(std::memcmp(tag_ptr + kHagcTagHeaderSize, payload.data(), payload.size()), 0);
      for (size_t pad = kHagcTagHeaderSize + payload.size(); pad < hagc_sz; ++pad) {
        EXPECT_EQ(tag_ptr[pad], 0u);
      }

      EXPECT_EQ(IccHelper::readIccColorGamut(icc->getData(), icc->getLength()), cg);

      std::vector<uint8_t> extracted_app2, extracted_raw;
      ASSERT_TRUE(IccHelper::readIccHagc(icc->getData(), icc->getLength(), extracted_app2));
      ASSERT_TRUE(IccHelper::readIccHagc(prof, prof_len, extracted_raw));
      EXPECT_EQ(extracted_app2, payload);
      EXPECT_EQ(extracted_raw, payload);

      if (idx == 0) {
        smpte2094_50::DynamicMetadata parsed;
        ASSERT_EQ(
            smpte2094_50::parseSt2094_50(extracted_app2.data(), extracted_app2.size(), parsed)
                .error_code,
            UHDR_CODEC_OK);
        EXPECT_EQ(smpte2094_50::validateDynamicMetadata(parsed).error_code, UHDR_CODEC_OK);
      }
    }
  }
}

TEST_F(IccHelperTest, InjectHagcPreservesCustomAndSharedTagsAndReplacesExisting) {
  auto base_icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3);
  ASSERT_NE(base_icc, nullptr);

  // Build a synthetic ICC profile (with APP2 identifier) featuring:
  // 1) shared TRC offsets (gTRC & bTRC aliased to rTRC),
  // 2) non-zero MD5 profile_id, and
  // 3) an unaligned 7-byte custom vendor tag ('cust').
  std::vector<uint8_t> src(static_cast<const uint8_t*>(base_icc->getData()),
                           static_cast<const uint8_t*>(base_icc->getData()) + base_icc->getLength());
  uint8_t* prof = src.data() + kICCIdentifierSize;
  const size_t old_prof_len = src.size() - kICCIdentifierSize;
  std::memset(prof + offsetof(ICCHeader, profile_id), 0xAA, sizeof(ICCHeader::profile_id));

  uint32_t rtrc_off = 0, rtrc_sz = 0;
  ASSERT_TRUE(findTagEntry(prof, old_prof_len, kTAG_rTRC, rtrc_off, rtrc_sz));
  const size_t old_tag_cnt = readBE32IccTest(prof + offsetof(ICCHeader, tag_count));
  for (size_t i = 0; i < old_tag_cnt; ++i) {
    uint8_t* e = prof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    const uint32_t sig = readBE32IccTest(e);
    if (sig == kTAG_gTRC || sig == kTAG_bTRC) {
      writeBE32IccTest(e + 4, rtrc_off);
      writeBE32IccTest(e + 8, rtrc_sz);
    }
  }

  // Append custom 7-byte 'cust' tag entry to src.
  const std::vector<uint8_t> kVendorPayload = {'v', 'e', 'n', 'd', 0x11, 0x22, 0x33};
  const size_t new_tag_cnt = old_tag_cnt + 1;
  const size_t old_table_end = sizeof(ICCHeader) + old_tag_cnt * kICCTagTableEntrySize;
  const size_t delta = kICCTagTableEntrySize;
  const size_t cust_off = ALIGNM(old_prof_len + delta, 4);
  const size_t custom_prof_len = ALIGNM(cust_off + kVendorPayload.size(), 4);
  std::vector<uint8_t> custom_app2(kICCIdentifierSize + custom_prof_len, 0);
  std::memcpy(custom_app2.data(), src.data(), kICCIdentifierSize + sizeof(ICCHeader));
  uint8_t* cprof = custom_app2.data() + kICCIdentifierSize;
  writeBE32IccTest(cprof + offsetof(ICCHeader, size), static_cast<uint32_t>(custom_prof_len));
  writeBE32IccTest(cprof + offsetof(ICCHeader, tag_count), static_cast<uint32_t>(new_tag_cnt));
  for (size_t i = 0; i < old_tag_cnt; ++i) {
    const uint8_t* oe = prof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    uint8_t* ne = cprof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    writeBE32IccTest(ne, readBE32IccTest(oe));
    writeBE32IccTest(ne + 4, readBE32IccTest(oe + 4) + static_cast<uint32_t>(delta));
    writeBE32IccTest(ne + 8, readBE32IccTest(oe + 8));
  }
  uint8_t* cust_e = cprof + sizeof(ICCHeader) + old_tag_cnt * kICCTagTableEntrySize;
  writeBE32IccTest(cust_e, SetFourByteTag('c', 'u', 's', 't'));
  writeBE32IccTest(cust_e + 4, static_cast<uint32_t>(cust_off));
  writeBE32IccTest(cust_e + 8, static_cast<uint32_t>(kVendorPayload.size()));
  std::memcpy(cprof + old_table_end + delta, prof + old_table_end, old_prof_len - old_table_end);
  std::memcpy(cprof + cust_off, kVendorPayload.data(), kVendorPayload.size());

  const std::vector<uint8_t> hagc_v1 = {0x00, 0x05, 0x10, 0x20, 0x30};
  auto injected_v1 = IccHelper::injectHagcIntoIccProfile(custom_app2.data(), custom_app2.size(),
                                                         hagc_v1.data(), hagc_v1.size());
  ASSERT_NE(injected_v1, nullptr);
  ASSERT_GT(injected_v1->getLength(), kICCIdentifierSize + sizeof(ICCHeader));
  EXPECT_EQ(IccHelper::readIccColorGamut(injected_v1->getData(), injected_v1->getLength()),
            UHDR_CG_DISPLAY_P3);

  const uint8_t* p1 = static_cast<const uint8_t*>(injected_v1->getData()) + kICCIdentifierSize;
  const size_t p1_len = injected_v1->getLength() - kICCIdentifierSize;
  EXPECT_EQ(readBE32IccTest(p1 + offsetof(ICCHeader, version)), 0x04400000u);
  for (size_t i = 0; i < sizeof(ICCHeader::profile_id); ++i) {
    EXPECT_EQ(p1[offsetof(ICCHeader, profile_id) + i], 0u);
  }

  // Shared TRC tags must remain aliased to a single shared offset rather than duplicated.
  uint32_t r1_off = 0, r1_sz = 0, g1_off = 0, g1_sz = 0, b1_off = 0, b1_sz = 0;
  ASSERT_TRUE(findTagEntry(p1, p1_len, kTAG_rTRC, r1_off, r1_sz));
  ASSERT_TRUE(findTagEntry(p1, p1_len, kTAG_gTRC, g1_off, g1_sz));
  ASSERT_TRUE(findTagEntry(p1, p1_len, kTAG_bTRC, b1_off, b1_sz));
  EXPECT_EQ(r1_off, g1_off);
  EXPECT_EQ(r1_off, b1_off);
  EXPECT_EQ(r1_sz, g1_sz);

  // Odd-sized custom 'cust' tag preserved and subsequent 'HAGC' tag remains 4-byte aligned.
  uint32_t c1_off = 0, c1_sz = 0, h1_off = 0, h1_sz = 0;
  ASSERT_TRUE(findTagEntry(p1, p1_len, SetFourByteTag('c', 'u', 's', 't'), c1_off, c1_sz));
  ASSERT_EQ(c1_sz, kVendorPayload.size());
  EXPECT_EQ(std::memcmp(p1 + c1_off, kVendorPayload.data(), kVendorPayload.size()), 0);
  ASSERT_TRUE(findTagEntry(p1, p1_len, kTAG_HAGC, h1_off, h1_sz));
  EXPECT_EQ(h1_off % 4u, 0u);

  std::vector<uint8_t> read_v1;
  ASSERT_TRUE(IccHelper::readIccHagc(injected_v1->getData(), injected_v1->getLength(), read_v1));
  EXPECT_EQ(read_v1, hagc_v1);

  // Second injection on raw (non-APP2) framing replaces existing 'HAGC' without duplicating it.
  const std::vector<uint8_t> hagc_v2 = {0x00, 0x09, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11};
  auto injected_v2_raw =
      IccHelper::injectHagcIntoIccProfile(p1, p1_len, hagc_v2.data(), hagc_v2.size());
  ASSERT_NE(injected_v2_raw, nullptr);
  const uint8_t* p2 = static_cast<const uint8_t*>(injected_v2_raw->getData());
  const size_t p2_len = injected_v2_raw->getLength();
  EXPECT_NE(std::memcmp(p2, kICCIdentifier, sizeof(kICCIdentifier)), 0);
  EXPECT_EQ(countTagOccurrences(p2, p2_len, kTAG_HAGC), 1u);

  std::vector<uint8_t> read_v2;
  ASSERT_TRUE(IccHelper::readIccHagc(p2, p2_len, read_v2));
  EXPECT_EQ(read_v2, hagc_v2);
}

TEST_F(IccHelperTest, RejectsMalformedHagcProfiles) {
  const std::vector<uint8_t> kSampleHagc = {0x00, 0x01, 0x02, 0x03};
  std::vector<uint8_t> out;

  EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(nullptr, 0, kSampleHagc.data(), kSampleHagc.size()),
            nullptr);
  EXPECT_FALSE(IccHelper::readIccHagc(nullptr, 0, out));

  auto valid = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709, kSampleHagc.data(),
                                          kSampleHagc.size());
  ASSERT_NE(valid, nullptr);
  EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(valid->getData(), valid->getLength(), nullptr, 4),
            nullptr);
  EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(valid->getData(), valid->getLength(),
                                                kSampleHagc.data(), 0),
            nullptr);
  EXPECT_FALSE(IccHelper::readIccHagc(valid->getData(), 32, out));

  const uint8_t* valid_bytes = static_cast<const uint8_t*>(valid->getData());
  const size_t valid_len = valid->getLength();

  // Multi-chunk APP2 ICC profile (chunk_count > 1) must be rejected before unreassembled parsing.
  {
    std::vector<uint8_t> bad(valid_bytes, valid_bytes + valid_len);
    bad[13] = 2;
    EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(bad.data(), bad.size(), kSampleHagc.data(),
                                                  kSampleHagc.size()),
              nullptr);
    EXPECT_FALSE(IccHelper::readIccHagc(bad.data(), bad.size(), out));
  }

  // Corrupted 'acsp' signature.
  {
    std::vector<uint8_t> bad(valid_bytes, valid_bytes + valid_len);
    bad[kICCIdentifierSize + offsetof(ICCHeader, signature)] ^= 0xFFu;
    EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(bad.data(), bad.size(), kSampleHagc.data(),
                                                  kSampleHagc.size()),
              nullptr);
    EXPECT_FALSE(IccHelper::readIccHagc(bad.data(), bad.size(), out));
  }

  // Declared header size exceeds buffer size.
  {
    std::vector<uint8_t> bad(valid_bytes, valid_bytes + valid_len);
    writeBE32IccTest(bad.data() + kICCIdentifierSize, static_cast<uint32_t>(valid_len + 64));
    EXPECT_EQ(IccHelper::injectHagcIntoIccProfile(bad.data(), bad.size(), kSampleHagc.data(),
                                                  kSampleHagc.size()),
              nullptr);
    EXPECT_FALSE(IccHelper::readIccHagc(bad.data(), bad.size(), out));
  }

  // Mutate 'HAGC' tag type ('adgc'), non-zero reserved field, and overflowing payload length.
  uint32_t hagc_off = 0, hagc_sz = 0;
  ASSERT_TRUE(findTagEntry(valid_bytes + kICCIdentifierSize, valid_len - kICCIdentifierSize,
                           kTAG_HAGC, hagc_off, hagc_sz));
  {
    std::vector<uint8_t> bad(valid_bytes, valid_bytes + valid_len);
    writeBE32IccTest(bad.data() + kICCIdentifierSize + hagc_off,
                     SetFourByteTag('a', 'd', 'g', 'c'));
    EXPECT_FALSE(IccHelper::readIccHagc(bad.data(), bad.size(), out));
  }
  {
    std::vector<uint8_t> bad(valid_bytes, valid_bytes + valid_len);
    writeBE32IccTest(bad.data() + kICCIdentifierSize + hagc_off + 4, 1u);
    EXPECT_FALSE(IccHelper::readIccHagc(bad.data(), bad.size(), out));
  }
  {
    std::vector<uint8_t> bad(valid_bytes, valid_bytes + valid_len);
    writeBE32IccTest(bad.data() + kICCIdentifierSize + hagc_off + 8, hagc_sz);
    EXPECT_FALSE(IccHelper::readIccHagc(bad.data(), bad.size(), out));
  }

  // Duplicate 'HAGC' tag entries and out-of-bounds sibling tag entries must fail closed.
  {
    std::vector<uint8_t> dup(valid_bytes, valid_bytes + valid_len);
    uint8_t* prof = dup.data() + kICCIdentifierSize;
    const uint32_t tc = readBE32IccTest(prof + offsetof(ICCHeader, tag_count));
    ASSERT_GE(tc, 2u);
    for (uint32_t i = 0; i < tc; ++i) {
      uint8_t* entry = prof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      if (readBE32IccTest(entry) != kTAG_HAGC) {
        writeBE32IccTest(entry, kTAG_HAGC);
        writeBE32IccTest(entry + 4, hagc_off);
        writeBE32IccTest(entry + 8, hagc_sz);
        break;
      }
    }
    EXPECT_FALSE(IccHelper::readIccHagc(dup.data(), dup.size(), out));
  }
  {
    std::vector<uint8_t> corrupt_sibling(valid_bytes, valid_bytes + valid_len);
    uint8_t* prof = corrupt_sibling.data() + kICCIdentifierSize;
    const uint32_t tc = readBE32IccTest(prof + offsetof(ICCHeader, tag_count));
    for (uint32_t i = 0; i < tc; ++i) {
      uint8_t* entry = prof + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      if (readBE32IccTest(entry) != kTAG_HAGC) {
        writeBE32IccTest(entry + 4, static_cast<uint32_t>(valid_len + 16));
        break;
      }
    }
    EXPECT_FALSE(IccHelper::readIccHagc(corrupt_sibling.data(), corrupt_sibling.size(), out));
  }
}

TEST_F(IccHelperTest, ReadIccColorTransferParsesCicpAndDefaultsUnspecified) {
  auto srgb = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
  auto lin = IccHelper::writeIccProfile(UHDR_CT_LINEAR, UHDR_CG_BT_2100);
  auto pq = IccHelper::writeIccProfile(UHDR_CT_PQ, UHDR_CG_BT_2100);
  auto hlg = IccHelper::writeIccProfile(UHDR_CT_HLG, UHDR_CG_DISPLAY_P3);
  ASSERT_NE(srgb, nullptr);
  ASSERT_NE(lin, nullptr);
  ASSERT_NE(pq, nullptr);
  ASSERT_NE(hlg, nullptr);

  // sRGB profile generated by writeIccProfile uses parametric TRC without CICP -> UNSPECIFIED.
  EXPECT_EQ(readIccColorTransfer(srgb->getData(), srgb->getLength()), UHDR_CT_UNSPECIFIED);
  EXPECT_EQ(readIccColorTransfer(lin->getData(), lin->getLength()), UHDR_CT_LINEAR);
  EXPECT_EQ(readIccColorTransfer(pq->getData(), pq->getLength()), UHDR_CT_PQ);
  EXPECT_EQ(readIccColorTransfer(hlg->getData(), hlg->getLength()), UHDR_CT_HLG);

  // Raw ICC (without 14-byte APP2 identifier) also resolves CICP transfer.
  EXPECT_EQ(readIccColorTransfer(static_cast<const uint8_t*>(pq->getData()) + kICCIdentifierSize,
                                 pq->getLength() - kICCIdentifierSize),
            UHDR_CT_PQ);
  EXPECT_EQ(readIccColorTransfer(nullptr, 0), UHDR_CT_UNSPECIFIED);
}

TEST_F(IccHelperTest, WriteRawIccProfileMatchesStrippedApp2BitForBit) {
  smpte2094_50::DynamicMetadata rwtm{};
  rwtm.baseline_hdr_headroom_log2 = 1.5f;
  smpte2094_50::populateUsingRwtm(rwtm);
  std::vector<uint8_t> hagc_bytes;
  ASSERT_EQ(smpte2094_50::encodeSt2094_50(rwtm, hagc_bytes).error_code, UHDR_CODEC_OK);

  const uhdr_color_gamut_t gamuts[] = {UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100};
  const uhdr_color_transfer_t transfers[] = {UHDR_CT_SRGB, UHDR_CT_LINEAR, UHDR_CT_HLG, UHDR_CT_PQ};

  for (uhdr_color_gamut_t cg : gamuts) {
    for (uhdr_color_transfer_t tf : transfers) {
      for (bool with_hagc : {false, true}) {
        const void* h_ptr = with_hagc ? hagc_bytes.data() : nullptr;
        const size_t h_sz = with_hagc ? hagc_bytes.size() : 0;

        auto app2_icc = IccHelper::writeIccProfile(tf, cg, h_ptr, h_sz);
        auto raw_icc = IccHelper::writeRawIccProfile(tf, cg, h_ptr, h_sz);
        ASSERT_NE(app2_icc, nullptr);
        ASSERT_NE(raw_icc, nullptr);
        ASSERT_EQ(app2_icc->getLength(), raw_icc->getLength() + kICCIdentifierSize);

        const uint8_t* raw_ptr = static_cast<const uint8_t*>(raw_icc->getData());
        const size_t raw_len = raw_icc->getLength();
        ASSERT_GE(raw_len, sizeof(ICCHeader));
        EXPECT_NE(std::memcmp(raw_ptr, kICCIdentifier, sizeof(kICCIdentifier)), 0);
        EXPECT_EQ(readBE32IccTest(raw_ptr), static_cast<uint32_t>(raw_len));
        EXPECT_EQ(readBE32IccTest(raw_ptr + offsetof(ICCHeader, signature)), kACSP_Signature);
        EXPECT_EQ(std::memcmp(raw_ptr,
                              static_cast<const uint8_t*>(app2_icc->getData()) + kICCIdentifierSize,
                              raw_len),
                  0);

        EXPECT_EQ(IccHelper::readIccColorGamut(raw_icc->getData(), raw_len), cg);
        std::vector<uint8_t> extracted;
        if (with_hagc) {
          EXPECT_EQ(readBE32IccTest(raw_ptr + offsetof(ICCHeader, version)), 0x04400000u);
          ASSERT_TRUE(IccHelper::readIccHagc(raw_ptr, raw_len, extracted));
          EXPECT_EQ(extracted, hagc_bytes);
        } else {
          EXPECT_FALSE(IccHelper::readIccHagc(raw_ptr, raw_len, extracted));
        }
      }
    }
  }

  // Invalid enums and mismatched pointer/size pairs must fail closed with nullptr.
  EXPECT_EQ(IccHelper::writeRawIccProfile(UHDR_CT_UNSPECIFIED, UHDR_CG_BT_709), nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(static_cast<uhdr_color_transfer_t>(-2), UHDR_CG_BT_709),
            nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(static_cast<uhdr_color_transfer_t>(999), UHDR_CG_BT_709),
            nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_UNSPECIFIED), nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(UHDR_CT_SRGB, static_cast<uhdr_color_gamut_t>(-2)),
            nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(UHDR_CT_SRGB, static_cast<uhdr_color_gamut_t>(999)),
            nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709, nullptr, 4), nullptr);
  EXPECT_EQ(IccHelper::writeRawIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709, hagc_bytes.data(), 0),
            nullptr);
  EXPECT_EQ(IccHelper::writeIccProfile(static_cast<uhdr_color_transfer_t>(-2), UHDR_CG_BT_709),
            nullptr);
  EXPECT_EQ(IccHelper::writeIccProfile(static_cast<uhdr_color_transfer_t>(999), UHDR_CG_BT_709),
            nullptr);
}

TEST_F(IccHelperTest, ReadIccColorGamutHandlesUnalignedBuffersAndTagOffsets) {
  for (uhdr_color_gamut_t cg : {UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100}) {
    auto raw_icc = IccHelper::writeRawIccProfile(UHDR_CT_SRGB, cg);
    ASSERT_NE(raw_icc, nullptr);
    const uint8_t* src = static_cast<const uint8_t*>(raw_icc->getData());
    const size_t len = raw_icc->getLength();

    // 1. Unaligned base buffer address (+1, +2, +3 byte offsets).
    for (size_t misalign = 1; misalign <= 3; ++misalign) {
      std::vector<uint8_t> shifted(misalign + len, 0u);
      std::memcpy(shifted.data() + misalign, src, len);
      EXPECT_EQ(IccHelper::readIccColorGamut(shifted.data() + misalign, len), cg);
    }

    // 2. Non-4-byte-aligned rXYZ/gXYZ/bXYZ tag offsets inside the profile itself.
    std::vector<uint8_t> odd_tags(len + 3u, 0u);
    std::memcpy(odd_tags.data(), src, sizeof(ICCHeader));
    const size_t new_size = odd_tags.size();
    writeBE32IccTest(odd_tags.data() + offsetof(ICCHeader, size), static_cast<uint32_t>(new_size));
    const uint32_t tc = readBE32IccTest(src + offsetof(ICCHeader, tag_count));
    const size_t table_end = sizeof(ICCHeader) + tc * kICCTagTableEntrySize;
    std::memcpy(odd_tags.data() + table_end + 1u, src + table_end, len - table_end);
    for (uint32_t i = 0; i < tc; ++i) {
      const uint8_t* oe = src + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      uint8_t* ne = odd_tags.data() + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      writeBE32IccTest(ne, readBE32IccTest(oe));
      writeBE32IccTest(ne + 4, readBE32IccTest(oe + 4) + 1u);
      writeBE32IccTest(ne + 8, readBE32IccTest(oe + 8));
    }
    EXPECT_EQ(IccHelper::readIccColorGamut(odd_tags.data(), odd_tags.size()), cg);
  }
}

}  // namespace ultrahdr
