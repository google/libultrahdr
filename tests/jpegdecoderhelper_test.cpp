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

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegdecoderhelper.h"
#include "ultrahdr/icc.h"
#include "ultrahdr/jpegr.h"

namespace ultrahdr {

// minnie-320x240-yuv.jpg & minnie-320x240-y.jpg has no icc or exif
// minnie-320x240-yuv-icc.jpg has icc
#ifdef __ANDROID__
#define YUV_IMAGE "/data/local/tmp/minnie-320x240-yuv.jpg"
#define RGB_IMAGE "/data/local/tmp/minnie-320x240-rgb.jpg"
#define YUV_ICC_IMAGE "/data/local/tmp/minnie-320x240-yuv-icc.jpg"
#define GREY_IMAGE "/data/local/tmp/minnie-320x240-y.jpg"
#else
#define YUV_IMAGE "minnie-320x240-yuv.jpg"
#define RGB_IMAGE "minnie-320x240-rgb.jpg"
#define YUV_ICC_IMAGE "minnie-320x240-yuv-icc.jpg"
#define GREY_IMAGE "minnie-320x240-y.jpg"
#endif
#define YUV_IMAGE_SIZE 20193
#define RGB_IMAGE_SIZE 20200
#define YUV_ICC_IMAGE_SIZE 34266
#define GREY_IMAGE_SIZE 20193
#define IMAGE_WIDTH 320
#define IMAGE_HEIGHT 240

class JpegDecoderHelperTest : public testing::Test {
 public:
  struct Image {
    std::unique_ptr<uint8_t[]> buffer;
    size_t size;
  };
  JpegDecoderHelperTest();
  ~JpegDecoderHelperTest();

 protected:
  virtual void SetUp();
  virtual void TearDown();

  Image mYuvImage, mYuvIccImage, mGreyImage, mRgbImage;
};

JpegDecoderHelperTest::JpegDecoderHelperTest() {}

JpegDecoderHelperTest::~JpegDecoderHelperTest() {}

static bool loadFile(const char filename[], JpegDecoderHelperTest::Image* result) {
  std::vector<std::string> candidates = {
      filename,
      std::string("third_party/libultrahdr/tests/data/") + filename,
      std::string("tests/data/") + filename,
      std::string("./data/") + filename,
      std::string("../tests/data/") + filename,
  };
  for (const auto& path : candidates) {
    std::ifstream ifd(path, std::ios::binary | std::ios::ate);
    if (ifd.good()) {
      int size = ifd.tellg();
      ifd.seekg(0, std::ios::beg);
      result->buffer.reset(new uint8_t[size]);
      ifd.read(reinterpret_cast<char*>(result->buffer.get()), size);
      ifd.close();
      return true;
    }
  }
  return false;
}

struct JpegSegment {
  bool found = false;
  size_t marker_offset = 0;
  size_t payload_offset = 0;
  size_t end = 0;
};

static JpegSegment findJpegSegment(const std::vector<uint8_t>& image, uint8_t marker_code,
                                   const uint8_t* payload_prefix = nullptr,
                                   size_t payload_prefix_size = 0) {
  JpegSegment result;
  size_t pos = 2;  // Skip SOI.
  while (pos + 3 < image.size()) {
    if (image[pos] != 0xff) return result;
    const size_t marker_offset = pos;
    while (pos < image.size() && image[pos] == 0xff) ++pos;
    if (pos >= image.size()) return result;
    const uint8_t code = image[pos++];
    if (code == 0xda || code == 0xd9) return result;
    if (pos + 2 > image.size()) return result;
    const size_t length = (static_cast<size_t>(image[pos]) << 8) | image[pos + 1];
    if (length < 2 || pos + length > image.size()) return result;
    const size_t payload_offset = pos + 2;
    const size_t payload_size = length - 2;
    if (code == marker_code &&
        (payload_prefix == nullptr ||
         (payload_size >= payload_prefix_size &&
          memcmp(image.data() + payload_offset, payload_prefix, payload_prefix_size) == 0))) {
      result.found = true;
      result.marker_offset = marker_offset;
      result.payload_offset = payload_offset;
      result.end = pos + length;
      return result;
    }
    pos += length;
  }
  return result;
}

static std::vector<uint8_t> makeJpegMarker(uint8_t marker_code,
                                           const std::vector<uint8_t>& payload) {
  const size_t length = payload.size() + 2;
  EXPECT_LE(length, static_cast<size_t>(std::numeric_limits<uint16_t>::max()));
  std::vector<uint8_t> marker = {0xff, marker_code, static_cast<uint8_t>(length >> 8),
                                 static_cast<uint8_t>(length)};
  marker.insert(marker.end(), payload.begin(), payload.end());
  return marker;
}

static std::vector<uint8_t> makeApp13Marker() {
  static constexpr uint8_t kPhotoshopId[] = {
      'P', 'h', 'o', 't', 'o', 's', 'h', 'o', 'p', ' ', '3', '.', '0', '\0',
  };
  // A small valid Photoshop resource block keeps this control marker meaningful to the
  // APP13 parser as well as to the marker-offset calculation.
  static constexpr uint8_t kIptcResource[] = {
      '8', 'B', 'I', 'M', 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
  };
  std::vector<uint8_t> payload(kPhotoshopId, kPhotoshopId + sizeof(kPhotoshopId));
  payload.insert(payload.end(), kIptcResource, kIptcResource + sizeof(kIptcResource));
  return makeJpegMarker(0xed, payload);
}

static std::vector<uint8_t> makeJpegWithPrefix(const std::vector<uint8_t>& source,
                                               const std::vector<uint8_t>& prefix,
                                               bool exif_first) {
  static constexpr uint8_t kExifId[] = {'E', 'x', 'i', 'f', '\0', '\0'};
  const JpegSegment exif =
      findJpegSegment(source, 0xe1, kExifId, sizeof(kExifId));
  EXPECT_TRUE(exif.found);
  if (!exif.found) return {};

  std::vector<uint8_t> result;
  result.reserve(source.size() + prefix.size());
  result.insert(result.end(), source.begin(), source.begin() + (exif_first ? 2 : exif.marker_offset));
  if (!exif_first) result.insert(result.end(), prefix.begin(), prefix.end());
  result.insert(result.end(), source.begin() + exif.marker_offset, source.begin() + exif.end);
  result.insert(result.end(), source.begin() + exif.end, source.end());
  return result;
}

static void expectExifPayloadAndOffset(const std::vector<uint8_t>& image,
                                       const std::vector<uint8_t>& expected_payload) {
  static constexpr uint8_t kExifId[] = {'E', 'x', 'i', 'f', '\0', '\0'};
  const JpegSegment exif =
      findJpegSegment(image, 0xe1, kExifId, sizeof(kExifId));
  ASSERT_TRUE(exif.found);
  ASSERT_EQ(exif.end - exif.payload_offset, expected_payload.size());

  JpegDecoderHelper decoder;
  ASSERT_EQ(decoder.decompressImage(image.data(), image.size()).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(decoder.getEXIFPos(), static_cast<long>(exif.payload_offset));
  ASSERT_EQ(decoder.getEXIFSize(), expected_payload.size());
  ASSERT_NE(decoder.getEXIFPtr(), nullptr);
  EXPECT_EQ(memcmp(decoder.getEXIFPtr(), expected_payload.data(), expected_payload.size()), 0);
}

static std::vector<std::pair<std::string, std::vector<uint8_t>>> makeProblematicPrefixes(
    const std::vector<uint8_t>& source) {
  const JpegSegment source_dqt = findJpegSegment(source, 0xdb);
  if (!source_dqt.found) return {};
  const std::vector<uint8_t> valid_dqt(source.begin() + source_dqt.marker_offset,
                                       source.begin() + source_dqt.end);
  return {
      {"COM", makeJpegMarker(0xfe, {'r', 'e', 'g', 'r', 'e', 's', 's', 'i', 'o', 'n'})},
      {"APP14", makeJpegMarker(0xee, {'A', 'd', 'o', 'b', 'e', 0x00, 0x64, 0x00, 0x00, 0x00,
                                       0x00, 0x01})},
      {"valid DQT", valid_dqt},
      {"marker fill bytes", {0xff, 0xff, 0xff}},
  };
}

void JpegDecoderHelperTest::SetUp() {
  if (!loadFile(YUV_IMAGE, &mYuvImage)) {
    FAIL() << "Load file " << YUV_IMAGE << " failed";
  }
  mYuvImage.size = YUV_IMAGE_SIZE;
  if (!loadFile(YUV_ICC_IMAGE, &mYuvIccImage)) {
    FAIL() << "Load file " << YUV_ICC_IMAGE << " failed";
  }
  mYuvIccImage.size = YUV_ICC_IMAGE_SIZE;
  if (!loadFile(GREY_IMAGE, &mGreyImage)) {
    FAIL() << "Load file " << GREY_IMAGE << " failed";
  }
  mGreyImage.size = GREY_IMAGE_SIZE;
  if (!loadFile(RGB_IMAGE, &mRgbImage)) {
    FAIL() << "Load file " << RGB_IMAGE << " failed";
  }
  mRgbImage.size = RGB_IMAGE_SIZE;
}

void JpegDecoderHelperTest::TearDown() {}

TEST_F(JpegDecoderHelperTest, decodeYuvImage) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size).error_code,
            UHDR_CODEC_OK);
  ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
  EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
            UHDR_CG_UNSPECIFIED);
}

TEST_F(JpegDecoderHelperTest, decodeYuvImageToRgba) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(
      decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size, DECODE_TO_RGB_CS).error_code,
      UHDR_CODEC_OK);
  ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
  EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
            UHDR_CG_UNSPECIFIED);
}

TEST_F(JpegDecoderHelperTest, decodeYuvIccImage) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(decoder.decompressImage(mYuvIccImage.buffer.get(), mYuvIccImage.size).error_code,
            UHDR_CODEC_OK);
  ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
  EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
            UHDR_CG_BT_709);
}

TEST_F(JpegDecoderHelperTest, decodeGreyImage) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size).error_code,
            UHDR_CODEC_OK);
  ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
  EXPECT_EQ(
      decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size, DECODE_STREAM).error_code,
      UHDR_CODEC_OK);
  ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
}

TEST_F(JpegDecoderHelperTest, decodeRgbImageToRgba) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(
      decoder.decompressImage(mRgbImage.buffer.get(), mRgbImage.size, DECODE_STREAM).error_code,
      UHDR_CODEC_OK);
  ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
  EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
            UHDR_CG_UNSPECIFIED);
}

TEST_F(JpegDecoderHelperTest, getCompressedImageParameters) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(decoder.parseImage(mYuvImage.buffer.get(), mYuvImage.size).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(IMAGE_WIDTH, decoder.getDecompressedImageWidth());
  EXPECT_EQ(IMAGE_HEIGHT, decoder.getDecompressedImageHeight());
  EXPECT_EQ(decoder.getICCSize(), 0);
  EXPECT_EQ(decoder.getEXIFSize(), 0);
}

TEST_F(JpegDecoderHelperTest, getCompressedImageParametersIcc) {
  JpegDecoderHelper decoder;
  EXPECT_EQ(decoder.parseImage(mYuvIccImage.buffer.get(), mYuvIccImage.size).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(IMAGE_WIDTH, decoder.getDecompressedImageWidth());
  EXPECT_EQ(IMAGE_HEIGHT, decoder.getDecompressedImageHeight());
  EXPECT_GT(decoder.getICCSize(), 0);
  EXPECT_GT(decoder.getEXIFSize(), 0);
  EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
            UHDR_CG_BT_709);
}

TEST_F(JpegDecoderHelperTest, exifPayloadOffsetHandlesMarkerOrderControls) {
  const std::vector<uint8_t> source(mYuvIccImage.buffer.get(),
                                    mYuvIccImage.buffer.get() + mYuvIccImage.size);
  static constexpr uint8_t kExifId[] = {'E', 'x', 'i', 'f', '\0', '\0'};
  const JpegSegment source_exif =
      findJpegSegment(source, 0xe1, kExifId, sizeof(kExifId));
  ASSERT_TRUE(source_exif.found);
  const std::vector<uint8_t> expected_payload(
      source.begin() + source_exif.payload_offset, source.begin() + source_exif.end);

  {
    SCOPED_TRACE("EXIF immediately after SOI");
    const std::vector<uint8_t> image = makeJpegWithPrefix(source, {}, true);
    expectExifPayloadAndOffset(image, expected_payload);
  }

  {
    SCOPED_TRACE("APP13 before EXIF");
    const std::vector<uint8_t> image = makeJpegWithPrefix(source, makeApp13Marker(), false);
    expectExifPayloadAndOffset(image, expected_payload);
  }
}

TEST_F(JpegDecoderHelperTest, exifPayloadOffsetCountsUnretainedJpegMarkers) {
  const std::vector<uint8_t> source(mYuvIccImage.buffer.get(),
                                    mYuvIccImage.buffer.get() + mYuvIccImage.size);
  static constexpr uint8_t kExifId[] = {'E', 'x', 'i', 'f', '\0', '\0'};
  const JpegSegment source_exif =
      findJpegSegment(source, 0xe1, kExifId, sizeof(kExifId));
  ASSERT_TRUE(source_exif.found);
  const std::vector<uint8_t> expected_payload(
      source.begin() + source_exif.payload_offset, source.begin() + source_exif.end);
  const auto prefixes = makeProblematicPrefixes(source);
  ASSERT_EQ(prefixes.size(), 4u);

  for (const auto& test_case : prefixes) {
    SCOPED_TRACE(test_case.first);
    const std::vector<uint8_t> image = makeJpegWithPrefix(source, test_case.second, false);
    expectExifPayloadAndOffset(image, expected_payload);
  }
}

TEST_F(JpegDecoderHelperTest, exifPayloadOffsetMatchesSelectedDuplicatePayload) {
  const std::vector<uint8_t> source(mYuvIccImage.buffer.get(),
                                    mYuvIccImage.buffer.get() + mYuvIccImage.size);
  const std::vector<uint8_t> duplicate_payload = {
      'E', 'x', 'i', 'f', '\0', '\0', 's', 'e', 'l', 'e', 'c', 't', 'e', 'd',
  };
  const std::vector<uint8_t> duplicate_com =
      makeJpegMarker(0xfe, {'d', 'u', 'p', 'l', 'i', 'c', 'a', 't', 'e'});
  const std::vector<uint8_t> duplicate_exif = makeJpegMarker(0xe1, duplicate_payload);
  std::vector<uint8_t> prefix = duplicate_com;
  prefix.insert(prefix.end(), duplicate_exif.begin(), duplicate_exif.end());
  const std::vector<uint8_t> image = makeJpegWithPrefix(source, prefix, false);
  ASSERT_FALSE(image.empty());

  const JpegSegment expected_exif =
      findJpegSegment(image, 0xe1, duplicate_payload.data(), duplicate_payload.size());
  ASSERT_TRUE(expected_exif.found);
  expectExifPayloadAndOffset(image, duplicate_payload);
}

TEST_F(JpegDecoderHelperTest, jpegrRecombinationPreservesExactPrimaryJpegBytes) {
  const std::vector<uint8_t> source(mYuvIccImage.buffer.get(),
                                    mYuvIccImage.buffer.get() + mYuvIccImage.size);
  static constexpr uint8_t kExifId[] = {'E', 'x', 'i', 'f', '\0', '\0'};
  static constexpr uint8_t kMpfId[] = {'M', 'P', 'F', '\0'};
  const JpegSegment source_exif =
      findJpegSegment(source, 0xe1, kExifId, sizeof(kExifId));
  ASSERT_TRUE(source_exif.found);

  const auto prefixes = makeProblematicPrefixes(source);
  ASSERT_EQ(prefixes.size(), 4u);

  for (const auto& test_case : prefixes) {
    SCOPED_TRACE(test_case.first);
    std::vector<uint8_t> base_image =
        makeJpegWithPrefix(source, test_case.second, false);
    ASSERT_FALSE(base_image.empty());
    const JpegSegment base_exif = findJpegSegment(base_image, 0xe1, kExifId, sizeof(kExifId));
    ASSERT_TRUE(base_exif.found);

    uhdr_compressed_image_t base{};
    base.data = base_image.data();
    base.data_sz = base_image.size();
    base.capacity = base_image.size();
    base.cg = UHDR_CG_BT_709;
    base.ct = UHDR_CT_SRGB;
    base.range = UHDR_CR_FULL_RANGE;

    uhdr_compressed_image_t gainmap{};
    gainmap.data = mYuvImage.buffer.get();
    gainmap.data_sz = mYuvImage.size;
    gainmap.capacity = mYuvImage.size;
    gainmap.cg = UHDR_CG_BT_709;
    gainmap.ct = UHDR_CT_SRGB;
    gainmap.range = UHDR_CR_FULL_RANGE;

    uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
    for (int i = 0; i < 3; ++i) {
      metadata.max_content_boost[i] = 2.0f;
      metadata.min_content_boost[i] = 1.0f;
      metadata.gamma[i] = 1.0f;
      metadata.offset_sdr[i] = 0.0f;
      metadata.offset_hdr[i] = 0.0f;
    }
    metadata.hdr_capacity_min = 1.0f;
    metadata.hdr_capacity_max = 2.0f;
    metadata.use_base_cg = true;

    std::vector<uint8_t> output(base_image.size() + gainmap.data_sz + 65536);
    uhdr_compressed_image_t dest{};
    dest.data = output.data();
    dest.capacity = output.size();

    JpegR jpegr;
    ASSERT_EQ(jpegr.encodeJPEGR(&base, &gainmap, &metadata, &dest).error_code, UHDR_CODEC_OK);

    const JpegSegment mpf = findJpegSegment(output, 0xe2, kMpfId, sizeof(kMpfId));
    ASSERT_TRUE(mpf.found);

    const JpegSegment output_exif = findJpegSegment(output, 0xe1, kExifId, sizeof(kExifId));
    ASSERT_TRUE(output_exif.found);
    ASSERT_EQ(output_exif.end - output_exif.payload_offset,
              source_exif.end - source_exif.payload_offset);
    EXPECT_EQ(memcmp(output.data() + output_exif.payload_offset,
                     source.data() + source_exif.payload_offset,
                     source_exif.end - source_exif.payload_offset),
              0);

    JpegDecoderHelper output_decoder;
    ASSERT_EQ(output_decoder.parseImage(output.data(), dest.data_sz).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(output_decoder.getEXIFPos(), static_cast<long>(output_exif.payload_offset));
  }
}

}  // namespace ultrahdr
