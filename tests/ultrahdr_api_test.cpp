#if defined(__has_include)
#if __has_include("testing/base/public/gunit.h")
#include "testing/base/public/gunit.h"
#else
#include <gtest/gtest.h>
#endif
#else
#include <gtest/gtest.h>
#endif
#include <algorithm>
#include <fstream>
#include <cstring>
#include <limits>
#include <vector>
#include <memory>
#include <vector>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/heifultrahdr.h"
#include "ultrahdr/avifultrahdr.h"
#if defined(UHDR_ENABLE_HEIF)
#include "libheif/heif.h"
#endif

namespace ultrahdr {

static const char* kYCbCrP010FileName = "raw_p010_image.p010";
static const char* kYCbCr420FileName = "raw_yuv420_image.yuv420";
static const char* kSdrJpgFileName = "jpeg_image.jpg";
static const char* kHevcGainmapFileName = "gainmap_hevc_16x16.heic";
static const size_t kImageWidth = 1280;
static const size_t kImageHeight = 720;

static bool loadFile(const char* filename, std::vector<uint8_t>& buffer) {
  std::vector<std::string> candidates = {
      filename,
      std::string("third_party/libultrahdr/tests/data/") + filename,
      std::string("tests/data/") + filename,
      std::string("./data/") + filename,
      std::string("data/") + filename,
      std::string("../tests/data/") + filename,
  };
  for (const auto& path : candidates) {
    std::ifstream stream(path, std::ios::binary);
    if (stream.is_open()) {
      stream.seekg(0, std::ios::end);
      size_t size = stream.tellg();
      stream.seekg(0, std::ios::beg);
      buffer.resize(size);
      stream.read(reinterpret_cast<char*>(buffer.data()), size);
      if (stream.good()) return true;
    }
  }
  return false;
}

static bool readMpfU16ForTest(const std::vector<uint8_t>& data, size_t offset, bool big_endian,
                              uint16_t* value) {
  if (offset > data.size() || data.size() - offset < 2) return false;
  *value = big_endian ? static_cast<uint16_t>((data[offset] << 8) | data[offset + 1])
                      : static_cast<uint16_t>(data[offset] | (data[offset + 1] << 8));
  return true;
}

static bool readMpfU32ForTest(const std::vector<uint8_t>& data, size_t offset, bool big_endian,
                              uint32_t* value) {
  if (offset > data.size() || data.size() - offset < 4) return false;
  if (big_endian) {
    *value = (static_cast<uint32_t>(data[offset]) << 24) |
             (static_cast<uint32_t>(data[offset + 1]) << 16) |
             (static_cast<uint32_t>(data[offset + 2]) << 8) | data[offset + 3];
  } else {
    *value = data[offset] | (static_cast<uint32_t>(data[offset + 1]) << 8) |
             (static_cast<uint32_t>(data[offset + 2]) << 16) |
             (static_cast<uint32_t>(data[offset + 3]) << 24);
  }
  return true;
}

static void writeMpfU16ForTest(std::vector<uint8_t>& data, size_t offset, bool big_endian,
                               uint16_t value) {
  data[offset] = static_cast<uint8_t>(value >> (big_endian ? 8 : 0));
  data[offset + 1] = static_cast<uint8_t>(value >> (big_endian ? 0 : 8));
}

static void writeMpfU32ForTest(std::vector<uint8_t>& data, size_t offset, bool big_endian,
                               uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    const int shift = big_endian ? 24 - 8 * i : 8 * i;
    data[offset + i] = static_cast<uint8_t>(value >> shift);
  }
}

struct MpfEntryLocations {
  bool big_endian;
  size_t signature;
  size_t ifd;
  size_t number_of_images_tag;
  size_t mp_entry_tag;
  size_t mp_entry_value;
  size_t version_id;
  size_t version_type;
  size_t version_count;
  size_t version_value;
  size_t count;
  size_t primary_attributes;
  size_t primary_offset;
  size_t secondary_attributes;
  size_t secondary_offset;
};

static bool findMpfEntryLocations(const std::vector<uint8_t>& data, MpfEntryLocations* locations) {
  const uint8_t signature[] = {'M', 'P', 'F', 0};
  const auto found =
      std::search(data.begin(), data.end(), std::begin(signature), std::end(signature));
  if (found == data.end()) return false;
  const size_t signature_offset = static_cast<size_t>(found - data.begin());
  const size_t tiff = signature_offset + sizeof signature;
  if (tiff > data.size() || data.size() - tiff < 8) return false;
  const bool big_endian = data[tiff] == 'M' && data[tiff + 1] == 'M';
  if (!big_endian && !(data[tiff] == 'I' && data[tiff + 1] == 'I')) return false;

  uint32_t ifd_relative_offset = 0;
  if (!readMpfU32ForTest(data, tiff + 4, big_endian, &ifd_relative_offset) ||
      ifd_relative_offset > data.size() - tiff) {
    return false;
  }
  const size_t ifd = tiff + ifd_relative_offset;
  uint16_t tag_count = 0;
  if (!readMpfU16ForTest(data, ifd, big_endian, &tag_count)) return false;
  bool found_version = false;
  bool found_number_of_images = false;
  bool found_entries = false;
  locations->big_endian = big_endian;
  locations->signature = signature_offset;
  locations->ifd = ifd;
  for (uint16_t i = 0; i < tag_count; ++i) {
    const size_t tag = ifd + 2 + 12 * i;
    uint16_t id = 0;
    uint32_t entries_offset = 0;
    if (!readMpfU16ForTest(data, tag, big_endian, &id) ||
        !readMpfU32ForTest(data, tag + 8, big_endian, &entries_offset)) {
      return false;
    }
    if (id == 0xb000) {
      locations->version_id = tag;
      locations->version_type = tag + 2;
      locations->version_count = tag + 4;
      locations->version_value = tag + 8;
      found_version = true;
      continue;
    }
    if (id == 0xb001) {
      locations->number_of_images_tag = tag;
      found_number_of_images = true;
      continue;
    }
    if (id != 0xb002) continue;
    if (entries_offset > data.size() - tiff || data.size() - (tiff + entries_offset) < 32) {
      return false;
    }
    const size_t entries = tiff + entries_offset;
    locations->count = tag + 4;
    locations->mp_entry_tag = tag;
    locations->mp_entry_value = tag + 8;
    locations->primary_attributes = entries;
    locations->primary_offset = entries + 8;
    locations->secondary_attributes = entries + 16;
    locations->secondary_offset = entries + 24;
    found_entries = true;
  }
  return found_version && found_number_of_images && found_entries;
}

static bool insertDuplicateMpfTag(std::vector<uint8_t>& data, uint16_t tag_id) {
  MpfEntryLocations locations;
  if (!findMpfEntryLocations(data, &locations) || locations.signature < 2) return false;

  uint16_t tag_count = 0;
  uint16_t app2_length = 0;
  uint32_t entries_offset = 0;
  uint32_t secondary_offset = 0;
  if (!readMpfU16ForTest(data, locations.ifd, locations.big_endian, &tag_count) ||
      !readMpfU16ForTest(data, locations.signature - 2, true, &app2_length) ||
      !readMpfU32ForTest(data, locations.mp_entry_value, locations.big_endian, &entries_offset) ||
      !readMpfU32ForTest(data, locations.secondary_offset, locations.big_endian,
                         &secondary_offset)) {
    return false;
  }
  const size_t source_tag =
      tag_id == 0xb001 ? locations.number_of_images_tag : locations.mp_entry_tag;
  const size_t insertion = locations.ifd + 2 + static_cast<size_t>(tag_count) * 12;
  if (source_tag > data.size() || data.size() - source_tag < 12 || insertion > data.size() ||
      app2_length > UINT16_MAX - 12) {
    return false;
  }

  const std::vector<uint8_t> duplicate(data.begin() + source_tag, data.begin() + source_tag + 12);
  data.insert(data.begin() + insertion, duplicate.begin(), duplicate.end());
  writeMpfU16ForTest(data, locations.ifd, locations.big_endian, tag_count + 1);
  writeMpfU16ForTest(data, locations.signature - 2, true, app2_length + 12);
  writeMpfU32ForTest(data, locations.mp_entry_value, locations.big_endian, entries_offset + 12);
  if (tag_id == 0xb002) {
    writeMpfU32ForTest(data, insertion + 8, locations.big_endian, entries_offset + 12);
  }
  writeMpfU32ForTest(data, locations.secondary_offset + 12, locations.big_endian,
                     secondary_offset + 12);
  return true;
}

#if defined(UHDR_ENABLE_HEIF)
static heif_error writeHeifToVector([[maybe_unused]] heif_context* context, const void* data,
                                    size_t size, void* userdata) {
  auto* output = static_cast<std::vector<uint8_t>*>(userdata);
  const uint8_t* bytes = static_cast<const uint8_t*>(data);
  output->insert(output->end(), bytes, bytes + size);
  return {heif_error_Ok, heif_suberror_Unspecified, nullptr};
}

static bool encodeOrdinaryAvif(std::vector<uint8_t>& output) {
  constexpr int width = 16;
  constexpr int height = 16;
  heif_context* context = heif_context_alloc();
  heif_image* image = nullptr;
  heif_encoder* encoder = nullptr;
  heif_image_handle* handle = nullptr;
  bool success = false;
  if (context == nullptr) return false;

  if (heif_image_create(width, height, heif_colorspace_YCbCr, heif_chroma_420, &image).code !=
          heif_error_Ok ||
      heif_image_add_plane(image, heif_channel_Y, width, height, 8).code != heif_error_Ok ||
      heif_image_add_plane(image, heif_channel_Cb, width / 2, height / 2, 8).code !=
          heif_error_Ok ||
      heif_image_add_plane(image, heif_channel_Cr, width / 2, height / 2, 8).code !=
          heif_error_Ok) {
    goto cleanup;
  }
  for (const heif_channel channel : {heif_channel_Y, heif_channel_Cb, heif_channel_Cr}) {
    int stride = 0;
    uint8_t* plane = heif_image_get_plane(image, channel, &stride);
    const int plane_height = channel == heif_channel_Y ? height : height / 2;
    if (plane == nullptr || stride <= 0) goto cleanup;
    std::fill(plane, plane + stride * plane_height, 128);
  }
  if (heif_context_get_encoder_for_format(context, heif_compression_AV1, &encoder).code !=
          heif_error_Ok ||
      heif_context_encode_image(context, image, encoder, nullptr, &handle).code != heif_error_Ok) {
    goto cleanup;
  }
  {
    heif_writer writer{1, writeHeifToVector};
    success = heif_context_write(context, &writer, &output).code == heif_error_Ok;
  }

cleanup:
  if (handle != nullptr) heif_image_handle_release(handle);
  if (encoder != nullptr) heif_encoder_release(encoder);
  if (image != nullptr) heif_image_release(image);
  heif_context_free(context);
  return success;
}
#endif

static void expectGainMapsEqual(const uhdr_raw_image_t* expected,
                                const uhdr_raw_image_t* actual) {
  ASSERT_NE(expected, nullptr);
  ASSERT_NE(actual, nullptr);
  ASSERT_EQ(actual->fmt, expected->fmt);
  ASSERT_EQ(actual->w, expected->w);
  ASSERT_EQ(actual->h, expected->h);

  const size_t bytes_per_pixel =
      expected->fmt == UHDR_IMG_FMT_8bppYCbCr400 ? 1 : 4;
  const size_t row_bytes = expected->w * bytes_per_pixel;
  const auto* expected_data = static_cast<const uint8_t*>(expected->planes[UHDR_PLANE_PACKED]);
  const auto* actual_data = static_cast<const uint8_t*>(actual->planes[UHDR_PLANE_PACKED]);
  for (unsigned row = 0; row < expected->h; ++row) {
    ASSERT_EQ(0, memcmp(expected_data + row * expected->stride[UHDR_PLANE_PACKED] * bytes_per_pixel,
                        actual_data + row * actual->stride[UHDR_PLANE_PACKED] * bytes_per_pixel,
                        row_bytes))
        << "gain map differs at row " << row;
  }
}

class UltraHdrApiTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(loadFile(kYCbCrP010FileName, mP010Data));
    ASSERT_TRUE(loadFile(kYCbCr420FileName, mYuv420Data));
    ASSERT_TRUE(loadFile(kSdrJpgFileName, mSdrJpgData));

    // Setup HDR raw image descriptor (P010, HLG, BT2100)
    mHdrRaw.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
    mHdrRaw.cg = UHDR_CG_BT_2100;
    mHdrRaw.ct = UHDR_CT_HLG;
    mHdrRaw.range = UHDR_CR_FULL_RANGE;
    mHdrRaw.w = kImageWidth;
    mHdrRaw.h = kImageHeight;
    mHdrRaw.planes[UHDR_PLANE_Y] = mP010Data.data();
    mHdrRaw.planes[UHDR_PLANE_UV] = mP010Data.data() + kImageWidth * kImageHeight * 2;
    mHdrRaw.stride[UHDR_PLANE_Y] = kImageWidth;
    mHdrRaw.stride[UHDR_PLANE_UV] = kImageWidth;

    // Setup SDR raw image descriptor (YUV420, sRGB, BT709)
    mSdrRaw.fmt = UHDR_IMG_FMT_12bppYCbCr420;
    mSdrRaw.cg = UHDR_CG_BT_709;
    mSdrRaw.ct = UHDR_CT_SRGB;
    mSdrRaw.range = UHDR_CR_FULL_RANGE;
    mSdrRaw.w = kImageWidth;
    mSdrRaw.h = kImageHeight;
    mSdrRaw.planes[UHDR_PLANE_Y] = mYuv420Data.data();
    mSdrRaw.planes[UHDR_PLANE_U] = mYuv420Data.data() + kImageWidth * kImageHeight;
    mSdrRaw.planes[UHDR_PLANE_V] = mYuv420Data.data() + kImageWidth * kImageHeight * 5 / 4;
    mSdrRaw.stride[UHDR_PLANE_Y] = kImageWidth;
    mSdrRaw.stride[UHDR_PLANE_U] = kImageWidth / 2;
    mSdrRaw.stride[UHDR_PLANE_V] = kImageWidth / 2;

    // Setup SDR compressed image descriptor (JPEG)
    mSdrCompressed.data = mSdrJpgData.data();
    mSdrCompressed.data_sz = mSdrJpgData.size();
    mSdrCompressed.capacity = mSdrJpgData.size();
    mSdrCompressed.cg = UHDR_CG_BT_709;
    mSdrCompressed.ct = UHDR_CT_SRGB;
    mSdrCompressed.range = UHDR_CR_FULL_RANGE;
  }

  std::vector<uint8_t> mP010Data;
  std::vector<uint8_t> mYuv420Data;
  std::vector<uint8_t> mSdrJpgData;
  uhdr_raw_image_t mHdrRaw{};
  uhdr_raw_image_t mSdrRaw{};
  uhdr_compressed_image_t mSdrCompressed{};
};

#if defined(UHDR_ENABLE_HEIF)
static heif_transfer_characteristics getPrimaryImageTransfer(
    const uhdr_compressed_image_t* image) {
  heif_transfer_characteristics transfer = heif_transfer_characteristic_unspecified;
  heif_context* context = heif_context_alloc();
  if (context == nullptr) {
    ADD_FAILURE() << "failed to allocate libheif context";
    return transfer;
  }

  heif_image_handle* primary_handle = nullptr;
  heif_color_profile_nclx* nclx = nullptr;
  heif_error error =
      heif_context_read_from_memory_without_copy(context, image->data, image->data_sz, nullptr);
  if (error.code != heif_error_Ok) {
    ADD_FAILURE() << "failed to parse encoded image";
    goto CleanUp;
  }
  error = heif_context_get_primary_image_handle(context, &primary_handle);
  if (error.code != heif_error_Ok) {
    ADD_FAILURE() << "failed to get primary image";
    goto CleanUp;
  }
  error = heif_image_handle_get_nclx_color_profile(primary_handle, &nclx);
  if (error.code != heif_error_Ok) {
    ADD_FAILURE() << "failed to get primary image nclx profile";
    goto CleanUp;
  }
  transfer = nclx->transfer_characteristics;

CleanUp:
  if (nclx != nullptr) heif_nclx_color_profile_free(nclx);
  if (primary_handle != nullptr) heif_image_handle_release(primary_handle);
  heif_context_free(context);
  return transfer;
}
#endif

TEST_F(UltraHdrApiTest, RoutingProbeRejectsInvalidInputAndOrdinaryJpeg) {
  EXPECT_EQ(uhdr_is_supported_gainmap_image(nullptr, 1), 0);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(mSdrJpgData.data(), 0), 0);
  EXPECT_EQ(is_uhdr_image(mSdrJpgData.data(), static_cast<int>(mSdrJpgData.size())), 0);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(mSdrJpgData.data(), mSdrJpgData.size()), 0);

  const uint8_t truncated_jpeg[] = {0xff, 0xd8, 0xff};
  EXPECT_EQ(uhdr_is_supported_gainmap_image(truncated_jpeg, sizeof truncated_jpeg), 0);
}

TEST_F(UltraHdrApiTest, InvalidCompressedImageIntentDoesNotMutateEncoder) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  auto* handle = dynamic_cast<uhdr_encoder_private*>(enc);
  ASSERT_NE(handle, nullptr);

  uhdr_error_info_t status = uhdr_enc_set_compressed_image(
      enc, &mSdrCompressed, static_cast<uhdr_img_label_t>(999));

  EXPECT_EQ(UHDR_CODEC_INVALID_PARAM, status.error_code) << status.detail;
  EXPECT_TRUE(handle->m_compressed_images.empty());
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, InvalidTargetBrightnessDoesNotMutateEncoder) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  auto* handle = dynamic_cast<uhdr_encoder_private*>(enc);
  ASSERT_NE(handle, nullptr);

  ASSERT_EQ(UHDR_CODEC_OK, uhdr_enc_set_target_display_peak_brightness(enc, 1000.0f).error_code);
  ASSERT_FLOAT_EQ(1000.0f, handle->m_target_disp_max_brightness);

  uhdr_error_info_t status = uhdr_enc_set_target_display_peak_brightness(
      enc, std::numeric_limits<float>::quiet_NaN());

  EXPECT_EQ(UHDR_CODEC_INVALID_PARAM, status.error_code) << status.detail;
  EXPECT_FLOAT_EQ(1000.0f, handle->m_target_disp_max_brightness);
  uhdr_release_encoder(enc);
}

// ============================================================================
// JPEG Tests (API-0 through API-4)
// ============================================================================

TEST_F(UltraHdrApiTest, JpegEncodeApi0AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 90, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 90, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);
  EXPECT_EQ(is_uhdr_image(output->data, static_cast<int>(output->data_sz)), 1);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(output->data, output->data_sz), 1);

  std::vector<uint8_t> broken_association(static_cast<uint8_t*>(output->data),
                                          static_cast<uint8_t*>(output->data) + output->data_sz);
  MpfEntryLocations locations;
  ASSERT_TRUE(findMpfEntryLocations(broken_association, &locations));
  uint32_t secondary_offset = 0;
  ASSERT_TRUE(readMpfU32ForTest(broken_association, locations.secondary_offset,
                                locations.big_endian, &secondary_offset));
  writeMpfU32ForTest(broken_association, locations.secondary_offset, locations.big_endian,
                     secondary_offset + 1);
  EXPECT_EQ(is_uhdr_image(broken_association.data(), static_cast<int>(broken_association.size())),
            0);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(broken_association.data(), broken_association.size()),
            0);

  std::vector<uint8_t> malformed_table(static_cast<uint8_t*>(output->data),
                                       static_cast<uint8_t*>(output->data) + output->data_sz);
  ASSERT_TRUE(findMpfEntryLocations(malformed_table, &locations));
  writeMpfU32ForTest(malformed_table, locations.count, locations.big_endian, 0xffffffffu);
  EXPECT_EQ(is_uhdr_image(malformed_table.data(), static_cast<int>(malformed_table.size())), 0);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(malformed_table.data(), malformed_table.size()), 0);

  std::vector<uint8_t> displaced_signature(static_cast<uint8_t*>(output->data),
                                           static_cast<uint8_t*>(output->data) + output->data_sz);
  ASSERT_TRUE(findMpfEntryLocations(displaced_signature, &locations));
  ASSERT_GE(locations.signature, 2u);
  uint16_t app2_length = 0;
  ASSERT_TRUE(readMpfU16ForTest(displaced_signature, locations.signature - 2, true, &app2_length));
  displaced_signature[locations.signature + 3] = 'x';
  displaced_signature.insert(displaced_signature.begin() + locations.signature + 4,
                             {'M', 'P', 'F', 0});
  writeMpfU16ForTest(displaced_signature, locations.signature - 2, true, app2_length + 4);
  EXPECT_EQ(is_uhdr_image(displaced_signature.data(), static_cast<int>(displaced_signature.size())),
            0);
  EXPECT_EQ(
      uhdr_is_supported_gainmap_image(displaced_signature.data(), displaced_signature.size()), 0);

  for (const uint16_t duplicate_tag : {uint16_t{0xb001}, uint16_t{0xb002}}) {
    std::vector<uint8_t> duplicate_mandatory_tag(
        static_cast<uint8_t*>(output->data),
        static_cast<uint8_t*>(output->data) + output->data_sz);
    ASSERT_TRUE(insertDuplicateMpfTag(duplicate_mandatory_tag, duplicate_tag));
    EXPECT_EQ(is_uhdr_image(duplicate_mandatory_tag.data(),
                            static_cast<int>(duplicate_mandatory_tag.size())),
              0);
    EXPECT_EQ(uhdr_is_supported_gainmap_image(duplicate_mandatory_tag.data(),
                                              duplicate_mandatory_tag.size()),
              0);
  }

  ASSERT_TRUE(findMpfEntryLocations(malformed_table, &locations));
  struct VersionMutation {
    size_t offset;
    bool is_u16;
  };
  for (const VersionMutation mutation : {
           VersionMutation{locations.version_id, true},
           VersionMutation{locations.version_type, true},
           VersionMutation{locations.version_count, false},
           VersionMutation{locations.version_value, false},
       }) {
    std::vector<uint8_t> malformed_version(static_cast<uint8_t*>(output->data),
                                           static_cast<uint8_t*>(output->data) + output->data_sz);
    if (mutation.is_u16) {
      writeMpfU16ForTest(malformed_version, mutation.offset, locations.big_endian, 0);
    } else {
      writeMpfU32ForTest(malformed_version, mutation.offset, locations.big_endian, 0);
    }
    EXPECT_EQ(is_uhdr_image(malformed_version.data(), static_cast<int>(malformed_version.size())),
              0);
    EXPECT_EQ(uhdr_is_supported_gainmap_image(malformed_version.data(), malformed_version.size()),
              0);
  }

  for (const size_t invalid_field :
       {locations.primary_attributes, locations.primary_offset, locations.secondary_attributes}) {
    std::vector<uint8_t> malformed_entry(static_cast<uint8_t*>(output->data),
                                         static_cast<uint8_t*>(output->data) + output->data_sz);
    ASSERT_TRUE(findMpfEntryLocations(malformed_entry, &locations));
    writeMpfU32ForTest(malformed_entry, invalid_field, locations.big_endian, 1);
    EXPECT_EQ(is_uhdr_image(malformed_entry.data(), static_cast<int>(malformed_entry.size())), 0);
    EXPECT_EQ(uhdr_is_supported_gainmap_image(malformed_entry.data(), malformed_entry.size()), 0);
  }

  // Decode stream
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(dec, UHDR_CT_HLG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_32bppRGBA1010102).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(dec), static_cast<int>(kImageWidth));
  EXPECT_EQ(uhdr_dec_get_image_height(dec), static_cast<int>(kImageHeight));
  uhdr_mem_block_t* base_image = uhdr_dec_get_base_image(dec);
  ASSERT_NE(base_image, nullptr);
  EXPECT_NE(base_image->data, nullptr);
  EXPECT_GT(base_image->data_sz, 0u);
  uhdr_mem_block_t* gainmap_image = uhdr_dec_get_gainmap_image(dec);
  ASSERT_NE(gainmap_image, nullptr);
  EXPECT_NE(gainmap_image->data, nullptr);
  EXPECT_GT(gainmap_image->data_sz, 0u);

  ASSERT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);
  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->w, kImageWidth);
  EXPECT_EQ(decoded->h, kImageHeight);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, JpegEncodeApi1AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mSdrRaw, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, JpegEncodeApi2AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

// ============================================================================
// HEIF / HEIC Tests (API-0, API-1, and Unsupported APIs)
// ============================================================================

#if defined(UHDR_ENABLE_HEIF)
static bool setBackwardDirectionFlag(const uhdr_compressed_image_t* image,
                                     std::vector<uint8_t>& modified_image) {
  std::unique_ptr<heif_context, decltype(&heif_context_free)> context(heif_context_alloc(),
                                                                      heif_context_free);
  if (context == nullptr) return false;
  heif_error error = heif_context_read_from_memory_without_copy(context.get(), image->data,
                                                                image->data_sz, nullptr);
  if (error.code != heif_error_Ok) return false;

  heif_image_handle* raw_base_handle = nullptr;
  error = heif_context_get_primary_image_handle(context.get(), &raw_base_handle);
  std::unique_ptr<heif_image_handle, decltype(&heif_image_handle_release)> base_handle(
      raw_base_handle, heif_image_handle_release);
  if (error.code != heif_error_Ok || base_handle == nullptr) return false;

  const size_t metadata_size = heif_image_handle_get_gain_map_metadata_size(base_handle.get());
  if (metadata_size <= 4) return false;
  std::vector<uint8_t> metadata(metadata_size);
  error = heif_image_handle_get_gain_map_metadata(base_handle.get(), metadata.data());
  if (error.code != heif_error_Ok) return false;

  modified_image.assign(static_cast<const uint8_t*>(image->data),
                        static_cast<const uint8_t*>(image->data) + image->data_sz);
  auto metadata_pos =
      std::search(modified_image.begin(), modified_image.end(), metadata.begin(), metadata.end());
  if (metadata_pos == modified_image.end()) return false;
  if (std::search(metadata_pos + metadata.size(), modified_image.end(), metadata.begin(),
                  metadata.end()) != modified_image.end()) {
    return false;
  }

  // ISO 21496-1 metadata stores its flags after two 16-bit version fields.
  // Set backwardDirection, which this decoder explicitly does not support.
  metadata_pos[4] |= 4;
  return true;
}

TEST_F(UltraHdrApiTest, RoutingProbeReflectsHevcDecoderAvailability) {
  std::vector<uint8_t> hevc_gainmap;
  ASSERT_TRUE(loadFile(kHevcGainmapFileName, hevc_gainmap));

  EXPECT_EQ(is_uhdr_image(hevc_gainmap.data(), static_cast<int>(hevc_gainmap.size())), 1);
  const bool have_hevc_decoder = heif_have_decoder_for_format(heif_compression_HEVC);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(hevc_gainmap.data(), hevc_gainmap.size()),
            have_hevc_decoder ? 1 : 0);

  if (have_hevc_decoder) {
    uhdr_compressed_image_t input{};
    input.data = hevc_gainmap.data();
    input.data_sz = hevc_gainmap.size();
    input.capacity = hevc_gainmap.size();
    input.cg = UHDR_CG_UNSPECIFIED;
    input.ct = UHDR_CT_UNSPECIFIED;
    input.range = UHDR_CR_UNSPECIFIED;
    uhdr_codec_private_t* decoder = uhdr_create_decoder();
    ASSERT_NE(decoder, nullptr);
    EXPECT_EQ(uhdr_dec_set_image(decoder, &input).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(uhdr_dec_set_out_color_transfer(decoder, UHDR_CT_HLG).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(uhdr_dec_set_out_img_format(decoder, UHDR_IMG_FMT_32bppRGBA1010102).error_code,
              UHDR_CODEC_OK);
    EXPECT_EQ(uhdr_dec_probe(decoder).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(uhdr_decode(decoder).error_code, UHDR_CODEC_OK);
    uhdr_release_decoder(decoder);
  }
}

TEST_F(UltraHdrApiTest, RoutingProbeRejectsOrdinaryAvif) {
  if (!heif_have_encoder_for_format(heif_compression_AV1)) {
    GTEST_SKIP() << "AV1 encoder plugin not available in environment";
  }
  std::vector<uint8_t> ordinary_avif;
  ASSERT_TRUE(encodeOrdinaryAvif(ordinary_avif));
  ASSERT_FALSE(ordinary_avif.empty());

  EXPECT_EQ(is_uhdr_image(ordinary_avif.data(), static_cast<int>(ordinary_avif.size())), 0);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(ordinary_avif.data(), ordinary_avif.size()), 0);
}

TEST_F(UltraHdrApiTest, HeicEncodeApi0AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      std::string detail_msg = enc_status.detail;
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << detail_msg;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  EXPECT_EQ(is_uhdr_image(output->data, static_cast<int>(output->data_sz)), 1);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(output->data, output->data_sz), 1);

  // Decode HEIC stream
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(dec, UHDR_CT_HLG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_32bppRGBA1010102).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(dec), static_cast<int>(kImageWidth));
  EXPECT_EQ(uhdr_dec_get_image_height(dec), static_cast<int>(kImageHeight));
  EXPECT_EQ(uhdr_dec_get_base_image(dec), nullptr);
  EXPECT_EQ(uhdr_dec_get_gainmap_image(dec), nullptr);

  uhdr_gainmap_metadata_t* metadata = uhdr_dec_get_gainmap_metadata(dec);
  EXPECT_NE(metadata, nullptr);

  uhdr_error_info_t dec_status = uhdr_decode(dec);
  if (dec_status.error_code != UHDR_CODEC_OK) {
    std::cout << "HeicEncodeApi0 decode error: " << (dec_status.has_detail ? dec_status.detail : "no detail") << std::endl;
  }
  ASSERT_EQ(dec_status.error_code, UHDR_CODEC_OK);
  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->w, kImageWidth);
  EXPECT_EQ(decoded->h, kImageHeight);
  uhdr_raw_image_t* hdr_gainmap = uhdr_get_decoded_gainmap_image(dec);
  ASSERT_NE(hdr_gainmap, nullptr);

  uhdr_codec_private_t* sdr_dec = uhdr_create_decoder();
  ASSERT_NE(sdr_dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(sdr_dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(sdr_dec, UHDR_CT_SRGB).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(sdr_dec, UHDR_IMG_FMT_32bppRGBA8888).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(sdr_dec).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_decode(sdr_dec).error_code, UHDR_CODEC_OK);
  expectGainMapsEqual(hdr_gainmap, uhdr_get_decoded_gainmap_image(sdr_dec));

  uhdr_release_decoder(sdr_dec);
  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, HeicEncodeApi1AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mSdrRaw, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      std::string detail_msg = enc_status.detail;
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << detail_msg;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);
  EXPECT_EQ(getPrimaryImageTransfer(output), heif_transfer_characteristic_IEC_61966_2_1);
  EXPECT_EQ(is_uhdr_image(output->data, static_cast<int>(output->data_sz)), 1);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(output->data, output->data_sz), 1);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, HeicEncodeRejectsUndersizedDestination) {
  std::vector<uint8_t> backing_store(6 * kImageWidth * kImageHeight, 0xa5);
  uhdr_compressed_image_t dest{};
  dest.data = backing_store.data();
  dest.capacity = 1;

  HeifUltraHdr codec;
  uhdr_error_info_t status = codec.encodeHeicUltraHdr(&mHdrRaw, &dest, 85, nullptr);
  if (status.error_code != UHDR_CODEC_OK && status.has_detail &&
      (strstr(status.detail, "Unsupported file-type") != nullptr ||
       strstr(status.detail, "No encoder") != nullptr)) {
    GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << status.detail;
  }

  EXPECT_EQ(status.error_code, UHDR_CODEC_MEM_ERROR);
  EXPECT_EQ(dest.capacity, 1u);
  EXPECT_EQ(dest.data_sz, 0u);
  EXPECT_EQ(backing_store.front(), 0xa5);
}

TEST_F(UltraHdrApiTest, HeicCompressedIntentsUnsupported) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t err = uhdr_encode(enc);
  EXPECT_EQ(err.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);

  uhdr_release_encoder(enc);
}

// ============================================================================
// AVIF Tests (API-0, API-1, and Unsupported APIs)
// ============================================================================

TEST_F(UltraHdrApiTest, AvifEncodeApi0AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      std::string detail_msg = enc_status.detail;
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << detail_msg;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  EXPECT_EQ(is_uhdr_image(output->data, static_cast<int>(output->data_sz)), 1);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(output->data, output->data_sz), 1);

  // Decode AVIF stream
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(dec, UHDR_CT_LINEAR).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_64bppRGBAHalfFloat).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_image_width(dec), static_cast<int>(kImageWidth));
  EXPECT_EQ(uhdr_dec_get_image_height(dec), static_cast<int>(kImageHeight));
  EXPECT_EQ(uhdr_dec_get_base_image(dec), nullptr);
  EXPECT_EQ(uhdr_dec_get_gainmap_image(dec), nullptr);

  uhdr_error_info_t dec_status = uhdr_decode(dec);
  if (dec_status.error_code != UHDR_CODEC_OK) {
    std::cout << "AvifEncodeApi0 decode error: " << (dec_status.has_detail ? dec_status.detail : "no detail") << std::endl;
  }
  ASSERT_EQ(dec_status.error_code, UHDR_CODEC_OK);
  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  ASSERT_NE(decoded, nullptr);
  EXPECT_EQ(decoded->w, kImageWidth);
  EXPECT_EQ(decoded->h, kImageHeight);
  uhdr_raw_image_t* hdr_gainmap = uhdr_get_decoded_gainmap_image(dec);
  ASSERT_NE(hdr_gainmap, nullptr);

  uhdr_codec_private_t* sdr_dec = uhdr_create_decoder();
  ASSERT_NE(sdr_dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(sdr_dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_color_transfer(sdr_dec, UHDR_CT_SRGB).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_set_out_img_format(sdr_dec, UHDR_IMG_FMT_32bppRGBA8888).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(sdr_dec).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_decode(sdr_dec).error_code, UHDR_CODEC_OK);
  expectGainMapsEqual(hdr_gainmap, uhdr_get_decoded_gainmap_image(sdr_dec));

  uhdr_release_decoder(sdr_dec);
  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifEncodeApi1AndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mSdrRaw, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK) {
    if (enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      uhdr_release_encoder(enc);
      GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << enc_status.detail;
      return;
    }
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);
  EXPECT_EQ(getPrimaryImageTransfer(output), heif_transfer_characteristic_IEC_61966_2_1);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifEncodeRejectsUndersizedDestination) {
  std::vector<uint8_t> backing_store(6 * kImageWidth * kImageHeight, 0xa5);
  uhdr_compressed_image_t dest{};
  dest.data = backing_store.data();
  dest.capacity = 1;

  AvifUltraHdr codec;
  uhdr_error_info_t status = codec.encodeAvifUltraHdr(&mHdrRaw, &dest, 85, nullptr);
  if (status.error_code != UHDR_CODEC_OK && status.has_detail &&
      (strstr(status.detail, "Unsupported file-type") != nullptr ||
       strstr(status.detail, "No encoder") != nullptr)) {
    GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << status.detail;
  }

  EXPECT_EQ(status.error_code, UHDR_CODEC_MEM_ERROR);
  EXPECT_EQ(dest.capacity, 1u);
  EXPECT_EQ(dest.data_sz, 0u);
  EXPECT_EQ(backing_store.front(), 0xa5);
}

TEST_F(UltraHdrApiTest, HeifAndAvifPropagateGainMapMetadataErrors) {
  int tested_formats = 0;
  for (uhdr_codec_t codec : {UHDR_CODEC_AVIF, UHDR_CODEC_HEIF}) {
    SCOPED_TRACE(codec == UHDR_CODEC_AVIF ? "AVIF" : "HEIF");
    uhdr_codec_private_t* enc = uhdr_create_encoder();
    ASSERT_NE(enc, nullptr);

    ASSERT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
    ASSERT_EQ(uhdr_enc_set_output_format(enc, codec).error_code, UHDR_CODEC_OK);
    uhdr_error_info_t enc_status = uhdr_encode(enc);
    if (enc_status.error_code != UHDR_CODEC_OK && enc_status.has_detail &&
        (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
         strstr(enc_status.detail, "No encoder") != nullptr)) {
      uhdr_release_encoder(enc);
      continue;
    }
    ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK);
    ++tested_formats;

    uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
    ASSERT_NE(output, nullptr);
    std::vector<uint8_t> invalid_data;
    ASSERT_TRUE(setBackwardDirectionFlag(output, invalid_data));

    uhdr_compressed_image_t invalid_image = *output;
    invalid_image.data = invalid_data.data();
    invalid_image.data_sz = invalid_image.capacity = invalid_data.size();

    uhdr_codec_private_t* dec = uhdr_create_decoder();
    ASSERT_NE(dec, nullptr);
    ASSERT_EQ(uhdr_dec_set_image(dec, &invalid_image).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
    uhdr_release_decoder(dec);

    // Exercise each backend error path directly as well. Sanitizer builds verify that these paths
    // release the partially decoded libheif objects before returning the metadata error.
    std::vector<uint8_t> decoded_data(kImageWidth * kImageHeight * 4);
    uhdr_raw_image_t decoded_image{};
    decoded_image.fmt = UHDR_IMG_FMT_32bppRGBA8888;
    decoded_image.cg = UHDR_CG_BT_709;
    decoded_image.ct = UHDR_CT_SRGB;
    decoded_image.range = UHDR_CR_FULL_RANGE;
    decoded_image.w = kImageWidth;
    decoded_image.h = kImageHeight;
    decoded_image.planes[UHDR_PLANE_PACKED] = decoded_data.data();
    decoded_image.stride[UHDR_PLANE_PACKED] = kImageWidth;
    uhdr_gainmap_metadata_t metadata{};
    uhdr_error_info_t decode_status;
    if (codec == UHDR_CODEC_AVIF) {
      AvifUltraHdr avif;
      decode_status = avif.decodeAvifUltraHdr(&invalid_image, &decoded_image, FLT_MAX, UHDR_CT_SRGB,
                                              UHDR_IMG_FMT_32bppRGBA8888, nullptr, &metadata);
    } else {
      HeifUltraHdr heif;
      decode_status = heif.decodeHeicUltraHdr(&invalid_image, &decoded_image, FLT_MAX, UHDR_CT_SRGB,
                                              UHDR_IMG_FMT_32bppRGBA8888, nullptr, &metadata);
    }
    EXPECT_EQ(decode_status.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);

    uhdr_release_encoder(enc);
  }
  if (tested_formats == 0) GTEST_SKIP() << "AV1 and HEVC encoder plugins are unavailable";
}

TEST_F(UltraHdrApiTest, AvifCompressedIntentsUnsupported) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t err = uhdr_encode(enc);
  EXPECT_EQ(err.error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);

  uhdr_release_encoder(enc);
}
#else
TEST_F(UltraHdrApiTest, HeicCodecUnsupportedWhenDisabled) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_HEIF).error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, AvifCodecUnsupportedWhenDisabled) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_AVIF).error_code, UHDR_CODEC_UNSUPPORTED_FEATURE);
  uhdr_release_encoder(enc);
}
#endif

}  // namespace ultrahdr
