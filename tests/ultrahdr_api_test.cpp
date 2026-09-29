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
#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/gainmapmetadata.h"
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
static void expectSupportedHeifGainmap(const void* data, size_t size, bool decoder_available) {
#if defined(UHDR_HAS_HEIF_ITEM_API)
  EXPECT_EQ(uhdr_is_supported_gainmap_image(data, size), decoder_available ? 1 : 0);
#else
  // The legacy HEIF gain-map APIs keep encode/decode coverage available, but routing requires
  // the optional item-inspection API. The documented fallback is an unsupported routing result.
  EXPECT_EQ(uhdr_is_supported_gainmap_image(data, size), 0);
  (void)decoder_available;
#endif
}

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

using HeifContextPtr = std::unique_ptr<heif_context, decltype(&heif_context_free)>;
using HeifEncoderPtr = std::unique_ptr<heif_encoder, decltype(&heif_encoder_release)>;
using HeifImagePtr = std::unique_ptr<heif_image, decltype(&heif_image_release)>;
using HeifHandlePtr =
    std::unique_ptr<heif_image_handle, decltype(&heif_image_handle_release)>;
using HeifOptionsPtr =
    std::unique_ptr<heif_encoding_options, decltype(&heif_encoding_options_free)>;
using HeifProfilePtr =
    std::unique_ptr<heif_color_profile_nclx, decltype(&heif_nclx_color_profile_free)>;

static bool fillHeifPlane(heif_image* image, heif_channel channel, int width, int height,
                          uint8_t value) {
  int stride = 0;
  uint8_t* plane = heif_image_get_plane(image, channel, &stride);
  if (plane == nullptr || stride < width) return false;
  for (int y = 0; y < height; ++y) {
    std::fill(plane + y * stride, plane + y * stride + width, value);
  }
  return true;
}

static HeifProfilePtr makeNclxProfile(uint16_t primaries, uint16_t transfer, uint16_t matrix) {
  HeifProfilePtr profile(heif_nclx_color_profile_alloc(), heif_nclx_color_profile_free);
  if (profile == nullptr ||
      heif_nclx_color_profile_set_color_primaries(profile.get(), primaries).code !=
          heif_error_Ok ||
      heif_nclx_color_profile_set_transfer_characteristics(profile.get(), transfer).code !=
          heif_error_Ok ||
      heif_nclx_color_profile_set_matrix_coefficients(profile.get(), matrix).code !=
          heif_error_Ok) {
    return HeifProfilePtr(nullptr, heif_nclx_color_profile_free);
  }
  profile->full_range_flag = 1;
  return profile;
}

static bool encodeGainmapSideAlphaAvif(std::vector<uint8_t>& output) {
  constexpr int base_width = 64;
  constexpr int base_height = 64;
  constexpr int gainmap_width = 32;
  constexpr int gainmap_height = 32;

  HeifContextPtr context(heif_context_alloc(), heif_context_free);
  if (context == nullptr) return false;

  heif_image* base_raw = nullptr;
  if (heif_image_create(base_width, base_height, heif_colorspace_YCbCr, heif_chroma_420,
                        &base_raw)
              .code != heif_error_Ok) {
    return false;
  }
  HeifImagePtr base(base_raw, heif_image_release);
  if (heif_image_add_plane(base.get(), heif_channel_Y, base_width, base_height, 8).code !=
          heif_error_Ok ||
      heif_image_add_plane(base.get(), heif_channel_Cb, base_width / 2, base_height / 2, 8)
              .code != heif_error_Ok ||
      heif_image_add_plane(base.get(), heif_channel_Cr, base_width / 2, base_height / 2, 8)
              .code != heif_error_Ok ||
      !fillHeifPlane(base.get(), heif_channel_Y, base_width, base_height, 128) ||
      !fillHeifPlane(base.get(), heif_channel_Cb, base_width / 2, base_height / 2, 128) ||
      !fillHeifPlane(base.get(), heif_channel_Cr, base_width / 2, base_height / 2, 128)) {
    return false;
  }

  heif_image* gainmap_raw = nullptr;
  if (heif_image_create(gainmap_width, gainmap_height, heif_colorspace_monochrome,
                        heif_chroma_monochrome, &gainmap_raw)
              .code != heif_error_Ok) {
    return false;
  }
  HeifImagePtr gainmap(gainmap_raw, heif_image_release);
  if (heif_image_add_plane(gainmap.get(), heif_channel_Y, gainmap_width, gainmap_height, 8)
              .code != heif_error_Ok ||
      heif_image_add_plane(gainmap.get(), heif_channel_Alpha, gainmap_width, gainmap_height, 8)
              .code != heif_error_Ok ||
      !fillHeifPlane(gainmap.get(), heif_channel_Y, gainmap_width, gainmap_height, 96) ||
      !fillHeifPlane(gainmap.get(), heif_channel_Alpha, gainmap_width, gainmap_height, 128)) {
    return false;
  }
  heif_image_set_premultiplied_alpha(gainmap.get(), 0);

  HeifProfilePtr base_profile =
      makeNclxProfile(heif_color_primaries_ITU_R_BT_709_5,
                      heif_transfer_characteristic_ITU_R_BT_709_5,
                      heif_matrix_coefficients_ITU_R_BT_709_5);
  HeifProfilePtr gainmap_profile =
      makeNclxProfile(heif_color_primaries_unspecified, heif_transfer_characteristic_unspecified,
                      heif_matrix_coefficients_ITU_R_BT_601_6);
  HeifProfilePtr derived_profile =
      makeNclxProfile(heif_color_primaries_ITU_R_BT_2020_2_and_2100_0,
                      heif_transfer_characteristic_ITU_R_BT_2100_0_HLG,
                      heif_matrix_coefficients_ITU_R_BT_2020_2_non_constant_luminance);
  if (base_profile == nullptr || gainmap_profile == nullptr || derived_profile == nullptr ||
      heif_image_set_nclx_color_profile(base.get(), base_profile.get()).code != heif_error_Ok ||
      heif_image_set_nclx_color_profile(gainmap.get(), gainmap_profile.get()).code !=
          heif_error_Ok) {
    return false;
  }

  heif_encoder* encoder_raw = nullptr;
  if (heif_context_get_encoder_for_format(context.get(), heif_compression_AV1, &encoder_raw)
              .code != heif_error_Ok) {
    return false;
  }
  HeifEncoderPtr encoder(encoder_raw, heif_encoder_release);
  if (heif_encoder_set_lossy_quality(encoder.get(), 100).code != heif_error_Ok) return false;

  HeifOptionsPtr options(heif_encoding_options_alloc(), heif_encoding_options_free);
  if (options == nullptr) return false;
  options->save_alpha_channel = 1;
  options->output_nclx_profile = base_profile.get();

  heif_image_handle* base_handle_raw = nullptr;
  if (heif_context_encode_image(context.get(), base.get(), encoder.get(), options.get(),
                                &base_handle_raw)
              .code != heif_error_Ok) {
    return false;
  }
  HeifHandlePtr base_handle(base_handle_raw, heif_image_handle_release);

  uhdr_gainmap_metadata_frac metadata;
  metadata.alternateHdrHeadroomN = 2;
  std::vector<uint8_t> iso_metadata;
  if (uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, iso_metadata).error_code !=
      UHDR_CODEC_OK) {
    return false;
  }

  options->output_nclx_profile = gainmap_profile.get();
  if (heif_encoder_set_lossy_quality(encoder.get(), 100).code != heif_error_Ok) return false;
  heif_image_handle* gainmap_handle_raw = nullptr;
  if (heif_context_encode_gain_map_image(
          context.get(), base_handle.get(), encoder.get(), gainmap.get(), options.get(),
          iso_metadata.data(), static_cast<int>(iso_metadata.size()), derived_profile.get(),
          &gainmap_handle_raw)
          .code != heif_error_Ok) {
    return false;
  }
  HeifHandlePtr gainmap_handle(gainmap_handle_raw, heif_image_handle_release);

  heif_writer writer{1, writeHeifToVector};
  return heif_context_write(context.get(), &writer, &output).code == heif_error_Ok &&
         !output.empty();
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
  // is_uhdr_image() retains its historical decoder-probe behavior. The stricter MPF association
  // check belongs to the new routing predicate.
  EXPECT_EQ(is_uhdr_image(broken_association.data(), static_cast<int>(broken_association.size())),
            1);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(broken_association.data(), broken_association.size()),
            0);

  std::vector<uint8_t> malformed_table(static_cast<uint8_t*>(output->data),
                                       static_cast<uint8_t*>(output->data) + output->data_sz);
  ASSERT_TRUE(findMpfEntryLocations(malformed_table, &locations));
  writeMpfU32ForTest(malformed_table, locations.count, locations.big_endian, 0xffffffffu);
  EXPECT_EQ(is_uhdr_image(malformed_table.data(), static_cast<int>(malformed_table.size())), 1);
  EXPECT_EQ(uhdr_is_supported_gainmap_image(malformed_table.data(), malformed_table.size()), 0);

  std::vector<uint8_t> displaced_signature(static_cast<uint8_t*>(output->data),
                                           static_cast<uint8_t*>(output->data) + output->data_sz);
  ASSERT_TRUE(findMpfEntryLocations(displaced_signature, &locations));
  ASSERT_GE(locations.signature, 2u);
  uint16_t app2_length = 0;
  ASSERT_TRUE(readMpfU16ForTest(displaced_signature, locations.signature - 2, true, &app2_length));
  displaced_signature[locations.signature + 3] = 'x';
  const size_t displaced_mpf_offset = locations.signature + 4;
  displaced_signature.insert(displaced_signature.begin() + displaced_mpf_offset, 4, uint8_t{0});
  displaced_signature[displaced_mpf_offset] = 'M';
  displaced_signature[displaced_mpf_offset + 1] = 'P';
  displaced_signature[displaced_mpf_offset + 2] = 'F';
  writeMpfU16ForTest(displaced_signature, locations.signature - 2, true, app2_length + 4);
  EXPECT_EQ(is_uhdr_image(displaced_signature.data(), static_cast<int>(displaced_signature.size())),
            1);
  EXPECT_EQ(
      uhdr_is_supported_gainmap_image(displaced_signature.data(), displaced_signature.size()), 0);

  for (const uint16_t duplicate_tag : {uint16_t{0xb001}, uint16_t{0xb002}}) {
    std::vector<uint8_t> duplicate_mandatory_tag(
        static_cast<uint8_t*>(output->data),
        static_cast<uint8_t*>(output->data) + output->data_sz);
    ASSERT_TRUE(insertDuplicateMpfTag(duplicate_mandatory_tag, duplicate_tag));
    EXPECT_EQ(is_uhdr_image(duplicate_mandatory_tag.data(),
                            static_cast<int>(duplicate_mandatory_tag.size())),
              1);
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
              1);
    EXPECT_EQ(uhdr_is_supported_gainmap_image(malformed_version.data(), malformed_version.size()),
              0);
  }

  for (const size_t invalid_field :
       {locations.primary_attributes, locations.primary_offset, locations.secondary_attributes}) {
    std::vector<uint8_t> malformed_entry(static_cast<uint8_t*>(output->data),
                                         static_cast<uint8_t*>(output->data) + output->data_sz);
    ASSERT_TRUE(findMpfEntryLocations(malformed_entry, &locations));
    writeMpfU32ForTest(malformed_entry, invalid_field, locations.big_endian, 1);
    EXPECT_EQ(is_uhdr_image(malformed_entry.data(), static_cast<int>(malformed_entry.size())), 1);
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
  expectSupportedHeifGainmap(hevc_gainmap.data(), hevc_gainmap.size(), have_hevc_decoder);

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

TEST_F(UltraHdrApiTest, RoutingProbeRejectsOrdinaryAvifButLegacyPredicateRemainsCompatible) {
  if (!heif_have_encoder_for_format(heif_compression_AV1)) {
    GTEST_SKIP() << "AV1 encoder plugin not available in environment";
  }
  std::vector<uint8_t> ordinary_avif;
  ASSERT_TRUE(encodeOrdinaryAvif(ordinary_avif));
  ASSERT_FALSE(ordinary_avif.empty());

  // The historical decoder-probe implementation returns 1 for a parseable HEIF/AVIF container
  // even when it has no gain map. Keep that compatibility behavior explicit here.
  EXPECT_EQ(is_uhdr_image(ordinary_avif.data(), static_cast<int>(ordinary_avif.size())), 1);
  expectSupportedHeifGainmap(ordinary_avif.data(), ordinary_avif.size(), false);
}

TEST(UltraHdrRoutingTest, GainmapSideAlphaIsSupported) {
  if (!heif_have_encoder_for_format(heif_compression_AV1)) {
    GTEST_SKIP() << "AV1 encoder plugin not available in environment";
  }

  std::vector<uint8_t> encoded;
  ASSERT_TRUE(encodeGainmapSideAlphaAvif(encoded));

  HeifContextPtr context(heif_context_alloc(), heif_context_free);
  ASSERT_NE(context, nullptr);
  ASSERT_EQ(heif_context_read_from_memory_without_copy(context.get(), encoded.data(),
                                                       encoded.size(), nullptr)
                .code,
            heif_error_Ok);

  heif_image_handle* primary_raw = nullptr;
  ASSERT_EQ(heif_context_get_primary_image_handle(context.get(), &primary_raw).code,
            heif_error_Ok);
  HeifHandlePtr primary(primary_raw, heif_image_handle_release);
  ASSERT_NE(primary, nullptr);

  heif_image_handle* gainmap_raw = nullptr;
  ASSERT_EQ(heif_image_handle_get_gain_map_image_handle(primary.get(), &gainmap_raw).code,
            heif_error_Ok);
  HeifHandlePtr gainmap(gainmap_raw, heif_image_handle_release);
  ASSERT_NE(gainmap, nullptr);

  EXPECT_EQ(heif_image_handle_has_alpha_channel(primary.get()), 0);
  EXPECT_EQ(heif_image_handle_has_alpha_channel(gainmap.get()), 1);
  EXPECT_EQ(heif_image_handle_is_premultiplied_alpha(gainmap.get()), 0);
  expectSupportedHeifGainmap(encoded.data(), encoded.size(),
                             heif_have_decoder_for_format(heif_compression_AV1));
}

namespace {

constexpr size_t kAlphaTestWidth = 64;
constexpr size_t kAlphaTestHeight = 64;

struct AlphaTestImages {
  std::vector<uint32_t> hdr1010102;
  std::vector<uint16_t> hdrHalfFloat;
  std::vector<uint32_t> sdr8888;
  uhdr_raw_image_t hdr1010102Desc{};
  uhdr_raw_image_t hdrHalfFloatDesc{};
  uhdr_raw_image_t sdr8888Desc{};

  AlphaTestImages()
      : hdr1010102(kAlphaTestWidth * kAlphaTestHeight),
        hdrHalfFloat(kAlphaTestWidth * kAlphaTestHeight * 4),
        sdr8888(kAlphaTestWidth * kAlphaTestHeight) {
    for (size_t y = 0; y < kAlphaTestHeight; ++y) {
      for (size_t x = 0; x < kAlphaTestWidth; ++x) {
        const size_t pixel = y * kAlphaTestWidth + x;
        const uint32_t alpha2 = static_cast<uint32_t>(x / (kAlphaTestWidth / 4));
        const uint32_t alpha8 = alpha2 * 85u;
        hdr1010102[pixel] = 700u | (500u << 10) | (300u << 20) | (alpha2 << 30);
        hdrHalfFloat[pixel * 4] = floatToHalf(2.0f);
        hdrHalfFloat[pixel * 4 + 1] = floatToHalf(1.5f);
        hdrHalfFloat[pixel * 4 + 2] = floatToHalf(1.0f);
        hdrHalfFloat[pixel * 4 + 3] = floatToHalf(alpha2 / 3.0f);
        sdr8888[pixel] = 120u | (80u << 8) | (40u << 16) | (alpha8 << 24);
      }
    }

    hdr1010102Desc.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
    hdr1010102Desc.cg = UHDR_CG_BT_2100;
    hdr1010102Desc.ct = UHDR_CT_HLG;
    hdr1010102Desc.range = UHDR_CR_FULL_RANGE;
    hdr1010102Desc.w = kAlphaTestWidth;
    hdr1010102Desc.h = kAlphaTestHeight;
    hdr1010102Desc.planes[UHDR_PLANE_PACKED] = hdr1010102.data();
    hdr1010102Desc.stride[UHDR_PLANE_PACKED] = kAlphaTestWidth;

    hdrHalfFloatDesc.fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
    hdrHalfFloatDesc.cg = UHDR_CG_BT_2100;
    hdrHalfFloatDesc.ct = UHDR_CT_LINEAR;
    hdrHalfFloatDesc.range = UHDR_CR_FULL_RANGE;
    hdrHalfFloatDesc.w = kAlphaTestWidth;
    hdrHalfFloatDesc.h = kAlphaTestHeight;
    hdrHalfFloatDesc.planes[UHDR_PLANE_PACKED] = hdrHalfFloat.data();
    hdrHalfFloatDesc.stride[UHDR_PLANE_PACKED] = kAlphaTestWidth;

    sdr8888Desc.fmt = UHDR_IMG_FMT_32bppRGBA8888;
    sdr8888Desc.cg = UHDR_CG_BT_709;
    sdr8888Desc.ct = UHDR_CT_SRGB;
    sdr8888Desc.range = UHDR_CR_FULL_RANGE;
    sdr8888Desc.w = kAlphaTestWidth;
    sdr8888Desc.h = kAlphaTestHeight;
    sdr8888Desc.planes[UHDR_PLANE_PACKED] = sdr8888.data();
    sdr8888Desc.stride[UHDR_PLANE_PACKED] = kAlphaTestWidth;
  }

  void makeHdr1010102AlphaOpaque() {
    for (uint32_t& pixel : hdr1010102) pixel |= 3u << 30;
  }
};

uhdr_error_info_t encodeRawAlphaImage(uhdr_codec_t codec, uhdr_raw_image_t* hdr,
                                      uhdr_raw_image_t* sdr, std::vector<uint8_t>* encoded) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  if (enc == nullptr) {
    uhdr_error_info_t status{};
    status.error_code = UHDR_CODEC_MEM_ERROR;
    return status;
  }

  uhdr_error_info_t status = uhdr_enc_set_raw_image(enc, hdr, UHDR_HDR_IMG);
  if (status.error_code == UHDR_CODEC_OK && sdr != nullptr) {
    status = uhdr_enc_set_raw_image(enc, sdr, UHDR_SDR_IMG);
  }
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_enc_set_output_format(enc, codec);
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_enc_set_quality(enc, 100, UHDR_BASE_IMG);
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_encode(enc);
  if (status.error_code == UHDR_CODEC_OK) {
    uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
    if (output == nullptr || output->data_sz == 0) {
      status.error_code = UHDR_CODEC_ERROR;
    } else {
      const uint8_t* data = static_cast<const uint8_t*>(output->data);
      encoded->assign(data, data + output->data_sz);
    }
  }
  uhdr_release_encoder(enc);
  return status;
}

::testing::AssertionResult containerHasStraightAlpha(const std::vector<uint8_t>& encoded) {
  heif_context* context = heif_context_alloc();
  if (context == nullptr) return ::testing::AssertionFailure() << "libheif allocation failed";

  heif_error error =
      heif_context_read_from_memory_without_copy(context, encoded.data(), encoded.size(), nullptr);
  if (error.code != heif_error_Ok) {
    const std::string detail = error.message != nullptr ? error.message : "no detail";
    heif_context_free(context);
    return ::testing::AssertionFailure() << "libheif read failed: " << detail;
  }

  heif_image_handle* primary = nullptr;
  error = heif_context_get_primary_image_handle(context, &primary);
  if (error.code != heif_error_Ok || primary == nullptr) {
    const std::string detail = error.message != nullptr ? error.message : "no detail";
    heif_context_free(context);
    return ::testing::AssertionFailure() << "primary image lookup failed: " << detail;
  }

  const bool has_alpha = heif_image_handle_has_alpha_channel(primary);
  const bool is_premultiplied = heif_image_handle_is_premultiplied_alpha(primary);
  heif_image_handle_release(primary);
  heif_context_free(context);
  if (!has_alpha) return ::testing::AssertionFailure() << "base image has no alpha channel";
  if (is_premultiplied) {
    return ::testing::AssertionFailure() << "base image alpha is marked premultiplied";
  }
  return ::testing::AssertionSuccess();
}

::testing::AssertionResult decodedAlphaMatches(const std::vector<uint8_t>& encoded) {
  const ::testing::AssertionResult container_result = containerHasStraightAlpha(encoded);
  if (!container_result) return container_result;

  uhdr_compressed_image_t input{};
  input.data = const_cast<uint8_t*>(encoded.data());
  input.data_sz = encoded.size();
  input.capacity = encoded.size();

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  if (dec == nullptr) return ::testing::AssertionFailure() << "decoder allocation failed";
  uhdr_error_info_t status = uhdr_dec_set_image(dec, &input);
  if (status.error_code == UHDR_CODEC_OK) {
    status = uhdr_dec_set_out_color_transfer(dec, UHDR_CT_SRGB);
  }
  if (status.error_code == UHDR_CODEC_OK) {
    status = uhdr_dec_set_out_img_format(dec, UHDR_IMG_FMT_32bppRGBA8888);
  }
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_dec_probe(dec);
  if (status.error_code == UHDR_CODEC_OK) status = uhdr_decode(dec);
  if (status.error_code != UHDR_CODEC_OK) {
    const std::string detail = status.has_detail ? status.detail : "no detail";
    uhdr_release_decoder(dec);
    return ::testing::AssertionFailure() << "decode failed: " << detail;
  }

  uhdr_raw_image_t* decoded = uhdr_get_decoded_image(dec);
  if (decoded == nullptr || decoded->fmt != UHDR_IMG_FMT_32bppRGBA8888 ||
      decoded->w != kAlphaTestWidth || decoded->h != kAlphaTestHeight) {
    uhdr_release_decoder(dec);
    return ::testing::AssertionFailure() << "unexpected decoded image descriptor";
  }

  const auto* pixels = static_cast<const uint32_t*>(decoded->planes[UHDR_PLANE_PACKED]);
  const size_t stride = decoded->stride[UHDR_PLANE_PACKED];
  for (size_t y = 0; y < kAlphaTestHeight; ++y) {
    for (size_t x = 0; x < kAlphaTestWidth; ++x) {
      const int alpha = pixels[y * stride + x] >> 24;
      const int expected = static_cast<int>(x / (kAlphaTestWidth / 4)) * 85;
      if (std::abs(alpha - expected) > 16) {
        uhdr_release_decoder(dec);
        return ::testing::AssertionFailure() << "unexpected alpha " << alpha << ", expected "
                                             << expected << " at (" << x << ", " << y << ")";
      }
    }
  }
  uhdr_release_decoder(dec);
  return ::testing::AssertionSuccess();
}

void expectRawAlphaPreserved(uhdr_codec_t codec, uhdr_raw_image_t* hdr,
                             uhdr_raw_image_t* sdr = nullptr) {
  std::vector<uint8_t> encoded;
  const uhdr_error_info_t status = encodeRawAlphaImage(codec, hdr, sdr, &encoded);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "no detail");
  EXPECT_TRUE(decodedAlphaMatches(encoded));
}

bool encoderUnavailable(const uhdr_error_info_t& status) {
  return status.error_code != UHDR_CODEC_OK && status.has_detail &&
         (strstr(status.detail, "Unsupported file-type") != nullptr ||
          strstr(status.detail, "No encoder") != nullptr);
}

}  // namespace

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
  expectSupportedHeifGainmap(output->data, output->data_sz,
                             heif_have_decoder_for_format(heif_compression_HEVC));

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
  expectSupportedHeifGainmap(output->data, output->data_sz,
                             heif_have_decoder_for_format(heif_compression_HEVC));

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
  expectSupportedHeifGainmap(output->data, output->data_sz,
                             heif_have_decoder_for_format(heif_compression_AV1));

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
  EXPECT_EQ(is_uhdr_image(output->data, static_cast<int>(output->data_sz)), 1);
  expectSupportedHeifGainmap(output->data, output->data_sz,
                             heif_have_decoder_for_format(heif_compression_AV1));

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

class OddMultichannelGainMapCodecTest : public ::testing::TestWithParam<uhdr_codec_t> {};

TEST_P(OddMultichannelGainMapCodecTest, PreservesOddGainMapEdges) {
  constexpr unsigned width = 36;
  constexpr unsigned height = 36;
  constexpr unsigned gainmap_scale_factor = 4;
  constexpr unsigned gainmap_width = width / gainmap_scale_factor;
  constexpr unsigned gainmap_height = height / gainmap_scale_factor;
  constexpr unsigned edge_sample_x = (gainmap_width - 1) * gainmap_scale_factor;
  constexpr unsigned edge_sample_y = (gainmap_height - 1) * gainmap_scale_factor;
  std::vector<uint32_t> hdr_pixels(static_cast<size_t>(width) * height,
                                   700u | (700u << 10) | (700u << 20) | (3u << 30));
  hdr_pixels[static_cast<size_t>(edge_sample_y) * width + edge_sample_x] =
      1000u | (300u << 10) | (100u << 20) | (3u << 30);
  uhdr_raw_image_t hdr{};
  hdr.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
  hdr.cg = UHDR_CG_BT_2100;
  hdr.ct = UHDR_CT_HLG;
  hdr.range = UHDR_CR_FULL_RANGE;
  hdr.w = width;
  hdr.h = height;
  hdr.planes[UHDR_PLANE_PACKED] = hdr_pixels.data();
  hdr.stride[UHDR_PLANE_PACKED] = width;

  std::vector<uint8_t> sdr_pixels(static_cast<size_t>(width) * height * 4, 128);
  for (size_t i = 3; i < sdr_pixels.size(); i += 4) sdr_pixels[i] = 255;
  uhdr_raw_image_t sdr{};
  sdr.fmt = UHDR_IMG_FMT_32bppRGBA8888;
  sdr.cg = UHDR_CG_BT_2100;
  sdr.ct = UHDR_CT_SRGB;
  sdr.range = UHDR_CR_FULL_RANGE;
  sdr.w = width;
  sdr.h = height;
  sdr.planes[UHDR_PLANE_PACKED] = sdr_pixels.data();
  sdr.stride[UHDR_PLANE_PACKED] = width;

  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  ASSERT_EQ(uhdr_enc_set_raw_image(enc, &hdr, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_raw_image(enc, &sdr, UHDR_SDR_IMG).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(enc, GetParam()).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_using_multi_channel_gainmap(enc, 1).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_gainmap_scale_factor(enc, gainmap_scale_factor).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_quality(enc, 100, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  uhdr_error_info_t enc_status = uhdr_encode(enc);
  if (enc_status.error_code != UHDR_CODEC_OK && enc_status.has_detail &&
      (strstr(enc_status.detail, "Unsupported file-type") != nullptr ||
       strstr(enc_status.detail, "No encoder") != nullptr)) {
    const std::string detail = enc_status.detail;
    uhdr_release_encoder(enc);
    GTEST_SKIP() << "encoder plugin not available in environment: " << detail;
  }
  ASSERT_EQ(enc_status.error_code, UHDR_CODEC_OK)
      << (enc_status.has_detail ? enc_status.detail : "");
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);

  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  ASSERT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_get_gainmap_width(dec), static_cast<int>(gainmap_width));
  EXPECT_EQ(uhdr_dec_get_gainmap_height(dec), static_cast<int>(gainmap_height));
  ASSERT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  heif_context* heif_ctx = heif_context_alloc();
  ASSERT_NE(heif_ctx, nullptr);
  ASSERT_EQ(
      heif_context_read_from_memory_without_copy(heif_ctx, output->data, output->data_sz, nullptr)
          .code,
      heif_error_Ok);
  heif_image_handle* base_handle = nullptr;
  ASSERT_EQ(heif_context_get_primary_image_handle(heif_ctx, &base_handle).code, heif_error_Ok);
  heif_image_handle* gainmap_handle = nullptr;
  ASSERT_EQ(heif_image_handle_get_gain_map_image_handle(base_handle, &gainmap_handle).code,
            heif_error_Ok);
  EXPECT_EQ(heif_image_handle_get_width(gainmap_handle), static_cast<int>(gainmap_width));
  EXPECT_EQ(heif_image_handle_get_height(gainmap_handle), static_cast<int>(gainmap_height));
  heif_image* decoded_gainmap = nullptr;
  ASSERT_EQ(heif_decode_image(gainmap_handle, &decoded_gainmap, heif_colorspace_RGB,
                              heif_chroma_interleaved_RGBA, nullptr)
                .code,
            heif_error_Ok);
  int gainmap_stride = 0;
  const uint8_t* gainmap_pixels =
      heif_image_get_plane_readonly(decoded_gainmap, heif_channel_interleaved, &gainmap_stride);
  ASSERT_NE(gainmap_pixels, nullptr);
  const size_t edge_offset =
      static_cast<size_t>(gainmap_height - 1) * gainmap_stride + (gainmap_width - 1) * 4;
  // The final source sample has much more red gain than green or blue. This verifies that the
  // partial lower-right 4:2:0 block carries its own chroma instead of retaining default values or
  // borrowing the previous complete pair.
  EXPECT_GT(gainmap_pixels[edge_offset], gainmap_pixels[edge_offset + 1] + 20);
  EXPECT_GT(gainmap_pixels[edge_offset], gainmap_pixels[edge_offset + 2] + 20);

  heif_image_release(decoded_gainmap);
  heif_image_handle_release(gainmap_handle);
  heif_image_handle_release(base_handle);
  heif_context_free(heif_ctx);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

INSTANTIATE_TEST_SUITE_P(AvifAndHeif, OddMultichannelGainMapCodecTest,
                         ::testing::Values(UHDR_CODEC_AVIF, UHDR_CODEC_HEIF));

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

TEST_F(UltraHdrApiTest, AvifPreservesRawAlpha) {
  AlphaTestImages images;
  std::vector<uint8_t> encoded;
  uhdr_error_info_t status =
      encodeRawAlphaImage(UHDR_CODEC_AVIF, &images.hdr1010102Desc, nullptr, &encoded);
  if (encoderUnavailable(status)) {
    GTEST_SKIP() << "AV1 encoder plugin not available in environment: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "no detail");
  // This fixture has straight alpha on the primary AVIF item. Its gain-map item is ordinary
  // monochrome and is not alpha-bearing. When item inspection is available, the routing assertion
  // covers the primary-alpha form; the helper below also performs a real SDR decode to RGBA.
  EXPECT_EQ(is_uhdr_image(encoded.data(), static_cast<int>(encoded.size())), 1);
  expectSupportedHeifGainmap(encoded.data(), encoded.size(),
                             heif_have_decoder_for_format(heif_compression_AV1));
  EXPECT_TRUE(decodedAlphaMatches(encoded));
  expectRawAlphaPreserved(UHDR_CODEC_AVIF, &images.hdrHalfFloatDesc);
  images.makeHdr1010102AlphaOpaque();
  expectRawAlphaPreserved(UHDR_CODEC_AVIF, &images.hdr1010102Desc, &images.sdr8888Desc);
}

TEST_F(UltraHdrApiTest, HeifPreservesRawAlpha) {
  AlphaTestImages images;
  std::vector<uint8_t> encoded;
  uhdr_error_info_t status =
      encodeRawAlphaImage(UHDR_CODEC_HEIF, &images.hdr1010102Desc, nullptr, &encoded);
  if (encoderUnavailable(status)) {
    GTEST_SKIP() << "HEVC encoder plugin not available in environment: " << status.detail;
  }
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << (status.has_detail ? status.detail : "no detail");
  EXPECT_EQ(is_uhdr_image(encoded.data(), static_cast<int>(encoded.size())), 1);
  expectSupportedHeifGainmap(encoded.data(), encoded.size(),
                             heif_have_decoder_for_format(heif_compression_HEVC));
  EXPECT_TRUE(decodedAlphaMatches(encoded));
  expectRawAlphaPreserved(UHDR_CODEC_HEIF, &images.hdrHalfFloatDesc);
  images.makeHdr1010102AlphaOpaque();
  expectRawAlphaPreserved(UHDR_CODEC_HEIF, &images.hdr1010102Desc, &images.sdr8888Desc);
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
