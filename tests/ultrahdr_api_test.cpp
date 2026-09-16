#if defined(__has_include)
#if __has_include("testing/base/public/gunit.h")
#include "testing/base/public/gunit.h"
#else
#include <gtest/gtest.h>
#endif
#else
#include <gtest/gtest.h>
#endif
#include <charconv>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <memory>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/jpegencoderhelper.h"
#include "ultrahdr/heifultrahdr.h"
#include "ultrahdr/avifultrahdr.h"
#include "image_io/base/message_handler.h"
#include "image_io/xml/xml_element_rules.h"
#include "image_io/xml/xml_handler.h"
#include "image_io/xml/xml_reader.h"

namespace ultrahdr {

static const char* kYCbCrP010FileName = "raw_p010_image.p010";
static const char* kYCbCr420FileName = "raw_yuv420_image.yuv420";
static const char* kSdrJpgFileName = "jpeg_image.jpg";
static const size_t kImageWidth = 1280;
static const size_t kImageHeight = 720;

static std::string makeLargeXmp(size_t size) {
  const std::string prefix =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\"><dc:Pad xmlns:dc=\"urn:test\"><!--";
  const std::string suffix = "--></dc:Pad></rdf:Description></rdf:RDF></x:xmpmeta>";
  EXPECT_GE(size, prefix.size() + suffix.size());
  return prefix + std::string(size - prefix.size() - suffix.size(), 'X') + suffix;
}

static std::vector<uint8_t> makeSmallHdrData() {
  const uint16_t pixel[] = {0x3c00, 0x4000, 0x3800, 0x3c00};
  std::vector<uint8_t> data(8 * 8 * sizeof(pixel));
  for (size_t i = 0; i < 8 * 8; ++i) {
    memcpy(data.data() + i * sizeof(pixel), pixel, sizeof(pixel));
  }
  return data;
}

static std::string getXmpPacket(const uhdr_mem_block_t* xmp) {
  constexpr std::string_view kXmpNamespace = "http://ns.adobe.com/xap/1.0/";
  if (xmp == nullptr || xmp->data == nullptr) return {};
  const auto* bytes = static_cast<const char*>(xmp->data);
  size_t offset = 0;
  if (xmp->data_sz >= kXmpNamespace.size() &&
      std::string_view(bytes, kXmpNamespace.size()) == kXmpNamespace) {
    offset = kXmpNamespace.size();
    if (offset < xmp->data_sz && bytes[offset] == '\0') ++offset;
  }
  return std::string(bytes + offset, xmp->data_sz - offset);
}

static uhdr_gainmap_metadata_t makeTestGainmapMetadata() {
  uhdr_gainmap_metadata_t metadata{};
  for (int channel = 0; channel < 3; ++channel) {
    metadata.max_content_boost[channel] = 2.0f;
    metadata.min_content_boost[channel] = 1.0f;
    metadata.gamma[channel] = 1.0f;
  }
  metadata.hdr_capacity_min = 1.0f;
  metadata.hdr_capacity_max = 2.0f;
  metadata.use_base_cg = 1;
  return metadata;
}

using EncoderPtr = std::unique_ptr<uhdr_codec_private_t, decltype(&uhdr_release_encoder)>;
using DecoderPtr = std::unique_ptr<uhdr_codec_private_t, decltype(&uhdr_release_decoder)>;

static EncoderPtr makeEncoder() {
  return EncoderPtr(uhdr_create_encoder(), &uhdr_release_encoder);
}

static DecoderPtr makeDecoder() {
  return DecoderPtr(uhdr_create_decoder(), &uhdr_release_decoder);
}

// Configures the API-4 inputs used by the focused JPEG XMP tests. The XMP block is optional when
// an API-4 re-encode should reuse XMP embedded in its compressed base image.
static uhdr_error_info_t configureJpegGainmapEncoder(uhdr_codec_private_t* encoder,
                                                     uhdr_compressed_image_t* base_image,
                                                     uhdr_compressed_image_t* gainmap_image,
                                                     uhdr_gainmap_metadata_t* metadata,
                                                     uhdr_mem_block_t* xmp) {
  uhdr_error_info_t status =
      uhdr_enc_set_compressed_image(encoder, base_image, UHDR_BASE_IMG);
  if (status.error_code != UHDR_CODEC_OK) return status;
  status = uhdr_enc_set_gainmap_image(encoder, gainmap_image, metadata);
  if (status.error_code != UHDR_CODEC_OK) return status;
  if (xmp != nullptr) {
    status = uhdr_enc_set_xmp_data(encoder, xmp);
    if (status.error_code != UHDR_CODEC_OK) return status;
  }
  return uhdr_enc_set_output_format(encoder, UHDR_CODEC_JPG);
}

struct JpegXmpRoundTrip {
  EncoderPtr encoder;
  DecoderPtr decoder;

  JpegXmpRoundTrip()
      : encoder(nullptr, &uhdr_release_encoder), decoder(nullptr, &uhdr_release_decoder) {}
};

static testing::AssertionResult encodeAndProbeJpegXmp(
    uhdr_compressed_image_t* base_image, uhdr_compressed_image_t* gainmap_image,
    uhdr_gainmap_metadata_t* metadata, uhdr_mem_block_t* xmp, JpegXmpRoundTrip& round_trip) {
  round_trip.encoder = makeEncoder();
  if (round_trip.encoder == nullptr) {
    return testing::AssertionFailure() << "uhdr_create_encoder returned nullptr";
  }

  const uhdr_error_info_t setup_status = configureJpegGainmapEncoder(
      round_trip.encoder.get(), base_image, gainmap_image, metadata, xmp);
  if (setup_status.error_code != UHDR_CODEC_OK) {
    return testing::AssertionFailure() << "JPEG XMP encoder setup failed: "
                                       << setup_status.detail;
  }

  const uhdr_error_info_t encode_status = uhdr_encode(round_trip.encoder.get());
  if (encode_status.error_code != UHDR_CODEC_OK) {
    return testing::AssertionFailure() << "JPEG XMP encode failed: " << encode_status.detail;
  }
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(round_trip.encoder.get());
  if (output == nullptr) {
    return testing::AssertionFailure() << "uhdr_get_encoded_stream returned nullptr";
  }

  round_trip.decoder = makeDecoder();
  if (round_trip.decoder == nullptr) {
    return testing::AssertionFailure() << "uhdr_create_decoder returned nullptr";
  }
  uhdr_error_info_t probe_status = uhdr_dec_set_image(round_trip.decoder.get(), output);
  if (probe_status.error_code != UHDR_CODEC_OK) {
    return testing::AssertionFailure() << "JPEG XMP decoder setup failed: "
                                       << probe_status.detail;
  }
  probe_status = uhdr_dec_probe(round_trip.decoder.get());
  if (probe_status.error_code != UHDR_CODEC_OK) {
    return testing::AssertionFailure() << "JPEG XMP probe failed: " << probe_status.detail;
  }
  return testing::AssertionSuccess();
}

#if defined(UHDR_WRITE_XMP)
struct ContainerDirectoryInfo {
  bool parsed = false;
  size_t directory_count = 0;
  std::vector<size_t> gainmap_lengths;
};

class ContainerDirectoryHandler : public photos_editing_formats::image_io::XmlHandler {
 public:
  photos_editing_formats::image_io::DataMatchResult StartElement(
      const photos_editing_formats::image_io::XmlTokenContext& context) override {
    std::string name;
    if (context.BuildTokenValue(&name)) {
      element_stack_.push_back(name);
      current_attribute_.clear();
      if (name == "Container:Directory") ++directory_count_;
      if (name == "Container:Item") {
        current_item_is_gainmap_ = false;
        current_item_length_.reset();
      }
    }
    return context.GetResult();
  }

  photos_editing_formats::image_io::DataMatchResult AttributeName(
      const photos_editing_formats::image_io::XmlTokenContext& context) override {
    context.BuildTokenValue(&current_attribute_);
    return context.GetResult();
  }

  photos_editing_formats::image_io::DataMatchResult AttributeValue(
      const photos_editing_formats::image_io::XmlTokenContext& context) override {
    std::string value;
    if (context.BuildTokenValue(&value, true) && !element_stack_.empty() &&
        element_stack_.back() == "Container:Item") {
      if (current_attribute_ == "Item:Semantic") {
        current_item_is_gainmap_ = value == "GainMap";
      } else if (current_attribute_ == "Item:Length") {
        size_t parsed = 0;
        const auto parse_result =
            std::from_chars(value.data(), value.data() + value.size(), parsed);
        if (parse_result.ec == std::errc() && parse_result.ptr == value.data() + value.size()) {
          current_item_length_ = parsed;
        } else {
          current_item_length_.reset();
        }
      }
    }
    return context.GetResult();
  }

  photos_editing_formats::image_io::DataMatchResult FinishElement(
      const photos_editing_formats::image_io::XmlTokenContext& context) override {
    if (!element_stack_.empty()) {
      if (element_stack_.back() == "Container:Item" && current_item_is_gainmap_ &&
          current_item_length_.has_value()) {
        gainmap_lengths_.push_back(*current_item_length_);
      }
      element_stack_.pop_back();
    }
    current_attribute_.clear();
    return context.GetResult();
  }

  size_t directoryCount() const { return directory_count_; }
  const std::vector<size_t>& gainmapLengths() const { return gainmap_lengths_; }

 private:
  std::vector<std::string> element_stack_;
  std::string current_attribute_;
  bool current_item_is_gainmap_ = false;
  std::optional<size_t> current_item_length_;
  size_t directory_count_ = 0;
  std::vector<size_t> gainmap_lengths_;
};

static ContainerDirectoryInfo getContainerDirectoryInfo(std::string_view xmp) {
  ContainerDirectoryInfo info;
  ContainerDirectoryHandler handler;
  photos_editing_formats::image_io::MessageHandler messages;
  photos_editing_formats::image_io::XmlReader reader(&handler, &messages);
  if (!reader.StartParse(std::make_unique<photos_editing_formats::image_io::XmlElementRule>()) ||
      !reader.Parse(std::string("<test>") + std::string(xmp) + "</test>") ||
      !reader.FinishParse() || reader.HasErrors()) {
    return info;
  }
  info.parsed = true;
  info.directory_count = handler.directoryCount();
  info.gainmap_lengths = handler.gainmapLengths();
  return info;
}
#endif

static void expectEncodedXmpDecodes(uhdr_compressed_image_t* output, size_t min_xmp_size) {
  ASSERT_NE(output, nullptr);
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  ASSERT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(dec);
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  EXPECT_GE(decoded_xmp->data_sz, min_xmp_size);
  ASSERT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);
  uhdr_release_decoder(dec);
}

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

#if defined(UHDR_WRITE_XMP)
TEST_F(UltraHdrApiTest, JpegApi4ExplicitXmpPreservesRdfNamespacePrefixes) {
  struct PrefixControl {
    const char* name;
    const char* packet;
  };
  const PrefixControl controls[] = {
      {"conventional",
       "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
       "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
       "rdf:about=\"\" xmlns:ex=\"urn:test\"><ex:Probe>semantic-probe</ex:Probe>"
       "<ex:Unrelated>keep-unrelated</ex:Unrelated></rdf:Description></rdf:RDF>"
       "</x:xmpmeta>"},
      {"alias",
       "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><r:RDF "
       "xmlns:r=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><r:Description "
       "r:about=\"\" xmlns:ex=\"urn:test\"><ex:Probe>semantic-probe</ex:Probe>"
       "<ex:Unrelated>keep-unrelated</ex:Unrelated></r:Description></r:RDF>"
       "</x:xmpmeta>"},
      {"default-rdf",
       "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><RDF "
       "xmlns=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" xmlns:r=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><Description "
       "r:about=\"\" xmlns:ex=\"urn:test\"><ex:Probe>semantic-probe</ex:Probe>"
       "<ex:Unrelated>keep-unrelated</ex:Unrelated></Description></RDF>"
       "</x:xmpmeta>"},
  };

  for (const PrefixControl& control : controls) {
    SCOPED_TRACE(control.name);
    uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
    uhdr_mem_block_t xmp_block{const_cast<char*>(control.packet), strlen(control.packet),
                               strlen(control.packet)};
    JpegXmpRoundTrip round_trip;
    ASSERT_TRUE(encodeAndProbeJpegXmp(&mSdrCompressed, &mSdrCompressed, &metadata, &xmp_block,
                                      round_trip));
    uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(round_trip.decoder.get());
    ASSERT_NE(decoded_xmp, nullptr);
    ASSERT_NE(decoded_xmp->data, nullptr);
    const std::string decoded_packet = getXmpPacket(decoded_xmp);
    const ContainerDirectoryInfo directory_info = getContainerDirectoryInfo(decoded_packet);
    ASSERT_TRUE(directory_info.parsed);
    EXPECT_EQ(directory_info.directory_count, 1u);
    const size_t generated_description = decoded_packet.rfind("<rdf:Description");
    ASSERT_NE(generated_description, std::string::npos);
    const size_t opening_end = decoded_packet.find('>', generated_description);
    ASSERT_NE(opening_end, std::string::npos);
    const std::string generated_opening =
        decoded_packet.substr(generated_description, opening_end - generated_description);
    EXPECT_NE(generated_opening.find(
                  "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\""),
              std::string::npos);
    EXPECT_NE(decoded_packet.find("semantic-probe"), std::string::npos);
    EXPECT_NE(decoded_packet.find("keep-unrelated"), std::string::npos);
  }
}

TEST_F(UltraHdrApiTest, JpegApi4XmpMergeReplacesVersionAttributeAndElement) {
  struct VersionForm {
    const char* name;
    const char* packet;
    const char* stale_value;
  };
  const VersionForm forms[] = {
      {"attribute",
       "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
       "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
       "rdf:about=\"\" xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\" "
       "hdrgm:Version=\"old-attribute\"/></rdf:RDF></x:xmpmeta>",
       "old-attribute"},
      {"element",
       "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
       "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
       "rdf:about=\"\" xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\">"
       "<hdrgm:Version>old-element</hdrgm:Version></rdf:Description></rdf:RDF>"
       "</x:xmpmeta>",
       "old-element"},
  };

  for (const VersionForm& form : forms) {
    SCOPED_TRACE(form.name);
    uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
    uhdr_mem_block_t xmp_block{const_cast<char*>(form.packet), strlen(form.packet),
                               strlen(form.packet)};
    JpegXmpRoundTrip round_trip;
    ASSERT_TRUE(encodeAndProbeJpegXmp(&mSdrCompressed, &mSdrCompressed, &metadata, &xmp_block,
                                      round_trip));
    uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(round_trip.decoder.get());
    ASSERT_NE(decoded_xmp, nullptr);
    ASSERT_NE(decoded_xmp->data, nullptr);
    const std::string decoded_packet = getXmpPacket(decoded_xmp);
    const ContainerDirectoryInfo directory_info = getContainerDirectoryInfo(decoded_packet);
    ASSERT_TRUE(directory_info.parsed);
    EXPECT_EQ(directory_info.directory_count, 1u);
    EXPECT_EQ(decoded_packet.find(form.stale_value), std::string::npos);
    EXPECT_NE(decoded_packet.find("hdrgm:Version=\"1.0\""), std::string::npos);
  }
}

TEST_F(UltraHdrApiTest, JpegApi4GetterSetterReencodeUsesSingleCurrentGainmapDirectory) {
  const std::string descriptive_seed =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
      "xmlns:c=\"http://ns.google.com/photos/1.0/container/\" "
      "xmlns:h=\"http://ns.adobe.com/hdr-gain-map/1.0/\" "
      "c:Directory=\"stale-container-attribute\" h:Version=\"stale-hdrgm-attribute\">"
      "<dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">retained-description"
      "</rdf:li></rdf:Alt></dc:description>"
      "<c:Directory>stale-container-element</c:Directory>"
      "<h:Version>stale-hdrgm-element</h:Version>"
      "</rdf:Description></rdf:RDF></x:xmpmeta>";
  uhdr_mem_block_t descriptive_seed_block{const_cast<char*>(descriptive_seed.data()),
                                           descriptive_seed.size(), descriptive_seed.size()};
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  JpegXmpRoundTrip first_round_trip;
  ASSERT_TRUE(encodeAndProbeJpegXmp(&mSdrCompressed, &mSdrCompressed, &metadata,
                                     &descriptive_seed_block, first_round_trip));
  uhdr_mem_block_t* first_xmp = uhdr_dec_get_xmp(first_round_trip.decoder.get());
  ASSERT_NE(first_xmp, nullptr);
  ASSERT_NE(first_xmp->data, nullptr);
  uhdr_mem_block_t* first_base = uhdr_dec_get_base_image(first_round_trip.decoder.get());
  ASSERT_NE(first_base, nullptr);
  uhdr_mem_block_t* first_gainmap = uhdr_dec_get_gainmap_image(first_round_trip.decoder.get());
  ASSERT_NE(first_gainmap, nullptr);
  ASSERT_NE(first_gainmap->data, nullptr);
  const std::string first_packet = getXmpPacket(first_xmp);
  ASSERT_FALSE(first_packet.empty());
  const char* stale_sentinels[] = {
      "stale-container-attribute", "stale-container-element", "stale-hdrgm-attribute",
      "stale-hdrgm-element",
  };

  auto checkOutput = [&](JpegXmpRoundTrip& round_trip, bool expect_changed_gainmap,
                         const char* expected_description, const char* absent_description,
                         std::string* packet_out) {
    uhdr_mem_block_t* output_gainmap = uhdr_dec_get_gainmap_image(round_trip.decoder.get());
    ASSERT_NE(output_gainmap, nullptr);
    ASSERT_NE(output_gainmap->data, nullptr);
    if (expect_changed_gainmap) {
      EXPECT_NE(output_gainmap->data_sz, first_gainmap->data_sz);
    }

    uhdr_mem_block_t* output_xmp = uhdr_dec_get_xmp(round_trip.decoder.get());
    ASSERT_NE(output_xmp, nullptr);
    ASSERT_NE(output_xmp->data, nullptr);
    const std::string output_packet = getXmpPacket(output_xmp);
    ASSERT_FALSE(output_packet.empty());
    EXPECT_NE(output_packet.find(expected_description), std::string::npos);
    if (absent_description != nullptr) {
      EXPECT_EQ(output_packet.find(absent_description), std::string::npos);
    }
    for (const char* stale : stale_sentinels) {
      EXPECT_EQ(output_packet.find(stale), std::string::npos) << stale;
    }

    const ContainerDirectoryInfo directory_info = getContainerDirectoryInfo(output_packet);
    ASSERT_TRUE(directory_info.parsed);
    EXPECT_EQ(directory_info.directory_count, 1u);
    ASSERT_EQ(directory_info.gainmap_lengths.size(), 1u);
    EXPECT_EQ(directory_info.gainmap_lengths.front(), output_gainmap->data_sz);
    ASSERT_EQ(uhdr_decode(round_trip.decoder.get()).error_code, UHDR_CODEC_OK);
    if (packet_out != nullptr) *packet_out = output_packet;
  };

  uhdr_gainmap_metadata_t* decoded_metadata =
      uhdr_dec_get_gainmap_metadata(first_round_trip.decoder.get());
  ASSERT_NE(decoded_metadata, nullptr);
  checkOutput(first_round_trip, false, "retained-description", nullptr, nullptr);

  JpegEncoderHelper changed_gainmap_encoder;
  ASSERT_EQ(changed_gainmap_encoder.compressImage(&mSdrRaw, 50, nullptr, 0).error_code,
            UHDR_CODEC_OK);
  uhdr_compressed_image_t changed_gainmap = changed_gainmap_encoder.getCompressedImage();
  ASSERT_NE(changed_gainmap.data, nullptr);
  ASSERT_NE(changed_gainmap.data_sz, first_gainmap->data_sz);

  uhdr_compressed_image_t base_input{
      first_base->data, first_base->data_sz, first_base->capacity, UHDR_CG_BT_709, UHDR_CT_SRGB,
      UHDR_CR_FULL_RANGE};
  uhdr_compressed_image_t gainmap_input = changed_gainmap;

  const std::string xpacket_wrapped =
      "<?xpacket begin=\"\xef\xbb\xbf\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n" + first_packet +
      "\n<?xpacket end=\"w\"?>";
  const std::string raw_getter(static_cast<const char*>(first_xmp->data), first_xmp->data_sz);
  const std::string replacement_xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:description>"
      "replacement-description</dc:description></rdf:Description></rdf:RDF></x:xmpmeta>";
  struct ReencodeControl {
    const char* name;
    const std::string* xmp;
    const char* expected_description;
    const char* absent_description;
    bool expect_xpacket_wrapper;
  };
  const ReencodeControl controls[] = {
      {"raw getter bytes", &raw_getter, "retained-description", nullptr, false},
      {"xpacket wrapped XML", &xpacket_wrapped, "retained-description", nullptr, true},
      {"no XMP setter", nullptr, "retained-description", nullptr, false},
      {"explicit replacement", &replacement_xmp, "replacement-description",
       "retained-description", false},
  };
  for (const ReencodeControl& control : controls) {
    SCOPED_TRACE(control.name);
    uhdr_mem_block_t xmp_input{};
    if (control.xmp != nullptr) {
      xmp_input = {const_cast<char*>(control.xmp->data()), control.xmp->size(),
                   control.xmp->size()};
    }
    JpegXmpRoundTrip second_round_trip;
    ASSERT_TRUE(encodeAndProbeJpegXmp(&base_input, &gainmap_input, decoded_metadata,
                                      control.xmp != nullptr ? &xmp_input : nullptr,
                                      second_round_trip));
    std::string second_packet;
    checkOutput(second_round_trip, true, control.expected_description,
                control.absent_description, &second_packet);
    if (control.expect_xpacket_wrapper) {
      EXPECT_NE(second_packet.find(
                    "<?xpacket begin=\"\xef\xbb\xbf\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>"),
                std::string::npos);
      EXPECT_NE(second_packet.find("<?xpacket end=\"w\"?>"), std::string::npos);
    }
  }
}

TEST_F(UltraHdrApiTest, JpegApi4XmpMergeIgnoresFakeRdfClosersInCommentsAndCdata) {
  const std::string user_xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:ex=\"urn:test\"><ex:Probe>semantic-probe</ex:Probe>"
      "<ex:Unrelated><![CDATA[keep-cdata </rdf:RDF>]]></ex:Unrelated>"
      "</rdf:Description></rdf:RDF><!-- keep-comment </rdf:RDF> -->"
      "</x:xmpmeta>";

  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  uhdr_mem_block_t xmp_block{const_cast<char*>(user_xmp.data()), user_xmp.size(), user_xmp.size()};
  JpegXmpRoundTrip round_trip;
  ASSERT_TRUE(encodeAndProbeJpegXmp(&mSdrCompressed, &mSdrCompressed, &metadata, &xmp_block,
                                    round_trip));
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(round_trip.decoder.get());
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  const std::string decoded_packet = getXmpPacket(decoded_xmp);
  const ContainerDirectoryInfo directory_info = getContainerDirectoryInfo(decoded_packet);
  ASSERT_TRUE(directory_info.parsed);
  EXPECT_EQ(directory_info.directory_count, 1u);
  EXPECT_NE(decoded_packet.find("semantic-probe"), std::string::npos);
  EXPECT_NE(decoded_packet.find("<![CDATA[keep-cdata </rdf:RDF>]]>"), std::string::npos);
  EXPECT_NE(decoded_packet.find("<!-- keep-comment </rdf:RDF> -->"), std::string::npos);
  ASSERT_EQ(directory_info.gainmap_lengths.size(), 1u);
  uhdr_mem_block_t* decoded_gainmap = uhdr_dec_get_gainmap_image(round_trip.decoder.get());
  ASSERT_NE(decoded_gainmap, nullptr);
  ASSERT_NE(decoded_gainmap->data, nullptr);
  EXPECT_EQ(directory_info.gainmap_lengths.front(), decoded_gainmap->data_sz);
}

TEST_F(UltraHdrApiTest, JpegApi4XmpMergeKeepsOwnedPropertiesOnNodeIdDescription) {
  const std::string user_xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:ID=\"other-id\" xmlns:Container=\"http://ns.google.com/photos/1.0/container/\">"
      "<Container:Directory>keep-id-directory</Container:Directory></rdf:Description>"
      "<rdf:Description rdf:nodeID=\"other-resource\" xmlns:Container=\"http://ns.google.com/photos/1.0/container/\">"
      "<Container:Directory>keep-node-directory</Container:Directory>"
      "</rdf:Description><rdf:Description rdf:about=\"\" xmlns:ex=\"urn:test\">"
      "<ex:Probe>primary-probe</ex:Probe></rdf:Description></rdf:RDF></x:xmpmeta>";

  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  uhdr_mem_block_t xmp_block{const_cast<char*>(user_xmp.data()), user_xmp.size(), user_xmp.size()};
  JpegXmpRoundTrip round_trip;
  ASSERT_TRUE(encodeAndProbeJpegXmp(&mSdrCompressed, &mSdrCompressed, &metadata, &xmp_block,
                                    round_trip));
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(round_trip.decoder.get());
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  const std::string decoded_packet = getXmpPacket(decoded_xmp);
  EXPECT_NE(decoded_packet.find("keep-id-directory"), std::string::npos);
  EXPECT_NE(decoded_packet.find("keep-node-directory"), std::string::npos);
  EXPECT_NE(decoded_packet.find("primary-probe"), std::string::npos);
}

TEST_F(UltraHdrApiTest, JpegApi4RejectsMalformedOrUnmergeableXmp) {
  const char* packets[] = {
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description>",
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description>"
      "</rdf:Other></rdf:RDF></x:xmpmeta>",
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><ex:Metadata xmlns:ex=\"urn:test\">"
      "<ex:Probe>unmergeable</ex:Probe></ex:Metadata></x:xmpmeta>",
  };

  for (const char* packet : packets) {
    SCOPED_TRACE(packet);
    EncoderPtr enc = makeEncoder();
    ASSERT_NE(enc, nullptr);
    uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
    uhdr_mem_block_t xmp_block{const_cast<char*>(packet), strlen(packet), strlen(packet)};
    const uhdr_error_info_t setup_status = configureJpegGainmapEncoder(
        enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata, &xmp_block);
    ASSERT_EQ(setup_status.error_code, UHDR_CODEC_OK) << setup_status.detail;
    const uhdr_error_info_t status = uhdr_encode(enc.get());
    EXPECT_EQ(status.error_code, UHDR_CODEC_INVALID_PARAM) << status.detail;
  }
}
#endif

#if !defined(UHDR_WRITE_XMP) && defined(UHDR_WRITE_ISO)
TEST_F(UltraHdrApiTest, JpegApi4IsoOnlyPassesThroughXmpExactly) {
  const std::string user_xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:ex=\"urn:test\"><ex:Probe>iso-passthrough</ex:Probe>"
      "</rdf:Description></rdf:RDF></x:xmpmeta>";
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  uhdr_mem_block_t xmp_block{const_cast<char*>(user_xmp.data()), user_xmp.size(), user_xmp.size()};
  JpegXmpRoundTrip round_trip;
  ASSERT_TRUE(encodeAndProbeJpegXmp(&mSdrCompressed, &mSdrCompressed, &metadata, &xmp_block,
                                    round_trip));
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(round_trip.decoder.get());
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  EXPECT_EQ(getXmpPacket(decoded_xmp), user_xmp);
}
#endif

TEST_F(UltraHdrApiTest, JpegEncodeWithXmpAndDecode) {
  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);

  EXPECT_EQ(uhdr_enc_set_raw_image(enc, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_BASE_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_quality(enc, 85, UHDR_GAIN_MAP_IMG).error_code, UHDR_CODEC_OK);

  const std::string kUserXmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.1.2\">\n"
      "  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
      "    <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n"
      "      <dc:creator>\n"
      "        <rdf:Seq>\n"
      "          <rdf:li>Greg Benz</rdf:li>\n"
      "        </rdf:Seq>\n"
      "      </dc:creator>\n"
      "      <dc:rights>\n"
      "        <rdf:Alt>\n"
      "          <rdf:li xml:lang=\"x-default\">Copyright 2026 Greg Benz</rdf:li>\n"
      "        </rdf:Alt>\n"
      "      </dc:rights>\n"
      "    </rdf:Description>\n"
      "  </rdf:RDF>\n"
      "</x:xmpmeta>\n";

  uhdr_mem_block_t xmp_block{};
  xmp_block.data = const_cast<char*>(kUserXmp.data());
  xmp_block.data_sz = xmp_block.capacity = kUserXmp.size();

  EXPECT_EQ(uhdr_enc_set_xmp_data(enc, &xmp_block).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  ASSERT_GT(output->data_sz, 0u);

  // Decode and verify XMP preservation
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);

  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(dec);
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  ASSERT_GT(decoded_xmp->data_sz, 0u);

  std::string decoded_xmp_str(static_cast<const char*>(decoded_xmp->data), decoded_xmp->data_sz);

  // Verify that user custom metadata was preserved
  EXPECT_NE(decoded_xmp_str.find("Greg Benz"), std::string::npos);
  EXPECT_NE(decoded_xmp_str.find("Copyright 2026 Greg Benz"), std::string::npos);

  // Verify gain map metadata was decoded and valid
  uhdr_gainmap_metadata_t* gm_meta = uhdr_dec_get_gainmap_metadata(dec);
  ASSERT_NE(gm_meta, nullptr);

  EXPECT_EQ(uhdr_decode(dec).error_code, UHDR_CODEC_OK);

  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, JpegEncodeApi2WithXmpAndDecode) {
  // First, produce a base JPEG that carries XMP
  uhdr_codec_private_t* enc1 = uhdr_create_encoder();
  ASSERT_NE(enc1, nullptr);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc1, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc1, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  const std::string kUserXmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n"
      "  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
      "    <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\n"
      "      <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">Base Image With XMP</rdf:li></rdf:Alt></dc:title>\n"
      "    </rdf:Description>\n"
      "  </rdf:RDF>\n"
      "</x:xmpmeta>\n";

  uhdr_mem_block_t xmp_block{};
  xmp_block.data = const_cast<char*>(kUserXmp.data());
  xmp_block.data_sz = xmp_block.capacity = kUserXmp.size();
  EXPECT_EQ(uhdr_enc_set_xmp_data(enc1, &xmp_block).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc1).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* enc1_out = uhdr_get_encoded_stream(enc1);
  ASSERT_NE(enc1_out, nullptr);

  // Probe and extract the base image with its embedded XMP
  uhdr_codec_private_t* dec1 = uhdr_create_decoder();
  ASSERT_NE(dec1, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec1, enc1_out).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec1).error_code, UHDR_CODEC_OK);
  uhdr_mem_block_t* base_img = uhdr_dec_get_base_image(dec1);
  ASSERT_NE(base_img, nullptr);

  uhdr_compressed_image_t sdr_compressed_with_xmp{};
  sdr_compressed_with_xmp.data = base_img->data;
  sdr_compressed_with_xmp.data_sz = base_img->data_sz;
  sdr_compressed_with_xmp.capacity = base_img->capacity;
  sdr_compressed_with_xmp.cg = UHDR_CG_DISPLAY_P3;
  sdr_compressed_with_xmp.ct = UHDR_CT_SRGB;
  sdr_compressed_with_xmp.range = UHDR_CR_FULL_RANGE;

  // Now use API-2 with this compressed SDR image carrying XMP, WITHOUT explicitly setting XMP
  uhdr_codec_private_t* enc2 = uhdr_create_encoder();
  ASSERT_NE(enc2, nullptr);
  EXPECT_EQ(uhdr_enc_set_raw_image(enc2, &mHdrRaw, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_compressed_image(enc2, &sdr_compressed_with_xmp, UHDR_SDR_IMG).error_code,
            UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_enc_set_output_format(enc2, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  ASSERT_EQ(uhdr_encode(enc2).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* enc2_out = uhdr_get_encoded_stream(enc2);
  ASSERT_NE(enc2_out, nullptr);

  // Decode and verify that the base image's XMP was preserved automatically
  uhdr_codec_private_t* dec2 = uhdr_create_decoder();
  ASSERT_NE(dec2, nullptr);
  EXPECT_EQ(uhdr_dec_set_image(dec2, enc2_out).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(uhdr_dec_probe(dec2).error_code, UHDR_CODEC_OK);

  uhdr_mem_block_t* dec2_xmp = uhdr_dec_get_xmp(dec2);
  ASSERT_NE(dec2_xmp, nullptr);
  std::string dec2_xmp_str(static_cast<const char*>(dec2_xmp->data), dec2_xmp->data_sz);
  EXPECT_NE(dec2_xmp_str.find("Base Image With XMP"), std::string::npos);

  uhdr_release_decoder(dec2);
  uhdr_release_encoder(enc2);
  uhdr_release_decoder(dec1);
  uhdr_release_encoder(enc1);
}

TEST_F(UltraHdrApiTest, LargeXmpFitsSmallRawApiOutput) {
#ifdef UHDR_WRITE_XMP
  // The dual writer adds its container directory to the supplied packet.
  constexpr size_t kXmpSize = 64000;
#else
  constexpr size_t kXmpSize = 65504;
#endif
  const std::vector<uint8_t> hdr_data = makeSmallHdrData();
  uhdr_raw_image_t hdr{};
  hdr.fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
  hdr.cg = UHDR_CG_DISPLAY_P3;
  hdr.ct = UHDR_CT_LINEAR;
  hdr.range = UHDR_CR_FULL_RANGE;
  hdr.w = hdr.h = 8;
  hdr.planes[UHDR_PLANE_PACKED] = const_cast<uint8_t*>(hdr_data.data());
  hdr.stride[UHDR_PLANE_PACKED] = 8;

  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  ASSERT_EQ(uhdr_enc_set_raw_image(enc, &hdr, UHDR_HDR_IMG).error_code, UHDR_CODEC_OK);
  const std::string xmp = makeLargeXmp(kXmpSize);
  uhdr_mem_block_t xmp_block{const_cast<char*>(xmp.data()), xmp.size(), xmp.size()};
  ASSERT_EQ(uhdr_enc_set_xmp_data(enc, &xmp_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  const uhdr_error_info_t status = uhdr_encode(enc);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  EXPECT_GT(output->data_sz, static_cast<size_t>(64 * 1024));
  expectEncodedXmpDecodes(output, kXmpSize);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, LargeXmpFitsCompressedBaseGainmapApiOutput) {
#ifdef UHDR_WRITE_XMP
  constexpr size_t kXmpSize = 64000;
#else
  constexpr size_t kXmpSize = 65504;
#endif
  uhdr_gainmap_metadata_t metadata{};
  for (int channel = 0; channel < 3; ++channel) {
    metadata.max_content_boost[channel] = 2.0f;
    metadata.min_content_boost[channel] = 1.0f;
    metadata.gamma[channel] = 1.0f;
  }
  metadata.hdr_capacity_min = 1.0f;
  metadata.hdr_capacity_max = 2.0f;
  metadata.use_base_cg = 1;

  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  ASSERT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_BASE_IMG).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_gainmap_image(enc, &mSdrCompressed, &metadata).error_code,
            UHDR_CODEC_OK);
  const std::string xmp = makeLargeXmp(kXmpSize);
  uhdr_mem_block_t xmp_block{const_cast<char*>(xmp.data()), xmp.size(), xmp.size()};
  ASSERT_EQ(uhdr_enc_set_xmp_data(enc, &xmp_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  const uhdr_error_info_t status = uhdr_encode(enc);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  EXPECT_GT(output->data_sz, static_cast<size_t>(64 * 1024));
  expectEncodedXmpDecodes(output, kXmpSize);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, OversizedFinalXmpIsRejected) {
  uhdr_gainmap_metadata_t metadata{};
  for (int channel = 0; channel < 3; ++channel) {
    metadata.max_content_boost[channel] = 2.0f;
    metadata.min_content_boost[channel] = 1.0f;
    metadata.gamma[channel] = 1.0f;
  }
  metadata.hdr_capacity_min = 1.0f;
  metadata.hdr_capacity_max = 2.0f;
  metadata.use_base_cg = 1;

  uhdr_codec_private_t* enc = uhdr_create_encoder();
  ASSERT_NE(enc, nullptr);
  ASSERT_EQ(uhdr_enc_set_compressed_image(enc, &mSdrCompressed, UHDR_BASE_IMG).error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_gainmap_image(enc, &mSdrCompressed, &metadata).error_code,
            UHDR_CODEC_OK);
#ifdef UHDR_WRITE_XMP
  const std::string xmp = makeLargeXmp(65504);
#else
  const std::string xmp = makeLargeXmp(65505);
#endif
  uhdr_mem_block_t xmp_block{const_cast<char*>(xmp.data()), xmp.size(), xmp.size()};
  ASSERT_EQ(uhdr_enc_set_xmp_data(enc, &xmp_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  const uhdr_error_info_t status = uhdr_encode(enc);
  EXPECT_NE(status.error_code, UHDR_CODEC_OK);
  EXPECT_TRUE(status.has_detail);
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
