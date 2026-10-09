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
#include "ultrahdr/jpegrutils.h"
#include "ultrahdr/jpegdecoderhelper.h"
#include "ultrahdr/jpegencoderhelper.h"
#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/gainmapmetadata.h"
#include "ultrahdr/heifultrahdr.h"
#include "ultrahdr/avifultrahdr.h"
#if defined(UHDR_ENABLE_HEIF)
#include "libheif/heif.h"
#endif
#include "image_io/base/message_handler.h"
#include "image_io/xml/xml_element_rules.h"
#include "image_io/xml/xml_handler.h"
#include "image_io/xml/xml_reader.h"

namespace ultrahdr {

static const char* kYCbCrP010FileName = "raw_p010_image.p010";
static const char* kYCbCr420FileName = "raw_yuv420_image.yuv420";
static const char* kSdrJpgFileName = "jpeg_image.jpg";
static const char* kHevcGainmapFileName = "gainmap_hevc_16x16.heic";
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

static std::vector<uint8_t> extractPrimaryScanBytes(const void* stream_data, size_t stream_size) {
  const auto* data = static_cast<const uint8_t*>(stream_data);
  if (data == nullptr || stream_size < 4 || data[0] != 0xFF || data[1] != 0xD8) return {};
  size_t pos = 2;
  while (pos + 4 <= stream_size) {
    if (data[pos] != 0xFF) return {};
    while (pos < stream_size && data[pos] == 0xFF) ++pos;
    if (pos >= stream_size) return {};
    uint8_t marker = data[pos++];
    if (marker == 0xD9) return {};
    if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) continue;
    if (pos + 2 > stream_size) return {};
    size_t seg_len = (static_cast<size_t>(data[pos]) << 8) | data[pos + 1];
    if (seg_len < 2 || pos + seg_len > stream_size) return {};
    size_t marker_begin = pos - 2;
    pos += seg_len;
    if (marker == 0xDA) {
      size_t scan_end = pos;
      while (scan_end < stream_size) {
        if (data[scan_end] != 0xFF) {
          ++scan_end;
          continue;
        }
        size_t ff_pos = scan_end;
        while (scan_end < stream_size && data[scan_end] == 0xFF) ++scan_end;
        if (scan_end >= stream_size) return {};
        uint8_t next_marker = data[scan_end];
        if (next_marker == 0x00 || (next_marker >= 0xD0 && next_marker <= 0xD7)) {
          ++scan_end;
          continue;
        }
        return std::vector<uint8_t>(data + marker_begin, data + ff_pos);
      }
      return {};
    }
  }
  return {};
}

struct JpegSegmentSpan {
  size_t begin;
  size_t end;
  size_t payload_begin;
  size_t payload_size;
};

static std::vector<JpegSegmentSpan> findApp1Segments(const std::vector<uint8_t>& jpeg,
                                                     std::string_view signature) {
  std::vector<JpegSegmentSpan> segments;
  if (jpeg.size() < 4 || jpeg[0] != 0xFF || jpeg[1] != 0xD8) return segments;
  size_t pos = 2;
  while (pos + 4 <= jpeg.size() && jpeg[pos] == 0xFF) {
    const size_t marker_begin = pos;
    while (pos < jpeg.size() && jpeg[pos] == 0xFF) ++pos;
    if (pos == jpeg.size()) break;
    const uint8_t marker = jpeg[pos++];
    if (marker == 0xD9 || marker == 0xDA) break;
    if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD8)) continue;
    if (pos + 2 > jpeg.size()) break;
    const size_t length = (static_cast<size_t>(jpeg[pos]) << 8) | jpeg[pos + 1];
    if (length < 2 || pos + length > jpeg.size()) break;
    const size_t payload_begin = pos + 2;
    const size_t payload_size = length - 2;
    if (marker == 0xE1 && payload_size >= signature.size() + 1 &&
        std::string_view(reinterpret_cast<const char*>(jpeg.data() + payload_begin),
                         signature.size()) == signature &&
        jpeg[payload_begin + signature.size()] == 0) {
      segments.push_back({marker_begin, pos + length, payload_begin, payload_size});
    }
    pos += length;
  }
  return segments;
}

static std::vector<JpegSegmentSpan> findExtendedXmpSegments(const std::vector<uint8_t>& jpeg) {
  return findApp1Segments(jpeg, "http://ns.adobe.com/xmp/extension/");
}

static uint32_t readBigEndian32(const std::vector<uint8_t>& bytes, size_t offset) {
  return (static_cast<uint32_t>(bytes[offset]) << 24) |
         (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
         (static_cast<uint32_t>(bytes[offset + 2]) << 8) | bytes[offset + 3];
}

static void writeBigEndian32(std::vector<uint8_t>* bytes, size_t offset, uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    (*bytes)[offset++] = static_cast<uint8_t>((value >> shift) & 0xFF);
  }
}

static bool reverseExtendedXmpSegments(std::vector<uint8_t>* jpeg) {
  const std::vector<JpegSegmentSpan> segments = findExtendedXmpSegments(*jpeg);
  if (segments.size() < 2) return false;
  for (size_t index = 1; index < segments.size(); ++index) {
    if (segments[index - 1].end != segments[index].begin) return false;
  }
  std::vector<uint8_t> reordered(jpeg->begin(), jpeg->begin() + segments.front().begin);
  for (auto segment = segments.rbegin(); segment != segments.rend(); ++segment) {
    reordered.insert(reordered.end(), jpeg->begin() + segment->begin, jpeg->begin() + segment->end);
  }
  reordered.insert(reordered.end(), jpeg->begin() + segments.back().end, jpeg->end());
  *jpeg = std::move(reordered);
  return true;
}

static std::string makeLargeGainMapOnlyXmp(size_t size) {
  const std::string prefix =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\">"
      "<hdrgm:Version>";
  const std::string suffix = "</hdrgm:Version></rdf:Description></rdf:RDF></x:xmpmeta>";
  EXPECT_GE(size, prefix.size() + suffix.size());
  return prefix + std::string(size - prefix.size() - suffix.size(), '1') + suffix;
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

TEST_F(UltraHdrApiTest, StripGainMapPreservesPrimaryScanExifIccAndUserXmp) {
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);

  const std::string kExifPayload = "Exif\0\0II*\0\x08\0\0\0\0\0";
  uhdr_mem_block_t exif_block{const_cast<char*>(kExifPayload.data()), kExifPayload.size(),
                              kExifPayload.size()};

  const std::string kUserXmp =
      "<?xpacket begin=\"\xef\xbb\xbf\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n"
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.1.2\">\n"
      "  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n"
      "    <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
      "xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\">\n"
      "      <photoshop:AuthorsPosition>Photographer</photoshop:AuthorsPosition>\n"
      "      <dc:description>\n"
      "        <rdf:Alt>\n"
      "          <rdf:li xml:lang=\"x-default\">Lossless SDR export test</rdf:li>\n"
      "        </rdf:Alt>\n"
      "      </dc:description>\n"
      "    </rdf:Description>\n"
      "  </rdf:RDF>\n"
      "</x:xmpmeta>\n"
      "<?xpacket end=\"w\"?>";
  uhdr_mem_block_t xmp_block{const_cast<char*>(kUserXmp.data()), kUserXmp.size(), kUserXmp.size()};

  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        &xmp_block)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_exif_data(enc.get(), &exif_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);

  uhdr_compressed_image_t* uhdr_stream = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(uhdr_stream, nullptr);
  ASSERT_EQ(is_uhdr_image(uhdr_stream->data, static_cast<int>(uhdr_stream->data_sz)), 1);

  // 1. Query required output size via {nullptr, 0, 0}.
  uhdr_mem_block_t size_query{nullptr, 0, 0};
  ASSERT_EQ(uhdr_strip_gain_map(uhdr_stream, &size_query).error_code, UHDR_CODEC_OK);
  ASSERT_GT(size_query.data_sz, 0u);
  ASSERT_LT(size_query.data_sz, uhdr_stream->data_sz);

  // 2. Strip gain map into caller-owned buffer.
  std::vector<uint8_t> stripped_buf(size_query.data_sz);
  uhdr_mem_block_t stripped_block{stripped_buf.data(), 0, stripped_buf.size()};
  ASSERT_EQ(uhdr_strip_gain_map(uhdr_stream, &stripped_block).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(stripped_block.data_sz, size_query.data_sz);

  // 3. Stripped output is a clean standard SDR JPEG, not recognized as Ultra HDR.
  EXPECT_EQ(is_uhdr_image(stripped_block.data, static_cast<int>(stripped_block.data_sz)), 0);

  // 4. Primary entropy-coded scan data is preserved bit-for-bit (no DCT re-encoding).
  const std::vector<uint8_t> orig_scan =
      extractPrimaryScanBytes(uhdr_stream->data, uhdr_stream->data_sz);
  const std::vector<uint8_t> stripped_scan =
      extractPrimaryScanBytes(stripped_block.data, stripped_block.data_sz);
  ASSERT_FALSE(orig_scan.empty());
  EXPECT_EQ(orig_scan, stripped_scan);

  // 5. Verify Exif, ICC, ISO metadata removal, and user XMP via JpegDecoderHelper.
  JpegDecoderHelper orig_decoder;
  ASSERT_EQ(orig_decoder.parseImage(uhdr_stream->data, uhdr_stream->data_sz).error_code, UHDR_CODEC_OK);
  JpegDecoderHelper stripped_decoder;
  ASSERT_EQ(stripped_decoder.parseImage(stripped_block.data, stripped_block.data_sz).error_code, UHDR_CODEC_OK);

  EXPECT_EQ(stripped_decoder.getIsoMetadataSize(), 0u);
  ASSERT_EQ(stripped_decoder.getEXIFSize(), orig_decoder.getEXIFSize());
  EXPECT_EQ(memcmp(stripped_decoder.getEXIFPtr(), orig_decoder.getEXIFPtr(),
                   orig_decoder.getEXIFSize()),
            0);
  ASSERT_EQ(stripped_decoder.getICCSize(), orig_decoder.getICCSize());
  if (orig_decoder.getICCSize() > 0) {
    EXPECT_EQ(
        memcmp(stripped_decoder.getICCPtr(), orig_decoder.getICCPtr(), orig_decoder.getICCSize()),
        0);
  }

  ASSERT_NE(stripped_decoder.getXMPPtr(), nullptr);
  uhdr_mem_block_t stripped_xmp_mem{stripped_decoder.getXMPPtr(), stripped_decoder.getXMPSize(),
                                    stripped_decoder.getXMPSize()};
  const std::string stripped_xmp_str = getXmpPacket(&stripped_xmp_mem);
  EXPECT_EQ(stripped_xmp_str, kUserXmp);
  EXPECT_EQ(stripped_xmp_str.find("Container:Directory"), std::string::npos);
  EXPECT_EQ(stripped_xmp_str.find("hdrgm:"), std::string::npos);

  // 6. Verify idempotency when calling uhdr_strip_gain_map again on the stripped SDR JPEG.
  uhdr_compressed_image_t stripped_input{stripped_block.data, stripped_block.data_sz,
                                         stripped_block.capacity, UHDR_CG_BT_709, UHDR_CT_SRGB,
                                         UHDR_CR_FULL_RANGE};
  std::vector<uint8_t> second_buf(stripped_block.data_sz);
  uhdr_mem_block_t second_block{second_buf.data(), 0, second_buf.size()};
  ASSERT_EQ(uhdr_strip_gain_map(&stripped_input, &second_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(second_block.data_sz, stripped_block.data_sz);
  EXPECT_EQ(memcmp(second_block.data, stripped_block.data, stripped_block.data_sz), 0);
}

TEST_F(UltraHdrApiTest, StripGainMapDropsGeneratedOnlyXmpSegment) {
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        nullptr)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* uhdr_stream = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(uhdr_stream, nullptr);

  std::vector<uint8_t> stripped_buf(uhdr_stream->data_sz);
  uhdr_mem_block_t stripped_block{stripped_buf.data(), 0, stripped_buf.size()};
  ASSERT_EQ(uhdr_strip_gain_map(uhdr_stream, &stripped_block).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(is_uhdr_image(stripped_block.data, static_cast<int>(stripped_block.data_sz)), 0);

  JpegDecoderHelper stripped_decoder;
  ASSERT_EQ(stripped_decoder.parseImage(stripped_block.data, stripped_block.data_sz).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(stripped_decoder.getIsoMetadataSize(), 0u);
  EXPECT_EQ(stripped_decoder.getXMPSize(), 0u);
}

TEST_F(UltraHdrApiTest, StripGainMapPreservesSharedDescriptionAndExtendedXmp) {
  // Part 1: Shared <rdf:Description> containing both user properties and gain-map properties.
  const std::string shared_xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" "
      "xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\" "
      "xmlns:Container=\"http://ns.google.com/photos/1.0/container/\" "
      "xmlns:Item=\"http://ns.google.com/photos/1.0/container/item/\" "
      "dc:format=\"image/jpeg\" hdrgm:Version=\"1.0\" hdrgm:GainMapMax=\"2.5\">"
      "<dc:description>Shared description photo</dc:description>"
      "<Container:Directory><rdf:Seq><rdf:li rdf:parseType=\"Resource\">"
      "<Container:Item Item:Semantic=\"Primary\" Item:Mime=\"image/jpeg\"/></rdf:li>"
      "<rdf:li rdf:parseType=\"Resource\"><Container:Item Item:Semantic=\"GainMap\" "
      "Item:Mime=\"image/jpeg\" Item:Length=\"1024\"/></rdf:li></rdf:Seq>"
      "</Container:Directory></rdf:Description></rdf:RDF></x:xmpmeta>";
  std::string stripped_shared;
  ASSERT_TRUE(stripGainMapFromXmp(shared_xmp, &stripped_shared));
  EXPECT_NE(stripped_shared.find("dc:format=\"image/jpeg\""), std::string::npos);
  EXPECT_NE(stripped_shared.find("<dc:description>Shared description photo</dc:description>"),
            std::string::npos);
  EXPECT_EQ(stripped_shared.find("hdrgm:"), std::string::npos);
  EXPECT_EQ(stripped_shared.find("Container:"), std::string::npos);

  // Part 2: Multi-segment Extended XMP (> 64 KB) is stripped and relinked.
  std::string ext_xmp = makeLargeXmp(140000);
  const std::string about = "rdf:about=\"\"";
  const size_t about_pos = ext_xmp.find(about);
  ASSERT_NE(about_pos, std::string::npos);
  ext_xmp.insert(about_pos + about.size(),
                 " xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\" "
                 "hdrgm:Version=\"1.0\"");
  std::string expected_ext_xmp;
  ASSERT_TRUE(stripGainMapFromXmp(ext_xmp, &expected_ext_xmp));
  EXPECT_EQ(expected_ext_xmp.find("hdrgm:Version"), std::string::npos);
  EXPECT_NE(expected_ext_xmp.find("<dc:Pad"), std::string::npos);
  uhdr_mem_block_t ext_xmp_block{const_cast<char*>(ext_xmp.data()), ext_xmp.size(), ext_xmp.size()};
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        &ext_xmp_block)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* uhdr_stream = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(uhdr_stream, nullptr);

  std::vector<uint8_t> reordered_input(
      static_cast<const uint8_t*>(uhdr_stream->data),
      static_cast<const uint8_t*>(uhdr_stream->data) + uhdr_stream->data_sz);
  ASSERT_TRUE(reverseExtendedXmpSegments(&reordered_input));
  uhdr_compressed_image_t reordered_stream{reordered_input.data(), reordered_input.size(),
                                           reordered_input.size(), UHDR_CG_UNSPECIFIED,
                                           UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED};
  std::vector<uint8_t> stripped_buf(reordered_input.size());
  uhdr_mem_block_t stripped_block{stripped_buf.data(), 0, stripped_buf.size()};
  ASSERT_EQ(uhdr_strip_gain_map(&reordered_stream, &stripped_block).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(is_uhdr_image(stripped_block.data, static_cast<int>(stripped_block.data_sz)), 0);

  JpegDecoderHelper stripped_decoder;
  ASSERT_EQ(stripped_decoder.parseImage(stripped_block.data, stripped_block.data_sz).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(stripped_decoder.getXMPSize(), expected_ext_xmp.size());
  EXPECT_EQ(memcmp(stripped_decoder.getXMPPtr(), expected_ext_xmp.data(), expected_ext_xmp.size()), 0);
  const std::vector<uint8_t> stripped_jpeg(
      static_cast<const uint8_t*>(stripped_block.data),
      static_cast<const uint8_t*>(stripped_block.data) + stripped_block.data_sz);
  const std::vector<JpegSegmentSpan> standard_segments =
      findApp1Segments(stripped_jpeg, "http://ns.adobe.com/xap/1.0/");
  std::string linked_guid;
  for (const JpegSegmentSpan& segment : standard_segments) {
    constexpr std::string_view kStandardNamespace = "http://ns.adobe.com/xap/1.0/";
    const size_t xml_begin = segment.payload_begin + kStandardNamespace.size() + 1;
    const std::string standard_xml(
        reinterpret_cast<const char*>(stripped_jpeg.data() + xml_begin),
        segment.payload_size - kStandardNamespace.size() - 1);
    std::string segment_guid;
    ASSERT_TRUE(getExtendedXmpGuidFromXmp(standard_xml, &segment_guid));
    if (!segment_guid.empty()) {
      ASSERT_TRUE(linked_guid.empty());
      linked_guid = segment_guid;
    }
  }
  ASSERT_FALSE(linked_guid.empty());
  EXPECT_EQ(linked_guid,
            computeMd5Guid(reinterpret_cast<const uint8_t*>(expected_ext_xmp.data()),
                           expected_ext_xmp.size()));
}

TEST_F(UltraHdrApiTest, StripGainMapLeavesUserOnlyExtendedXmpChunksUnchanged) {
  const std::string user_xmp = makeLargeXmp(140000);
  uhdr_mem_block_t xmp_block{const_cast<char*>(user_xmp.data()), user_xmp.size(), user_xmp.size()};
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        &xmp_block)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* encoded = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(encoded, nullptr);
  std::vector<uint8_t> original(static_cast<const uint8_t*>(encoded->data),
                                static_cast<const uint8_t*>(encoded->data) + encoded->data_sz);
  const std::vector<JpegSegmentSpan> original_segments = findExtendedXmpSegments(original);
  ASSERT_GE(original_segments.size(), 2u);

  uhdr_compressed_image_t input{original.data(), original.size(), original.size(),
                                UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,
                                UHDR_CR_UNSPECIFIED};
  std::vector<uint8_t> output(original.size());
  uhdr_mem_block_t output_block{output.data(), 0, output.size()};
  ASSERT_EQ(uhdr_strip_gain_map(&input, &output_block).error_code, UHDR_CODEC_OK);
  output.resize(output_block.data_sz);
  const std::vector<JpegSegmentSpan> output_segments = findExtendedXmpSegments(output);
  ASSERT_EQ(output_segments.size(), original_segments.size());
  for (size_t index = 0; index < original_segments.size(); ++index) {
    const JpegSegmentSpan& before = original_segments[index];
    const JpegSegmentSpan& after = output_segments[index];
    ASSERT_EQ(before.end - before.begin, after.end - after.begin);
    EXPECT_EQ(std::memcmp(original.data() + before.begin, output.data() + after.begin,
                          before.end - before.begin),
              0);
  }
  JpegDecoderHelper decoder;
  ASSERT_EQ(decoder.parseImage(output.data(), output.size()).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(decoder.getXMPSize(), user_xmp.size());
  EXPECT_EQ(std::memcmp(decoder.getXMPPtr(), user_xmp.data(), user_xmp.size()), 0);
}

TEST_F(UltraHdrApiTest, StripGainMapRemovesEmptyLinkedExtendedXmp) {
  const std::string gainmap_only_xmp = makeLargeGainMapOnlyXmp(140000);
  std::string stripped_xmp;
  ASSERT_TRUE(stripGainMapFromXmp(gainmap_only_xmp, &stripped_xmp));
  ASSERT_TRUE(stripped_xmp.empty());
  uhdr_mem_block_t xmp_block{const_cast<char*>(gainmap_only_xmp.data()), gainmap_only_xmp.size(),
                             gainmap_only_xmp.size()};
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        &xmp_block)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* encoded = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(encoded, nullptr);
  std::vector<uint8_t> output(encoded->data_sz);
  uhdr_mem_block_t output_block{output.data(), 0, output.size()};
  ASSERT_EQ(uhdr_strip_gain_map(encoded, &output_block).error_code, UHDR_CODEC_OK);
  output.resize(output_block.data_sz);
  EXPECT_TRUE(findExtendedXmpSegments(output).empty());
  JpegDecoderHelper decoder;
  ASSERT_EQ(decoder.parseImage(output.data(), output.size()).error_code, UHDR_CODEC_OK);
  ASSERT_NE(decoder.getXMPPtr(), nullptr);
  uhdr_mem_block_t decoded_xmp_block{decoder.getXMPPtr(), decoder.getXMPSize(),
                                     decoder.getXMPSize()};
  const std::string decoded_xmp = getXmpPacket(&decoded_xmp_block);
  std::string guid;
  ASSERT_TRUE(getExtendedXmpGuidFromXmp(decoded_xmp, &guid)) << decoded_xmp;
  EXPECT_TRUE(guid.empty());
}

TEST_F(UltraHdrApiTest, StripGainMapRejectsMalformedLinkedExtendedXmpWithoutWriting) {
  constexpr std::string_view kExtensionNamespace = "http://ns.adobe.com/xmp/extension/";
  std::string ext_xmp = makeLargeXmp(140000);
  const size_t about_pos = ext_xmp.find("rdf:about=\"\"");
  ASSERT_NE(about_pos, std::string::npos);
  ext_xmp.insert(about_pos + std::string("rdf:about=\"\"").size(),
                 " xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\" "
                 "hdrgm:Version=\"1.0\"");
  uhdr_mem_block_t xmp_block{const_cast<char*>(ext_xmp.data()), ext_xmp.size(), ext_xmp.size()};
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        &xmp_block)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* encoded = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(encoded, nullptr);
  const std::vector<uint8_t> original(static_cast<const uint8_t*>(encoded->data),
                                      static_cast<const uint8_t*>(encoded->data) + encoded->data_sz);
  const std::vector<JpegSegmentSpan> segments = findExtendedXmpSegments(original);
  ASSERT_GE(segments.size(), 2u);
  const size_t extension_header = kExtensionNamespace.size() + 1 + 32 + 8;
  const size_t total_offset = segments[1].payload_begin + kExtensionNamespace.size() + 1 + 32;
  const size_t chunk_offset = total_offset + 4;

  std::vector<std::vector<uint8_t>> malformed;
  malformed.push_back(original);
  malformed.back().erase(malformed.back().begin() + segments.back().begin,
                         malformed.back().begin() + segments.back().end);
  malformed.push_back(original);
  writeBigEndian32(&malformed.back(), total_offset,
                   readBigEndian32(malformed.back(), total_offset) + 1);
  malformed.push_back(original);
  writeBigEndian32(&malformed.back(), chunk_offset, 0);
  malformed.push_back(original);
  const size_t changed_byte = ext_xmp.find('X');
  ASSERT_NE(changed_byte, std::string::npos);
  bool digest_byte_changed = false;
  for (const JpegSegmentSpan& segment : segments) {
    const size_t header = segment.payload_begin + extension_header;
    const size_t offset = readBigEndian32(malformed.back(), header - 4);
    const size_t data_size = segment.payload_size - extension_header;
    if (changed_byte >= offset && changed_byte - offset < data_size) {
      malformed.back()[header + changed_byte - offset] = 'Y';
      digest_byte_changed = true;
      break;
    }
  }
  ASSERT_TRUE(digest_byte_changed);

  for (size_t index = 0; index < malformed.size(); ++index) {
    SCOPED_TRACE(index);
    uhdr_compressed_image_t input{malformed[index].data(), malformed[index].size(),
                                  malformed[index].size(), UHDR_CG_UNSPECIFIED,
                                  UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED};
    std::vector<uint8_t> output(malformed[index].size() * 2, 0xA5);
    uhdr_mem_block_t output_block{output.data(), 0, output.size()};
    EXPECT_EQ(uhdr_strip_gain_map(&input, &output_block).error_code, UHDR_CODEC_INVALID_PARAM);
    EXPECT_TRUE(std::all_of(output.begin(), output.end(), [](uint8_t value) { return value == 0xA5; }));
  }
}

TEST_F(UltraHdrApiTest, ExtendedXmpElementLinkIsUpdatedAndRemovedByNamespace) {
  const std::string old_guid = "0123456789ABCDEF0123456789ABCDEF";
  const std::string new_guid = "FEDCBA9876543210FEDCBA9876543210";
  const std::string xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:n=\"http://ns.adobe.com/xmp/note/\" "
      "xmlns:dc=\"http://purl.org/dc/elements/1.1/\" dc:title=\"Keep this title\">"
      "<n:HasExtendedXMP>" + old_guid +
      "</n:HasExtendedXMP></rdf:Description></rdf:RDF></x:xmpmeta>";
  std::string found_guid;
  ASSERT_TRUE(getExtendedXmpGuidFromXmp(xmp, &found_guid));
  EXPECT_EQ(found_guid, old_guid);
  std::string updated;
  ASSERT_TRUE(replaceExtendedXmpGuidInXmp(xmp, new_guid, &updated));
  EXPECT_NE(updated.find(new_guid), std::string::npos);
  EXPECT_EQ(updated.find(old_guid), std::string::npos);
  EXPECT_NE(updated.find("dc:title=\"Keep this title\""), std::string::npos);
  std::string removed;
  ASSERT_TRUE(replaceExtendedXmpGuidInXmp(xmp, "", &removed));
  EXPECT_EQ(removed.find("HasExtendedXMP"), std::string::npos);
  EXPECT_NE(removed.find("dc:title=\"Keep this title\""), std::string::npos);
}

TEST_F(UltraHdrApiTest, StripGainMapKeepsNamespaceUsedByRetainedDescendant) {
  const std::string shared_xmp =
      "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><rdf:RDF "
      "xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\"><rdf:Description "
      "rdf:about=\"\" xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\" "
      "xmlns:u=\"urn:user\" hdrgm:Version=\"1.0\"><u:keep hdrgm:custom=\"x\"/>"
      "</rdf:Description></rdf:RDF></x:xmpmeta>";

  std::string stripped;
  ASSERT_TRUE(stripGainMapFromXmp(shared_xmp, &stripped));
  EXPECT_EQ(stripped.find("hdrgm:Version=\"1.0\""), std::string::npos);
  EXPECT_NE(stripped.find("xmlns:hdrgm=\"http://ns.adobe.com/hdr-gain-map/1.0/\""),
            std::string::npos);
  EXPECT_NE(stripped.find("<u:keep hdrgm:custom=\"x\"/>"), std::string::npos);
}

TEST_F(UltraHdrApiTest, StripGainMapStripsTrailingBinaryTrailerAfterPrimaryEoi) {
  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        nullptr)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* uhdr_stream = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(uhdr_stream, nullptr);

  // Append a synthetic binary trailer containing arbitrary 0xFF bytes (e.g. Samsung SEF trailer).
  std::vector<uint8_t> with_trailer(
      static_cast<const uint8_t*>(uhdr_stream->data),
      static_cast<const uint8_t*>(uhdr_stream->data) + uhdr_stream->data_sz);
  const uint8_t sef_trailer[] = {0x53, 0x45, 0x46, 0x54, 0xFF, 0xE1, 0xFF, 0xD8, 0xFF, 0xFE, 0x00};
  with_trailer.insert(with_trailer.end(), std::begin(sef_trailer), std::end(sef_trailer));

  uhdr_compressed_image_t trailer_input{with_trailer.data(), with_trailer.size(),
                                        with_trailer.size(), UHDR_CG_BT_709, UHDR_CT_SRGB,
                                        UHDR_CR_FULL_RANGE};
  std::vector<uint8_t> stripped_buf(with_trailer.size());
  uhdr_mem_block_t stripped_block{stripped_buf.data(), 0, stripped_buf.size()};
  ASSERT_EQ(uhdr_strip_gain_map(&trailer_input, &stripped_block).error_code, UHDR_CODEC_OK);
  ASSERT_GE(stripped_block.data_sz, 4u);
  EXPECT_EQ(stripped_buf[stripped_block.data_sz - 2], 0xFF);
  EXPECT_EQ(stripped_buf[stripped_block.data_sz - 1], 0xD9);
  EXPECT_EQ(is_uhdr_image(stripped_block.data, static_cast<int>(stripped_block.data_sz)), 0);
}

TEST_F(UltraHdrApiTest, StripGainMapInvalidParamsAndCorruptInput) {
  uhdr_mem_block_t out{nullptr, 0, 0};
  EXPECT_EQ(uhdr_strip_gain_map(nullptr, &out).error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_EQ(uhdr_strip_gain_map(&mSdrCompressed, nullptr).error_code, UHDR_CODEC_INVALID_PARAM);

  uhdr_mem_block_t bad_out{nullptr, 0, 16};
  EXPECT_EQ(uhdr_strip_gain_map(&mSdrCompressed, &bad_out).error_code, UHDR_CODEC_INVALID_PARAM);

  uint8_t tiny_buf[4]{};
  uhdr_mem_block_t tiny_out{tiny_buf, 0, sizeof(tiny_buf)};
  EXPECT_EQ(uhdr_strip_gain_map(&mSdrCompressed, &tiny_out).error_code, UHDR_CODEC_INVALID_PARAM);
  EXPECT_GT(tiny_out.data_sz, sizeof(tiny_buf));

  uint8_t non_jpeg[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
  uhdr_compressed_image_t non_jpeg_in{non_jpeg, sizeof(non_jpeg), sizeof(non_jpeg),
                                      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,
                                      UHDR_CR_UNSPECIFIED};
  EXPECT_EQ(uhdr_strip_gain_map(&non_jpeg_in, &out).error_code, UHDR_CODEC_INVALID_PARAM);

  // Truncated JPEG (SOI + EOI without SOS)
  uint8_t no_sos_jpeg[] = {0xFF, 0xD8, 0xFF, 0xD9};
  uhdr_compressed_image_t no_sos_in{no_sos_jpeg, sizeof(no_sos_jpeg), sizeof(no_sos_jpeg),
                                    UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,
                                    UHDR_CR_UNSPECIFIED};
  EXPECT_EQ(uhdr_strip_gain_map(&no_sos_in, &out).error_code, UHDR_CODEC_INVALID_PARAM);
}

TEST_F(UltraHdrApiTest, StripGainMapOnAppleGainMapFixtures) {
  for (const char* filename : {"apple_gainmap_new.jpg", "apple_gainmap_old.jpg"}) {
    SCOPED_TRACE(filename);
    std::vector<uint8_t> apple_data;
    ASSERT_TRUE(loadFile(filename, apple_data));
    ASSERT_EQ(is_uhdr_image(apple_data.data(), static_cast<int>(apple_data.size())), 1);

    uhdr_compressed_image_t apple_in{apple_data.data(), apple_data.size(), apple_data.size(),
                                     UHDR_CG_DISPLAY_P3, UHDR_CT_SRGB, UHDR_CR_FULL_RANGE};
    uhdr_mem_block_t size_query{nullptr, 0, 0};
    ASSERT_EQ(uhdr_strip_gain_map(&apple_in, &size_query).error_code, UHDR_CODEC_OK);
    ASSERT_GT(size_query.data_sz, 0u);
    ASSERT_LT(size_query.data_sz, apple_data.size());

    std::vector<uint8_t> stripped_buf(size_query.data_sz);
    uhdr_mem_block_t stripped_block{stripped_buf.data(), 0, stripped_buf.size()};
    ASSERT_EQ(uhdr_strip_gain_map(&apple_in, &stripped_block).error_code, UHDR_CODEC_OK);
    EXPECT_EQ(stripped_block.data_sz, size_query.data_sz);
    EXPECT_EQ(is_uhdr_image(stripped_block.data, static_cast<int>(stripped_block.data_sz)), 0);

    // Primary entropy-coded scan (including DRI and RST0..RST7 markers) must be bit-identical.
    const std::vector<uint8_t> orig_scan =
        extractPrimaryScanBytes(apple_data.data(), apple_data.size());
    const std::vector<uint8_t> stripped_scan =
        extractPrimaryScanBytes(stripped_block.data, stripped_block.data_sz);
    ASSERT_FALSE(orig_scan.empty());
    EXPECT_EQ(orig_scan, stripped_scan);

    // Verify EXIF and ICC profile are preserved and stripped JPEG decodes cleanly.
    JpegDecoderHelper orig_decoder;
    ASSERT_EQ(orig_decoder.parseImage(apple_data.data(), apple_data.size()).error_code,
              UHDR_CODEC_OK);
    JpegDecoderHelper stripped_decoder;
    ASSERT_EQ(stripped_decoder
                  .decompressImage(stripped_block.data, stripped_block.data_sz, DECODE_TO_RGB_CS)
                  .error_code,
              UHDR_CODEC_OK);
    ASSERT_EQ(stripped_decoder.getEXIFSize(), orig_decoder.getEXIFSize());
    EXPECT_EQ(memcmp(stripped_decoder.getEXIFPtr(), orig_decoder.getEXIFPtr(),
                     orig_decoder.getEXIFSize()),
              0);
    ASSERT_EQ(stripped_decoder.getICCSize(), orig_decoder.getICCSize());
    EXPECT_EQ(memcmp(stripped_decoder.getICCPtr(), orig_decoder.getICCPtr(),
                     orig_decoder.getICCSize()),
              0);
  }
}

TEST_F(UltraHdrApiTest, NearLimitStandardXmpSpillsCleanlyToExtendedXmp) {
  // 65,200 bytes is <= kMaxStandardXmpPayload (65,503 B), but when UHDR_WRITE_XMP is enabled,
  // merging the ~600-byte Ultra HDR container directory pushes it over 65,503 B into Extended XMP.
  constexpr size_t kNearLimitSize = 65200;
  const std::string near_limit_xmp = makeLargeXmp(kNearLimitSize);
  uhdr_mem_block_t xmp_block{const_cast<char*>(near_limit_xmp.data()), near_limit_xmp.size(),
                             near_limit_xmp.size()};
  uhdr_gainmap_metadata_t metadata = makeTestGainmapMetadata();

  EncoderPtr enc = makeEncoder();
  ASSERT_NE(enc, nullptr);
  ASSERT_EQ(configureJpegGainmapEncoder(enc.get(), &mSdrCompressed, &mSdrCompressed, &metadata,
                                        &xmp_block)
                .error_code,
            UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_encode(enc.get()).error_code, UHDR_CODEC_OK);
  uhdr_compressed_image_t* uhdr_stream = uhdr_get_encoded_stream(enc.get());
  ASSERT_NE(uhdr_stream, nullptr);

  // Verify uhdr_dec_get_xmp recovers the exact 65,200-byte user XMP packet.
  DecoderPtr dec = makeDecoder();
  ASSERT_NE(dec, nullptr);
  ASSERT_EQ(uhdr_dec_set_image(dec.get(), uhdr_stream).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_dec_probe(dec.get()).error_code, UHDR_CODEC_OK);
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(dec.get());
  ASSERT_NE(decoded_xmp, nullptr);
  EXPECT_EQ(getXmpPacket(decoded_xmp), near_limit_xmp);

  // Verify uhdr_strip_gain_map also preserves the 65,200-byte user XMP packet cleanly.
  std::vector<uint8_t> stripped_buf(uhdr_stream->data_sz);
  uhdr_mem_block_t stripped_block{stripped_buf.data(), 0, stripped_buf.size()};
  ASSERT_EQ(uhdr_strip_gain_map(uhdr_stream, &stripped_block).error_code, UHDR_CODEC_OK);
  EXPECT_EQ(is_uhdr_image(stripped_block.data, static_cast<int>(stripped_block.data_sz)), 0);

  JpegDecoderHelper stripped_decoder;
  ASSERT_EQ(stripped_decoder.parseImage(stripped_block.data, stripped_block.data_sz).error_code,
            UHDR_CODEC_OK);
  uhdr_mem_block_t stripped_xmp_mem{stripped_decoder.getXMPPtr(), stripped_decoder.getXMPSize(),
                                    stripped_decoder.getXMPSize()};
  EXPECT_EQ(getXmpPacket(&stripped_xmp_mem), near_limit_xmp);
}

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

TEST_F(UltraHdrApiTest, ExtendedXmpMultiSegmentRawApiOutput) {
  // 150 KB XMP metadata spans across 3 Extended XMP APP1 segments in JPEG
  constexpr size_t kLargeXmpSize = 150 * 1024;
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
  const std::string xmp = makeLargeXmp(kLargeXmpSize);
  uhdr_mem_block_t xmp_block{const_cast<char*>(xmp.data()), xmp.size(), xmp.size()};
  ASSERT_EQ(uhdr_enc_set_xmp_data(enc, &xmp_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  const uhdr_error_info_t status = uhdr_encode(enc);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  EXPECT_GT(output->data_sz, kLargeXmpSize);
  expectEncodedXmpDecodes(output, kLargeXmpSize);

  // Validate exact bit-for-bit decoded XMP content
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  ASSERT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(dec);
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  EXPECT_EQ(decoded_xmp->data_sz, kLargeXmpSize);
  EXPECT_EQ(memcmp(decoded_xmp->data, xmp.data(), kLargeXmpSize), 0);
  uhdr_release_decoder(dec);
  uhdr_release_encoder(enc);
}

TEST_F(UltraHdrApiTest, ExtendedXmpMultiSegmentCompressedBaseGainmapApiOutput) {
  constexpr size_t kLargeXmpSize = 200 * 1024;
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
  const std::string xmp = makeLargeXmp(kLargeXmpSize);
  uhdr_mem_block_t xmp_block{const_cast<char*>(xmp.data()), xmp.size(), xmp.size()};
  ASSERT_EQ(uhdr_enc_set_xmp_data(enc, &xmp_block).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_enc_set_output_format(enc, UHDR_CODEC_JPG).error_code, UHDR_CODEC_OK);

  const uhdr_error_info_t status = uhdr_encode(enc);
  ASSERT_EQ(status.error_code, UHDR_CODEC_OK) << status.detail;
  uhdr_compressed_image_t* output = uhdr_get_encoded_stream(enc);
  ASSERT_NE(output, nullptr);
  EXPECT_GT(output->data_sz, kLargeXmpSize);
  expectEncodedXmpDecodes(output, kLargeXmpSize);

  // Validate exact bit-for-bit decoded XMP content
  uhdr_codec_private_t* dec = uhdr_create_decoder();
  ASSERT_NE(dec, nullptr);
  ASSERT_EQ(uhdr_dec_set_image(dec, output).error_code, UHDR_CODEC_OK);
  ASSERT_EQ(uhdr_dec_probe(dec).error_code, UHDR_CODEC_OK);
  uhdr_mem_block_t* decoded_xmp = uhdr_dec_get_xmp(dec);
  ASSERT_NE(decoded_xmp, nullptr);
  ASSERT_NE(decoded_xmp->data, nullptr);
  EXPECT_EQ(decoded_xmp->data_sz, kLargeXmpSize);
  EXPECT_EQ(memcmp(decoded_xmp->data, xmp.data(), kLargeXmpSize), 0);
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
