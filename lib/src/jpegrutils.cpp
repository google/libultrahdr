/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <string_view>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/jpegr.h"
#include "ultrahdr/jpegrutils.h"

#include "image_io/xml/xml_reader.h"
#include "image_io/xml/xml_writer.h"
#include "image_io/base/message_handler.h"
#include "image_io/xml/xml_element_rules.h"
#include "image_io/xml/xml_handler.h"
#include "image_io/xml/xml_rule.h"

using namespace photos_editing_formats::image_io;
using namespace std;

namespace ultrahdr {
/*
 * Helper function used for generating XMP metadata.
 *
 * @param prefix The prefix part of the name.
 * @param suffix The suffix part of the name.
 * @return A name of the form "prefix:suffix".
 */
static inline string Name(const string& prefix, const string& suffix) {
  std::stringstream ss;
  ss << prefix << ":" << suffix;
  return ss.str();
}

static uhdr_error_info_t makeError(uhdr_codec_err_t code, std::string_view message) {
  uhdr_error_info_t status{};
  status.error_code = code;
  status.has_detail = 1;
  const std::string_view clipped = message.substr(0, sizeof(status.detail) - 1);
  std::copy(clipped.begin(), clipped.end(), std::begin(status.detail));
  return status;
}

DataStruct::DataStruct(size_t s) : data(s, 0), writePos(0) {}

DataStruct::~DataStruct() = default;

void* DataStruct::getData() { return data.empty() ? nullptr : data.data(); }

size_t DataStruct::getLength() { return data.size(); }

size_t DataStruct::getBytesWritten() { return writePos; }

bool DataStruct::write8(uint8_t value) {
  uint8_t v = value;
  return write(&v, 1);
}

bool DataStruct::write16(uint16_t value) {
  uint16_t v = value;
  return write(&v, 2);
}

bool DataStruct::write32(uint32_t value) {
  uint32_t v = value;
  return write(&v, 4);
}

bool DataStruct::write(const void* src, size_t size) {
  if (size == 0) {
    return true;
  }
  if (src == nullptr || writePos > data.size() || size > data.size() - writePos) {
    ALOGE("Writing out of boundary: write position: %zu, size: %zu, capacity: %zu", writePos, size,
          data.size());
    return false;
  }
  std::string_view src_view(static_cast<const char*>(src), size);
  std::transform(src_view.begin(), src_view.end(),
                 data.begin() + static_cast<std::ptrdiff_t>(writePos),
                 [](char c) { return static_cast<uint8_t>(c); });
  writePos += size;
  return true;
}

/*
 * Helper function used for writing data to destination.
 */
uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, size_t length,
                        size_t& position) {
  if (destination == nullptr || position > destination->capacity ||
      length > destination->capacity - position) {
    std::stringstream ss;
    ss << "output buffer to store compressed data is too small: write position: " << position
       << ", size: " << length
       << ", capacity: " << (destination != nullptr ? destination->capacity : 0);
    return makeError(UHDR_CODEC_MEM_ERROR, ss.str());
  }
  if (length == 0) {
    return g_no_error;
  }
  if (destination->data == nullptr || source == nullptr) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "null buffer passed to Write()");
  }

  // C API boundary: bounds checked above (position + length <= destination->capacity).
#if defined(__clang__)
#pragma clang unsafe_buffer_usage begin
#endif
  std::memcpy(static_cast<uint8_t*>(destination->data) + position, source, length);
#if defined(__clang__)
#pragma clang unsafe_buffer_usage end
#endif
  position += length;
  return g_no_error;
}

// Extremely simple XML Handler - just searches for interesting elements
class XMPXmlHandler : public XmlHandler {
 public:
  XMPXmlHandler() : XmlHandler() {
    state = NotStrarted;
    versionFound = false;
    minContentBoostFound = false;
    maxContentBoostFound = false;
    gammaFound = false;
    offsetSdrFound = false;
    offsetHdrFound = false;
    hdrCapacityMinFound = false;
    hdrCapacityMaxFound = false;
    baseRenditionIsHdrFound = false;
    isApple = false;
  }

  enum ParseState { NotStrarted, Started, Done };

  virtual DataMatchResult StartElement(const XmlTokenContext& context) {
    string val;
    if (context.BuildTokenValue(&val)) {
      if (!val.compare(containerName)) {
        state = Started;
      } else if (state == Started) {
        if (val.find(kAppleMapVersion) != string::npos) {
          lastElementName = kAppleMapVersion;
        } else if (val.find(kAppleMapHeadroom) != string::npos) {
          lastElementName = kAppleMapHeadroom;
        } else {
          lastElementName = "Unknown";
        }
      } else {
        if (state != Done) {
          state = NotStrarted;
        }
      }
    }
    return context.GetResult();
  }

  virtual DataMatchResult FinishElement(const XmlTokenContext& context) {
    if (state == Started) {
      if (lastElementName.empty()) {
        state = Done;
        lastAttributeName = "";
      } else {
        lastElementName = "";
      }
    }
    return context.GetResult();
  }

  virtual DataMatchResult ElementContent(const XmlTokenContext& context) {
    string val;
    if (state == Started && !lastElementName.empty()) {
      if (context.BuildTokenValue(&val)) {
        if (!lastElementName.compare(kAppleMapVersion)) {
          versionStr = val;
          versionFound = true;
          isApple = true;
        } else if (!lastElementName.compare(kAppleMapHeadroom)) {
          maxContentBoostStr = val;
          maxContentBoostFound = true;
        }
      }
    }
    return context.GetResult();
  }

  virtual DataMatchResult AttributeName(const XmlTokenContext& context) {
    string val;
    if (state == Started) {
      if (context.BuildTokenValue(&val)) {
        if (!val.compare(versionAttrName)) {
          lastAttributeName = versionAttrName;
        } else if (!val.compare(maxContentBoostAttrName)) {
          lastAttributeName = maxContentBoostAttrName;
        } else if (!val.compare(minContentBoostAttrName)) {
          lastAttributeName = minContentBoostAttrName;
        } else if (!val.compare(gammaAttrName)) {
          lastAttributeName = gammaAttrName;
        } else if (!val.compare(offsetSdrAttrName)) {
          lastAttributeName = offsetSdrAttrName;
        } else if (!val.compare(offsetHdrAttrName)) {
          lastAttributeName = offsetHdrAttrName;
        } else if (!val.compare(hdrCapacityMinAttrName)) {
          lastAttributeName = hdrCapacityMinAttrName;
        } else if (!val.compare(hdrCapacityMaxAttrName)) {
          lastAttributeName = hdrCapacityMaxAttrName;
        } else if (!val.compare(baseRenditionIsHdrAttrName)) {
          lastAttributeName = baseRenditionIsHdrAttrName;
        } else {
          lastAttributeName = "";
        }
      }
    }
    return context.GetResult();
  }

  virtual DataMatchResult AttributeValue(const XmlTokenContext& context) {
    string val;
    if (state == Started) {
      if (context.BuildTokenValue(&val, true)) {
        if (!lastAttributeName.compare(versionAttrName)) {
          versionStr = val;
          versionFound = true;
        } else if (!lastAttributeName.compare(maxContentBoostAttrName)) {
          maxContentBoostStr = val;
          maxContentBoostFound = true;
        } else if (!lastAttributeName.compare(minContentBoostAttrName)) {
          minContentBoostStr = val;
          minContentBoostFound = true;
        } else if (!lastAttributeName.compare(gammaAttrName)) {
          gammaStr = val;
          gammaFound = true;
        } else if (!lastAttributeName.compare(offsetSdrAttrName)) {
          offsetSdrStr = val;
          offsetSdrFound = true;
        } else if (!lastAttributeName.compare(offsetHdrAttrName)) {
          offsetHdrStr = val;
          offsetHdrFound = true;
        } else if (!lastAttributeName.compare(hdrCapacityMinAttrName)) {
          hdrCapacityMinStr = val;
          hdrCapacityMinFound = true;
        } else if (!lastAttributeName.compare(hdrCapacityMaxAttrName)) {
          hdrCapacityMaxStr = val;
          hdrCapacityMaxFound = true;
        } else if (!lastAttributeName.compare(baseRenditionIsHdrAttrName)) {
          baseRenditionIsHdrStr = val;
          baseRenditionIsHdrFound = true;
        }
      }
    }
    return context.GetResult();
  }

  bool getVersion(string* version, bool* present) {
    if (state == Done) {
      *version = versionStr;
      *present = versionFound;
      return true;
    } else {
      return false;
    }
  }

  bool getMaxContentBoost(float* max_content_boost, bool* present) {
    if (state == Done) {
      *present = maxContentBoostFound;
      stringstream ss(maxContentBoostStr);
      float val;
      if (ss >> val) {
        *max_content_boost = exp2(val);
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getMinContentBoost(float* min_content_boost, bool* present) {
    if (state == Done) {
      *present = minContentBoostFound;
      stringstream ss(minContentBoostStr);
      float val;
      if (ss >> val) {
        *min_content_boost = exp2(val);
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getGamma(float* gamma, bool* present) {
    if (state == Done) {
      *present = gammaFound;
      stringstream ss(gammaStr);
      float val;
      if (ss >> val) {
        *gamma = val;
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getOffsetSdr(float* offset_sdr, bool* present) {
    if (state == Done) {
      *present = offsetSdrFound;
      stringstream ss(offsetSdrStr);
      float val;
      if (ss >> val) {
        *offset_sdr = val;
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getOffsetHdr(float* offset_hdr, bool* present) {
    if (state == Done) {
      *present = offsetHdrFound;
      stringstream ss(offsetHdrStr);
      float val;
      if (ss >> val) {
        *offset_hdr = val;
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getHdrCapacityMin(float* hdr_capacity_min, bool* present) {
    if (state == Done) {
      *present = hdrCapacityMinFound;
      stringstream ss(hdrCapacityMinStr);
      float val;
      if (ss >> val) {
        *hdr_capacity_min = exp2(val);
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getHdrCapacityMax(float* hdr_capacity_max, bool* present) {
    if (state == Done) {
      *present = hdrCapacityMaxFound;
      stringstream ss(hdrCapacityMaxStr);
      float val;
      if (ss >> val) {
        *hdr_capacity_max = exp2(val);
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getBaseRenditionIsHdr(bool* base_rendition_is_hdr, bool* present) {
    if (state == Done) {
      *present = baseRenditionIsHdrFound;
      if (!baseRenditionIsHdrStr.compare("False")) {
        *base_rendition_is_hdr = false;
        return true;
      } else if (!baseRenditionIsHdrStr.compare("True")) {
        *base_rendition_is_hdr = true;
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  bool getIsApple() const { return isApple; }

 private:
  static const string containerName;

  static const string versionAttrName;
  string versionStr;
  bool versionFound;
  static const string maxContentBoostAttrName;
  string maxContentBoostStr;
  bool maxContentBoostFound;
  static const string minContentBoostAttrName;
  string minContentBoostStr;
  bool minContentBoostFound;
  static const string gammaAttrName;
  string gammaStr;
  bool gammaFound;
  static const string offsetSdrAttrName;
  string offsetSdrStr;
  bool offsetSdrFound;
  static const string offsetHdrAttrName;
  string offsetHdrStr;
  bool offsetHdrFound;
  static const string hdrCapacityMinAttrName;
  string hdrCapacityMinStr;
  bool hdrCapacityMinFound;
  static const string hdrCapacityMaxAttrName;
  string hdrCapacityMaxStr;
  bool hdrCapacityMaxFound;
  static const string baseRenditionIsHdrAttrName;
  string baseRenditionIsHdrStr;
  bool baseRenditionIsHdrFound;

  string lastAttributeName;
  string lastElementName;
  ParseState state;
  bool isApple;

  static const string kAppleMapVersion;
  static const string kAppleMapHeadroom;
};

// GContainer XMP constants - URI and namespace prefix
const string kContainerUri = "http://ns.google.com/photos/1.0/container/";
const string kContainerPrefix = "Container";

// GContainer XMP constants - element and attribute names
const string kConDirectory = Name(kContainerPrefix, "Directory");
const string kConItem = Name(kContainerPrefix, "Item");

// GContainer XMP constants - names for XMP handlers
const string XMPXmlHandler::containerName = "rdf:Description";
// Item XMP constants - URI and namespace prefix
const string kItemUri = "http://ns.google.com/photos/1.0/container/item/";
const string kItemPrefix = "Item";

// Item XMP constants - element and attribute names
const string kItemLength = Name(kItemPrefix, "Length");
const string kItemMime = Name(kItemPrefix, "Mime");
const string kItemSemantic = Name(kItemPrefix, "Semantic");

// Item XMP constants - element and attribute values
const string kSemanticPrimary = "Primary";
const string kSemanticGainMap = "GainMap";
const string kMimeImageJpeg = "image/jpeg";

// GainMap XMP constants - URI and namespace prefix
const string kGainMapUri = "http://ns.adobe.com/hdr-gain-map/1.0/";
const string kGainMapPrefix = "hdrgm";

// GainMap XMP constants - element and attribute names
const string kMapVersion = Name(kGainMapPrefix, "Version");
const string kMapGainMapMin = Name(kGainMapPrefix, "GainMapMin");
const string kMapGainMapMax = Name(kGainMapPrefix, "GainMapMax");
const string kMapGamma = Name(kGainMapPrefix, "Gamma");
const string kMapOffsetSdr = Name(kGainMapPrefix, "OffsetSDR");
const string kMapOffsetHdr = Name(kGainMapPrefix, "OffsetHDR");
const string kMapHDRCapacityMin = Name(kGainMapPrefix, "HDRCapacityMin");
const string kMapHDRCapacityMax = Name(kGainMapPrefix, "HDRCapacityMax");
const string kMapBaseRenditionIsHDR = Name(kGainMapPrefix, "BaseRenditionIsHDR");

// GainMap XMP constants - names for XMP handlers
const string XMPXmlHandler::versionAttrName = kMapVersion;
const string XMPXmlHandler::minContentBoostAttrName = kMapGainMapMin;
const string XMPXmlHandler::maxContentBoostAttrName = kMapGainMapMax;
const string XMPXmlHandler::gammaAttrName = kMapGamma;
const string XMPXmlHandler::offsetSdrAttrName = kMapOffsetSdr;
const string XMPXmlHandler::offsetHdrAttrName = kMapOffsetHdr;
const string XMPXmlHandler::hdrCapacityMinAttrName = kMapHDRCapacityMin;
const string XMPXmlHandler::hdrCapacityMaxAttrName = kMapHDRCapacityMax;
const string XMPXmlHandler::baseRenditionIsHdrAttrName = kMapBaseRenditionIsHDR;
const string XMPXmlHandler::kAppleMapVersion = "HDRGainMapVersion";
const string XMPXmlHandler::kAppleMapHeadroom = "HDRGainMapHeadroom";

static inline uint8_t byteAt(std::string_view data, size_t index) {
  return static_cast<uint8_t>(data[index]);
}

static bool readU16(std::string_view data, uint16_t* value, size_t* offset, bool isBigEndian) {
  if (*offset > data.size() || data.size() - *offset < 2) return false;
  const uint8_t b0 = byteAt(data, *offset);
  const uint8_t b1 = byteAt(data, *offset + 1);
  if (isBigEndian) {
    *value = static_cast<uint16_t>((static_cast<uint16_t>(b0) << 8) | b1);
  } else {
    *value = static_cast<uint16_t>(b0 | (static_cast<uint16_t>(b1) << 8));
  }
  *offset += 2;
  return true;
}

static bool readU32(std::string_view data, uint32_t* value, size_t* offset, bool isBigEndian) {
  if (*offset > data.size() || data.size() - *offset < 4) return false;
  const uint32_t b0 = byteAt(data, *offset);
  const uint32_t b1 = byteAt(data, *offset + 1);
  const uint32_t b2 = byteAt(data, *offset + 2);
  const uint32_t b3 = byteAt(data, *offset + 3);
  if (isBigEndian) {
    *value = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  } else {
    *value = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  }
  *offset += 4;
  return true;
}

static bool readS32(std::string_view data, int32_t* value, size_t* offset, bool isBigEndian) {
  uint32_t u;
  if (!readU32(data, &u, offset, isBigEndian)) return false;
  *value = static_cast<int32_t>(u);
  return true;
}

// Resolves an offset stored in the EXIF data, relative to base, to an offset in
// the buffer. Fails if the result lies past the end of the buffer. Every offset
// read from the EXIF data must go through this, so that the sum never wraps.
static bool resolveOffset(size_t base, uint32_t relOffset, size_t size, size_t* offset) {
  if (base > size || relOffset > size - base) return false;
  *offset = base + relOffset;
  return true;
}

static bool matchBytes(std::string_view data, size_t offset, std::string_view expected) {
  if (offset > data.size() || data.size() - offset < expected.size()) return false;
  return data.substr(offset, expected.size()) == expected;
}

static bool getExifAppleHeadroom(std::string_view exif, float* altHeadroom) {
  *altHeadroom = 0.0f;
  size_t offset = 0;
  const size_t size = exif.size();
  static constexpr std::string_view kExifHeader("Exif\0\0", 6);
  static constexpr std::string_view kTiffLittle("II\x2A\0", 4);
  static constexpr std::string_view kTiffBig("MM\0\x2A", 4);

  // Find TIFF header offset
  if (!matchBytes(exif, 0, kExifHeader)) {
    // Some EXIF blobs might not have the APP1 EXIF marker depending on where it
    // was extracted. Try to find the TIFF header by looking for II*\0 or MM\0*
    const size_t le_pos = exif.find(kTiffLittle);
    const size_t be_pos = exif.find(kTiffBig);
    const size_t found_pos = std::min(le_pos, be_pos);
    if (found_pos == std::string_view::npos) return false;
    offset = found_pos;
  } else {
    offset = 6;
  }

  if (size - offset < 4) return false;
  bool isBigEndian = (exif[offset] == 'M');
  offset += 4;  // Skip the TIFF header.

  uint32_t offsetToIfd;
  if (!readU32(exif, &offsetToIfd, &offset, isBigEndian)) return false;

  static constexpr std::string_view kAppleMakerNotesHeader("Apple iOS\0\0\x01MM", 14);
  const size_t appleMakerNotesHeaderSize = kAppleMakerNotesHeader.size();
  bool inAppleMakerNotes = false;

  bool hasMaker33Or48 = false;
  double maker33 = 0.0;
  double maker48 = 0.0;

  int numIfds = 0;
  const int maxIfds = 3;  // Prevent infinite looping caused by malformed data.

  // Exif offset is relative to TIFF header
  const size_t tiffHeaderOffset = offset - 8;

  while (offsetToIfd != 0 && numIfds++ < maxIfds) {
    size_t ifdOffset;
    if (!resolveOffset(tiffHeaderOffset, offsetToIfd, size, &ifdOffset)) return false;
    offset = ifdOffset;
    bool offsetToNextIfdAlreadySet = false;

    uint16_t fieldCount;
    if (!readU16(exif, &fieldCount, &offset, isBigEndian)) return false;

    for (uint16_t field = 0; field < fieldCount; ++field) {
      uint16_t tagId;
      uint16_t dataFormat;
      uint32_t numComponents;
      uint32_t tagData;
      if (!readU16(exif, &tagId, &offset, isBigEndian)) return false;
      if (!readU16(exif, &dataFormat, &offset, isBigEndian)) return false;
      if (!readU32(exif, &numComponents, &offset, isBigEndian)) return false;
      if (!readU32(exif, &tagData, &offset, isBigEndian)) return false;

      if (tagId == 0x8769) {  // Exif Offset (offset to a sub IFD)
        offsetToIfd = tagData;
        offsetToNextIfdAlreadySet = true;
        break;
      } else if (tagId == 0x927c) {  // Maker Notes
        size_t makerNotesOffset;
        // The first IFD follows the header; its offset must fit in 32 bits too.
        if (tagData <= UINT32_MAX - appleMakerNotesHeaderSize &&
            resolveOffset(tiffHeaderOffset, tagData, size, &makerNotesOffset) &&
            matchBytes(exif, makerNotesOffset, kAppleMakerNotesHeader)) {
          offsetToIfd = tagData + static_cast<uint32_t>(appleMakerNotesHeaderSize);
          inAppleMakerNotes = true;
          offsetToNextIfdAlreadySet = true;
          isBigEndian = true;  // Apple Maker Notes are always big endian.
          break;
        }
      } else if (inAppleMakerNotes && (tagId == 33 || tagId == 48) && dataFormat == 10) {
        // Offsets in the Apple Maker Notes are relative to the Maker Notes
        // header, which precedes their first IFD.
        if (ifdOffset < appleMakerNotesHeaderSize) return false;
        size_t tmpOffset;
        if (!resolveOffset(ifdOffset - appleMakerNotesHeaderSize, tagData, size, &tmpOffset)) {
          return false;
        }
        int32_t numerator;
        uint32_t denominator;
        if (!readS32(exif, &numerator, &tmpOffset, isBigEndian)) return false;
        if (!readU32(exif, &denominator, &tmpOffset, isBigEndian)) return false;
        if (denominator != 0) {
          const double v = static_cast<double>(numerator) / denominator;
          if (tagId == 33) {
            maker33 = v;
          } else {
            maker48 = v;
          }
          hasMaker33Or48 = true;
        }
      }
    }

    if (!offsetToNextIfdAlreadySet) {
      if (!readU32(exif, &offsetToIfd, &offset, isBigEndian)) return false;
    }
  }

  if (!hasMaker33Or48) {
    return false;
  }

  double stops;
  if (maker33 < 1.0) {
    if (maker48 <= 0.01) {
      stops = -20.0 * maker48 + 1.8;
    } else {
      stops = -0.101 * maker48 + 1.601;
    }
  } else {
    if (maker48 <= 0.01) {
      stops = -70.0 * maker48 + 3.0;
    } else {
      stops = -0.303 * maker48 + 2.303;
    }
  }

  *altHeadroom = static_cast<float>(pow(2.0, stops));
  return true;
}

uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, uint8_t* exif_data,
                                     int exif_size, uhdr_gainmap_metadata_ext_t* metadata) {
  if (metadata == nullptr) {
    return makeError(UHDR_CODEC_INVALID_PARAM, "received nullptr for gain map metadata descriptor");
  }
  static constexpr std::string_view kNameSpace = "http://ns.adobe.com/xap/1.0/";

  if (xmp_data == nullptr || xmp_size < kNameSpace.size() + 2) {
    std::stringstream ss;
    ss << "size of xmp block is expected to be atleast " << (kNameSpace.size() + 2)
       << " bytes, received only " << xmp_size << " bytes";
    return makeError(UHDR_CODEC_ERROR, ss.str());
  }

  std::string_view xmp(reinterpret_cast<const char*>(xmp_data), xmp_size);
  if (xmp.substr(0, kNameSpace.size()) != kNameSpace) {
    std::stringstream ss;
    ss << "mismatch in namespace of xmp block. Expected " << kNameSpace << ", Got "
       << xmp.substr(0, kNameSpace.size());
    return makeError(UHDR_CODEC_ERROR, ss.str());
  }

  // Position the view to the start of XMP XML portion
  xmp.remove_prefix(kNameSpace.size() + 1);
  XMPXmlHandler handler;

  // xml parser fails to parse packet header, wrapper. remove them before handing the data to
  // parser. if there is no packet header, do nothing otherwise go to the position of '<' without
  // '?' after it.
  size_t offset = 0;
  for (size_t i = 0; i + 1 < xmp.size(); ++i) {
    if (xmp[i] == '<' && xmp[i + 1] != '?') {
      offset = i;
      break;
    }
  }
  xmp.remove_prefix(offset);

  // If there is no packet wrapper, do nothing other wise go to the position of last '>' without '?'
  // before it.
  offset = 0;
  for (size_t i = xmp.size(); i > 1; --i) {
    if (xmp[i - 1] == '>' && xmp[i - 2] != '?') {
      offset = xmp.size() - i;
      break;
    }
  }
  xmp.remove_suffix(offset);

  // remove padding
  while (xmp.size() > 1 && xmp.back() != '>') {
    xmp.remove_suffix(1);
  }

  string str(xmp);
  MessageHandler msg_handler;
  unique_ptr<XmlRule> rule(new XmlElementRule);
  XmlReader reader(&handler, &msg_handler);
  reader.StartParse(std::move(rule));
  reader.Parse(str);
  reader.FinishParse();
  if (reader.HasErrors()) {
    return makeError(UHDR_CODEC_UNKNOWN_ERROR, "xml parser returned with error");
  }

  if (handler.getIsApple()) {
    metadata->version = kJpegrVersion;
    std::fill(std::begin(metadata->gamma), std::end(metadata->gamma), 1.0f);
    std::fill(std::begin(metadata->min_content_boost), std::end(metadata->min_content_boost), 1.0f);
    std::fill(std::begin(metadata->offset_sdr), std::end(metadata->offset_sdr), 0.0f);
    std::fill(std::begin(metadata->offset_hdr), std::end(metadata->offset_hdr), 0.0f);
    metadata->hdr_capacity_min = 1.0f;

    float max_content_boost;
    bool present = false;
    if (handler.getMaxContentBoost(&max_content_boost, &present) && present) {
      std::fill(std::begin(metadata->max_content_boost), std::end(metadata->max_content_boost),
                max_content_boost);
      metadata->hdr_capacity_max = max_content_boost;
    } else if (exif_data != nullptr && exif_size > 0 &&
               getExifAppleHeadroom(std::string_view(reinterpret_cast<const char*>(exif_data),
                                                     static_cast<size_t>(exif_size)),
                                    &max_content_boost)) {
      std::fill(std::begin(metadata->max_content_boost), std::end(metadata->max_content_boost),
                max_content_boost);
      metadata->hdr_capacity_max = max_content_boost;
    } else {
      return makeError(UHDR_CODEC_ERROR,
                       "xml parse error, could not find attribute HDRGainMapHeadroom "
                       "and Exif Headroom missing");
    }

    return g_no_error;
  }

  // Apply default values to any not-present fields, except for Version,
  // maxContentBoost, and hdrCapacityMax, which are required. Return false if
  // we encounter a present field that couldn't be parsed, since this
  // indicates it is invalid (eg. string where there should be a float).
  bool present = false;
  if (!handler.getVersion(&metadata->version, &present) || !present) {
    return makeError(UHDR_CODEC_ERROR, "xml parse error, could not find attribute " + kMapVersion);
  }
  if (!handler.getMaxContentBoost(&metadata->max_content_boost[0], &present) || !present) {
    return makeError(UHDR_CODEC_ERROR,
                     "xml parse error, could not find attribute " + kMapGainMapMax);
  }
  if (!handler.getHdrCapacityMax(&metadata->hdr_capacity_max, &present) || !present) {
    return makeError(UHDR_CODEC_ERROR,
                     "xml parse error, could not find attribute " + kMapHDRCapacityMax);
  }
  if (!handler.getMinContentBoost(&metadata->min_content_boost[0], &present)) {
    if (present) {
      return makeError(UHDR_CODEC_ERROR,
                       "xml parse error, unable to parse attribute " + kMapGainMapMin);
    }
    metadata->min_content_boost[0] = 1.0f;
  }
  if (!handler.getGamma(&metadata->gamma[0], &present)) {
    if (present) {
      return makeError(UHDR_CODEC_ERROR, "xml parse error, unable to parse attribute " + kMapGamma);
    }
    metadata->gamma[0] = 1.0f;
  }
  if (!handler.getOffsetSdr(&metadata->offset_sdr[0], &present)) {
    if (present) {
      return makeError(UHDR_CODEC_ERROR,
                       "xml parse error, unable to parse attribute " + kMapOffsetSdr);
    }
    metadata->offset_sdr[0] = 1.0f / 64.0f;
  }
  if (!handler.getOffsetHdr(&metadata->offset_hdr[0], &present)) {
    if (present) {
      return makeError(UHDR_CODEC_ERROR,
                       "xml parse error, unable to parse attribute " + kMapOffsetHdr);
    }
    metadata->offset_hdr[0] = 1.0f / 64.0f;
  }
  if (!handler.getHdrCapacityMin(&metadata->hdr_capacity_min, &present)) {
    if (present) {
      return makeError(UHDR_CODEC_ERROR,
                       "xml parse error, unable to parse attribute " + kMapHDRCapacityMin);
    }
    metadata->hdr_capacity_min = 1.0f;
  }

  bool base_rendition_is_hdr;
  if (!handler.getBaseRenditionIsHdr(&base_rendition_is_hdr, &present)) {
    if (present) {
      return makeError(UHDR_CODEC_ERROR,
                       "xml parse error, unable to parse attribute " + kMapBaseRenditionIsHDR);
    }
    base_rendition_is_hdr = false;
  }
  if (base_rendition_is_hdr) {
    return makeError(UHDR_CODEC_ERROR, "hdr intent as base rendition is not supported");
  }
  metadata->use_base_cg = true;
  std::fill(std::begin(metadata->min_content_boost), std::end(metadata->min_content_boost),
            metadata->min_content_boost[0]);
  std::fill(std::begin(metadata->max_content_boost), std::end(metadata->max_content_boost),
            metadata->max_content_boost[0]);
  std::fill(std::begin(metadata->gamma), std::end(metadata->gamma), metadata->gamma[0]);
  std::fill(std::begin(metadata->offset_hdr), std::end(metadata->offset_hdr),
            metadata->offset_hdr[0]);
  std::fill(std::begin(metadata->offset_sdr), std::end(metadata->offset_sdr),
            metadata->offset_sdr[0]);

  return uhdr_validate_gainmap_metadata_descriptor(metadata);
}

string generateXmpForPrimaryImage(size_t secondary_image_length,
                                  uhdr_gainmap_metadata_ext_t& metadata) {
  const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});
  const vector<string> kLiItem({string("rdf:li"), kConItem});

  std::stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("x:xmpmeta");
  writer.WriteXmlns("x", "adobe:ns:meta/");
  writer.WriteAttributeNameAndValue("x:xmptk", "Adobe XMP Core 5.1.2");
  writer.StartWritingElement("rdf:RDF");
  writer.WriteXmlns("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
  writer.StartWritingElement("rdf:Description");
  writer.WriteXmlns(kContainerPrefix, kContainerUri);
  writer.WriteXmlns(kItemPrefix, kItemUri);
  writer.WriteXmlns(kGainMapPrefix, kGainMapUri);
  writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);

  writer.StartWritingElements(kConDirSeq);

  size_t item_depth = writer.StartWritingElement("rdf:li");
  writer.WriteAttributeNameAndValue("rdf:parseType", "Resource");
  writer.StartWritingElement(kConItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kSemanticPrimary);
  writer.WriteAttributeNameAndValue(kItemMime, kMimeImageJpeg);
  writer.FinishWritingElementsToDepth(item_depth);

  writer.StartWritingElement("rdf:li");
  writer.WriteAttributeNameAndValue("rdf:parseType", "Resource");
  writer.StartWritingElement(kConItem);
  writer.WriteAttributeNameAndValue(kItemSemantic, kSemanticGainMap);
  writer.WriteAttributeNameAndValue(kItemMime, kMimeImageJpeg);
  writer.WriteAttributeNameAndValue(kItemLength, secondary_image_length);

  writer.FinishWriting();

  return ss.str();
}

string generateXmpForSecondaryImage(uhdr_gainmap_metadata_ext_t& metadata) {
  const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});

  std::stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("x:xmpmeta");
  writer.WriteXmlns("x", "adobe:ns:meta/");
  writer.WriteAttributeNameAndValue("x:xmptk", "Adobe XMP Core 5.1.2");
  writer.StartWritingElement("rdf:RDF");
  writer.WriteXmlns("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
  writer.StartWritingElement("rdf:Description");
  writer.WriteAttributeNameAndValue("rdf:about", "");
  writer.WriteXmlns(kGainMapPrefix, kGainMapUri);
  writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
  writer.WriteAttributeNameAndValue(kMapGainMapMin, log2(metadata.min_content_boost[0]));
  writer.WriteAttributeNameAndValue(kMapGainMapMax, log2(metadata.max_content_boost[0]));
  writer.WriteAttributeNameAndValue(kMapGamma, metadata.gamma[0]);
  writer.WriteAttributeNameAndValue(kMapOffsetSdr, metadata.offset_sdr[0]);
  writer.WriteAttributeNameAndValue(kMapOffsetHdr, metadata.offset_hdr[0]);
  writer.WriteAttributeNameAndValue(kMapHDRCapacityMin, log2(metadata.hdr_capacity_min));
  writer.WriteAttributeNameAndValue(kMapHDRCapacityMax, log2(metadata.hdr_capacity_max));
  writer.WriteAttributeNameAndValue(kMapBaseRenditionIsHDR, "False");
  writer.FinishWriting();

  return ss.str();
}

}  // namespace ultrahdr
