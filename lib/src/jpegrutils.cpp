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
#include <cmath>
#include <limits>
#include <utility>

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

DataStruct::DataStruct(size_t s) {
  data = malloc(s);
  length = s;
  memset(data, 0, s);
  writePos = 0;
}

DataStruct::~DataStruct() {
  if (data != nullptr) {
    free(data);
  }
}

void* DataStruct::getData() { return data; }

size_t DataStruct::getLength() { return length; }

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
  if (writePos + size > length) {
    ALOGE("Writing out of boundary: write position: %zd, size: %zd, capacity: %zd", writePos, size,
          length);
    return false;
  }
  memcpy((uint8_t*)data + writePos, src, size);
  writePos += size;
  return true;
}

/*
 * Helper function used for writing data to destination.
 */
uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, size_t length,
                        size_t& position) {
  if (position + length > destination->capacity) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_MEM_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "output buffer to store compressed data is too small: write position: %zd, size: %zd, "
             "capacity: %zd",
             position, length, destination->capacity);
    return status;
  }

  memcpy((uint8_t*)destination->data + sizeof(uint8_t) * position, source, length);
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
const string kRdfUri = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
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

static bool readU16(const uint8_t* data, size_t size, uint16_t* value, size_t* offset,
                    bool isBigEndian) {
  if (*offset > size || size - *offset < 2) return false;
  if (isBigEndian) {
    *value = (data[*offset] << 8) | data[*offset + 1];
  } else {
    *value = data[*offset] | (data[*offset + 1] << 8);
  }
  *offset += 2;
  return true;
}

static bool readU32(const uint8_t* data, size_t size, uint32_t* value, size_t* offset,
                    bool isBigEndian) {
  if (*offset > size || size - *offset < 4) return false;
  if (isBigEndian) {
    *value = (data[*offset] << 24) | (data[*offset + 1] << 16) | (data[*offset + 2] << 8) |
             data[*offset + 3];
  } else {
    *value = data[*offset] | (data[*offset + 1] << 8) | (data[*offset + 2] << 16) |
             (data[*offset + 3] << 24);
  }
  *offset += 4;
  return true;
}

static bool readS32(const uint8_t* data, size_t size, int32_t* value, size_t* offset,
                    bool isBigEndian) {
  uint32_t u;
  if (!readU32(data, size, &u, offset, isBigEndian)) return false;
  *value = (int32_t)u;
  return true;
}

static bool getExifAppleHeadroom(const uint8_t* exif, size_t size, float* altHeadroom) {
  *altHeadroom = 0.0f;
  size_t offset = 0;

  // Find TIFF header offset
  if (size < 6 || memcmp(exif, "Exif\0\0", 6) != 0) {
    // Some EXIF blobs might not have the APP1 EXIF marker depending on where it
    // was extracted. Try to find the TIFF header by looking for II*\0 or MM\0*
    bool found = false;
    for (size_t i = 0; i + 4 <= size; i++) {
      if ((exif[i] == 'I' && exif[i + 1] == 'I' && exif[i + 2] == 0x2A && exif[i + 3] == 0) ||
          (exif[i] == 'M' && exif[i + 1] == 'M' && exif[i + 2] == 0 && exif[i + 3] == 0x2A)) {
        offset = i;
        found = true;
        break;
      }
    }
    if (!found) return false;
  } else {
    offset = 6;
  }

  if (offset + 4 > size) return false;
  bool isBigEndian = (exif[offset] == 'M');
  offset += 4;  // Skip the TIFF header.

  uint32_t offsetToIfd;
  if (!readU32(exif, size, &offsetToIfd, &offset, isBigEndian)) return false;

  const uint8_t appleMakerNotesHeader[] = {'A', 'p', 'p',  'l',  'e',  ' ', 'i',
                                           'O', 'S', 0x00, 0x00, 0x01, 'M', 'M'};
  const size_t appleMakerNotesHeaderSize = sizeof(appleMakerNotesHeader);
  bool inAppleMakerNotes = false;

  bool hasMaker33Or48 = false;
  double maker33 = 0.0;
  double maker48 = 0.0;

  int numIfds = 0;
  const int maxIfds = 3;  // Prevent infinite looping caused by malformed data.

  // Exif offset is relative to TIFF header
  const size_t tiffHeaderOffset = offset - 8;

  while (offsetToIfd != 0 && numIfds++ < maxIfds) {
    offset = tiffHeaderOffset + offsetToIfd;
    bool offsetToNextIfdAlreadySet = false;

    uint16_t fieldCount;
    if (!readU16(exif, size, &fieldCount, &offset, isBigEndian)) return false;

    for (uint16_t field = 0; field < fieldCount; ++field) {
      uint16_t tagId;
      uint16_t dataFormat;
      uint32_t numComponents;
      uint32_t tagData;
      if (!readU16(exif, size, &tagId, &offset, isBigEndian)) return false;
      if (!readU16(exif, size, &dataFormat, &offset, isBigEndian)) return false;
      if (!readU32(exif, size, &numComponents, &offset, isBigEndian)) return false;
      if (!readU32(exif, size, &tagData, &offset, isBigEndian)) return false;

      if (tagId == 0x8769) {  // Exif Offset (offset to a sub IFD)
        offsetToIfd = tagData;
        offsetToNextIfdAlreadySet = true;
        break;
      } else if (tagId == 0x927c) {  // Maker Notes
        uint32_t makerNotesOffset = tagData;
        if (tiffHeaderOffset + makerNotesOffset + appleMakerNotesHeaderSize <= size &&
            !memcmp(&exif[tiffHeaderOffset + makerNotesOffset], appleMakerNotesHeader,
                    appleMakerNotesHeaderSize)) {
          offsetToIfd = makerNotesOffset + (uint32_t)appleMakerNotesHeaderSize;
          inAppleMakerNotes = true;
          offsetToNextIfdAlreadySet = true;
          isBigEndian = true;  // Apple Maker Notes are always big endian.
          break;
        }
      } else if (inAppleMakerNotes && (tagId == 33 || tagId == 48) && dataFormat == 10) {
        // Guard against size_t underflow before the subtraction. If
        // (tiffHeaderOffset + offsetToIfd) is smaller than the Apple Maker
        // Notes header size, the unsigned arithmetic would wrap around to a
        // value close to SIZE_MAX, and the subsequent readU32/readS32 bounds
        // check (*offset + 4 > size) would also overflow and silently pass,
        // resulting in an out-of-bounds read.
        if (tiffHeaderOffset + offsetToIfd < appleMakerNotesHeaderSize) return false;
        size_t tmpOffset =
            tiffHeaderOffset + offsetToIfd - appleMakerNotesHeaderSize;
        // Guard against size_t overflow when adding the attacker-controlled
        // tagData to the computed base offset.
        if (tmpOffset > SIZE_MAX - (size_t)tagData) return false;
        tmpOffset += (size_t)tagData;
        int32_t numerator;
        uint32_t denominator;
        if (!readS32(exif, size, &numerator, &tmpOffset, isBigEndian)) return false;
        if (!readU32(exif, size, &denominator, &tmpOffset, isBigEndian)) return false;
        if (denominator != 0) {
          const double v = (double)numerator / denominator;
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
      if (!readU32(exif, size, &offsetToIfd, &offset, isBigEndian)) return false;
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

  *altHeadroom = pow(2.0, stops);
  return true;
}

uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, uint8_t* exif_data,
                                     int exif_size, uhdr_gainmap_metadata_ext_t* metadata) {
  string nameSpace = "http://ns.adobe.com/xap/1.0/\0";

  if (xmp_size < nameSpace.size() + 2) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "size of xmp block is expected to be atleast %zd bytes, received only %zd bytes",
             nameSpace.size() + 2, xmp_size);
    return status;
  }

  if (strncmp(reinterpret_cast<char*>(xmp_data), nameSpace.c_str(), nameSpace.size())) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "mismatch in namespace of xmp block. Expected %s, Got %.*s", nameSpace.c_str(),
             (int)nameSpace.size(), reinterpret_cast<char*>(xmp_data));
    return status;
  }

  // Position the pointers to the start of XMP XML portion
  xmp_data += nameSpace.size() + 1;
  xmp_size -= nameSpace.size() + 1;
  XMPXmlHandler handler;

  // xml parser fails to parse packet header, wrapper. remove them before handing the data to
  // parser. if there is no packet header, do nothing otherwise go to the position of '<' without
  // '?' after it.
  size_t offset = 0;
  for (size_t i = 0; i < xmp_size - 1; ++i) {
    if (xmp_data[i] == '<') {
      if (xmp_data[i + 1] != '?') {
        offset = i;
        break;
      }
    }
  }
  xmp_data += offset;
  xmp_size -= offset;

  // If there is no packet wrapper, do nothing other wise go to the position of last '>' without '?'
  // before it.
  offset = 0;
  for (size_t i = xmp_size - 1; i >= 1; --i) {
    if (xmp_data[i] == '>') {
      if (xmp_data[i - 1] != '?') {
        offset = xmp_size - (i + 1);
        break;
      }
    }
  }
  xmp_size -= offset;

  // remove padding
  while (xmp_data[xmp_size - 1] != '>' && xmp_size > 1) {
    xmp_size--;
  }

  string str(reinterpret_cast<const char*>(xmp_data), xmp_size);
  MessageHandler msg_handler;
  unique_ptr<XmlRule> rule(new XmlElementRule);
  XmlReader reader(&handler, &msg_handler);
  reader.StartParse(std::move(rule));
  reader.Parse(str);
  reader.FinishParse();
  if (reader.HasErrors()) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "xml parser returned with error");
    return status;
  }

  if (handler.getIsApple()) {
    metadata->version = kJpegrVersion;
    for (int c = 0; c < 3; ++c) {
      metadata->gamma[c] = 1.0f;
      metadata->min_content_boost[c] = 1.0f;
      metadata->offset_sdr[c] = 0.0f;
      metadata->offset_hdr[c] = 0.0f;
    }
    metadata->hdr_capacity_min = 1.0f;

    float max_content_boost;
    bool present = false;
    if (handler.getMaxContentBoost(&max_content_boost, &present) && present) {
      for (int c = 0; c < 3; ++c) {
        metadata->max_content_boost[c] = max_content_boost;
      }
      metadata->hdr_capacity_max = max_content_boost;
    } else if (exif_data != nullptr && exif_size > 0 &&
               getExifAppleHeadroom(exif_data, exif_size, &max_content_boost)) {
      for (int c = 0; c < 3; ++c) {
        metadata->max_content_boost[c] = max_content_boost;
      }
      metadata->hdr_capacity_max = max_content_boost;
    } else {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail,
               "xml parse error, could not find attribute HDRGainMapHeadroom "
               "and Exif Headroom missing");
      return status;
    }

    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_OK;
    status.has_detail = 0;
    return status;
  }

  // Apply default values to any not-present fields, except for Version,
  // maxContentBoost, and hdrCapacityMax, which are required. Return false if
  // we encounter a present field that couldn't be parsed, since this
  // indicates it is invalid (eg. string where there should be a float).
  bool present = false;
  if (!handler.getVersion(&metadata->version, &present) || !present) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "xml parse error, could not find attribute %s",
             kMapVersion.c_str());
    return status;
  }
  if (!handler.getMaxContentBoost(&metadata->max_content_boost[0], &present) || !present) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "xml parse error, could not find attribute %s",
             kMapGainMapMax.c_str());
    return status;
  }
  if (!handler.getHdrCapacityMax(&metadata->hdr_capacity_max, &present) || !present) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "xml parse error, could not find attribute %s",
             kMapHDRCapacityMax.c_str());
    return status;
  }
  if (!handler.getMinContentBoost(&metadata->min_content_boost[0], &present)) {
    if (present) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
               kMapGainMapMin.c_str());
      return status;
    }
    metadata->min_content_boost[0] = 1.0f;
  }
  if (!handler.getGamma(&metadata->gamma[0], &present)) {
    if (present) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
               kMapGamma.c_str());
      return status;
    }
    metadata->gamma[0] = 1.0f;
  }
  if (!handler.getOffsetSdr(&metadata->offset_sdr[0], &present)) {
    if (present) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
               kMapOffsetSdr.c_str());
      return status;
    }
    metadata->offset_sdr[0] = 1.0f / 64.0f;
  }
  if (!handler.getOffsetHdr(&metadata->offset_hdr[0], &present)) {
    if (present) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
               kMapOffsetHdr.c_str());
      return status;
    }
    metadata->offset_hdr[0] = 1.0f / 64.0f;
  }
  if (!handler.getHdrCapacityMin(&metadata->hdr_capacity_min, &present)) {
    if (present) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
               kMapHDRCapacityMin.c_str());
      return status;
    }
    metadata->hdr_capacity_min = 1.0f;
  }

  bool base_rendition_is_hdr;
  if (!handler.getBaseRenditionIsHdr(&base_rendition_is_hdr, &present)) {
    if (present) {
      uhdr_error_info_t status;
      status.error_code = UHDR_CODEC_ERROR;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
               kMapBaseRenditionIsHDR.c_str());
      return status;
    }
    base_rendition_is_hdr = false;
  }
  if (base_rendition_is_hdr) {
    uhdr_error_info_t status;
    status.error_code = UHDR_CODEC_ERROR;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail, "hdr intent as base rendition is not supported");
    return status;
  }
  metadata->use_base_cg = true;
  std::fill_n(metadata->min_content_boost + 1, 2, metadata->min_content_boost[0]);
  std::fill_n(metadata->max_content_boost + 1, 2, metadata->max_content_boost[0]);
  std::fill_n(metadata->gamma + 1, 2, metadata->gamma[0]);
  std::fill_n(metadata->offset_hdr + 1, 2, metadata->offset_hdr[0]);
  std::fill_n(metadata->offset_sdr + 1, 2, metadata->offset_sdr[0]);

  return uhdr_validate_gainmap_metadata_descriptor(metadata);
}

namespace {

constexpr size_t kNoXmpElement = (std::numeric_limits<size_t>::max)();

bool IsXmlWhitespace(char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool FindXmlMarkupEnd(const string& xml, size_t begin, size_t* end) {
  char quote = 0;
  for (size_t pos = begin; pos < xml.size(); ++pos) {
    const char c = xml[pos];
    if (quote != 0) {
      if (c == quote) quote = 0;
    } else if (c == '\'' || c == '"') {
      quote = c;
    } else if (c == '>') {
      *end = pos + 1;
      return true;
    }
  }
  return false;
}

struct XmpAttributeSpan {
  string qualified_name;
  string value;
  string uri;
  string local_name;
  size_t name_begin = 0;
  size_t value_end = 0;
  bool namespace_declaration = false;
};

struct XmpNamespaceDeclaration {
  string prefix;
  string uri;
};

struct XmpElementSpan {
  string qualified_name;
  string uri;
  string local_name;
  vector<XmpNamespaceDeclaration> namespace_declarations;
  vector<XmpAttributeSpan> attributes;
  size_t parent = kNoXmpElement;
  size_t start_begin = 0;
  size_t end_begin = 0;
  size_t end_end = 0;
  bool self_closing = false;
};

class XmpMergeXmlHandler : public XmlHandler {
 public:
  explicit XmpMergeXmlHandler(const string& xml) : xml_(xml) {}

  DataMatchResult StartElement(const XmlTokenContext& context) override {
    if (!FinalizePendingElement()) valid_ = false;
    pending_name_.clear();
    pending_attributes_.clear();
    pending_attribute_index_ = kNoXmpElement;
    pending_name_begin_ = context.GetTokenRange().GetBegin();
    if (!context.BuildTokenValue(&pending_name_)) valid_ = false;
    pending_element_ = true;
    return context.GetResult();
  }

  DataMatchResult AttributeName(const XmlTokenContext& context) override {
    if (!pending_element_ || pending_attribute_index_ != kNoXmpElement) {
      valid_ = false;
      return context.GetResult();
    }
    XmpAttributeSpan attribute;
    attribute.name_begin = context.GetTokenRange().GetBegin();
    if (!context.BuildTokenValue(&attribute.qualified_name)) valid_ = false;
    pending_attributes_.push_back(std::move(attribute));
    pending_attribute_index_ = pending_attributes_.size() - 1;
    return context.GetResult();
  }

  DataMatchResult AttributeValue(const XmlTokenContext& context) override {
    if (!pending_element_ || pending_attribute_index_ == kNoXmpElement) {
      valid_ = false;
      return context.GetResult();
    }
    XmpAttributeSpan& attribute = pending_attributes_[pending_attribute_index_];
    if (!context.BuildTokenValue(&attribute.value, true)) valid_ = false;
    attribute.value_end = context.GetTokenRange().GetEnd();
    pending_attribute_index_ = kNoXmpElement;
    return context.GetResult();
  }

  DataMatchResult FinishElement(const XmlTokenContext& context) override {
    const bool had_pending_element = pending_element_;
    if (!FinalizePendingElement()) valid_ = false;
    if (!context.GetTokenRange().IsValid()) {
      if (!had_pending_element || !last_element_was_self_closing_) valid_ = false;
      last_element_was_self_closing_ = false;
      return context.GetResult();
    }

    string closing_name;
    if (!context.BuildTokenValue(&closing_name)) valid_ = false;
    if (stack_.empty()) {
      valid_ = false;
      return context.GetResult();
    }
    XmpElementSpan& element = elements_[stack_.back()];
    const size_t close_name_begin = context.GetTokenRange().GetBegin();
    const size_t close_begin = xml_.rfind('<', close_name_begin);
    size_t close_end = 0;
    if (close_begin == string::npos || !FindXmlMarkupEnd(xml_, close_begin, &close_end) ||
        closing_name != element.qualified_name) {
      valid_ = false;
    } else {
      element.end_begin = close_begin;
      element.end_end = close_end;
      stack_.pop_back();
      if (stack_.empty()) root_closed_ = true;
    }
    return context.GetResult();
  }

  DataMatchResult ElementContent(const XmlTokenContext& context) override {
    if (!FinalizePendingElement()) valid_ = false;
    if (!stack_.empty() && stack_.back() == root_index_) {
      string value;
      if (!context.BuildTokenValue(&value) || !IsOuterWhitespace(value)) valid_ = false;
    }
    return context.GetResult();
  }

  DataMatchResult Comment(const XmlTokenContext& context) override {
    if (!FinalizePendingElement()) valid_ = false;
    return context.GetResult();
  }

  DataMatchResult Cdata(const XmlTokenContext& context) override {
    if (!FinalizePendingElement()) valid_ = false;
    if (!stack_.empty() && stack_.back() == root_index_) valid_ = false;
    return context.GetResult();
  }

  DataMatchResult Pi(const XmlTokenContext& context) override {
    if (!FinalizePendingElement()) valid_ = false;
    return context.GetResult();
  }

  bool IsComplete() const {
    return valid_ && !pending_element_ && stack_.empty() && root_closed_ &&
           root_index_ != kNoXmpElement;
  }

  const vector<XmpElementSpan>& elements() const { return elements_; }
  size_t root_index() const { return root_index_; }

 private:
  bool LookupNamespace(size_t parent, const vector<XmpNamespaceDeclaration>& local,
                       const string& prefix, string* uri) const {
    for (auto it = local.rbegin(); it != local.rend(); ++it) {
      if (it->prefix == prefix) {
        *uri = it->uri;
        return true;
      }
    }
    for (size_t index = parent; index != kNoXmpElement; index = elements_[index].parent) {
      const vector<XmpNamespaceDeclaration>& declarations = elements_[index].namespace_declarations;
      for (auto it = declarations.rbegin(); it != declarations.rend(); ++it) {
        if (it->prefix == prefix) {
          *uri = it->uri;
          return true;
        }
      }
    }
    if (prefix == "xml") {
      *uri = "http://www.w3.org/XML/1998/namespace";
      return true;
    }
    if (prefix == "xmlns") {
      *uri = "http://www.w3.org/2000/xmlns/";
      return true;
    }
    return false;
  }

  bool IsOuterWhitespace(const string& value) const {
    size_t begin = 0;
    if (value.compare(0, 3, "\xef\xbb\xbf") == 0) begin = 3;
    for (; begin < value.size(); ++begin) {
      if (!IsXmlWhitespace(value[begin])) return false;
    }
    return true;
  }

  bool ResolveName(const string& qualified_name, size_t parent,
                   const vector<XmpNamespaceDeclaration>& local, bool attribute,
                   string* uri, string* local_name) const {
    const size_t colon = qualified_name.find(':');
    if (colon == string::npos) {
      *local_name = qualified_name;
      if (attribute) {
        uri->clear();
        return true;
      }
      if (!LookupNamespace(parent, local, "", uri)) uri->clear();
      return true;
    }
    if (colon == 0 || colon + 1 >= qualified_name.size() ||
        qualified_name.find(':', colon + 1) != string::npos) {
      return false;
    }
    const string prefix = qualified_name.substr(0, colon);
    if (!LookupNamespace(parent, local, prefix, uri)) return false;
    *local_name = qualified_name.substr(colon + 1);
    return true;
  }

  bool FinalizePendingElement() {
    if (!pending_element_) return true;
    if (pending_name_.empty() || pending_attribute_index_ != kNoXmpElement) {
      pending_element_ = false;
      return false;
    }
    const size_t start_begin = xml_.rfind('<', pending_name_begin_);
    size_t start_end = 0;
    if (start_begin == string::npos || !FindXmlMarkupEnd(xml_, start_begin, &start_end)) {
      pending_element_ = false;
      return false;
    }
    const size_t parent = stack_.empty() ? kNoXmpElement : stack_.back();
    vector<XmpNamespaceDeclaration> namespace_declarations;
    for (auto& attribute : pending_attributes_) {
      string prefix;
      if (attribute.qualified_name == "xmlns") {
        attribute.namespace_declaration = true;
      } else if (attribute.qualified_name.compare(0, 6, "xmlns:") == 0) {
        prefix = attribute.qualified_name.substr(6);
        if (prefix.empty() || prefix.find(':') != string::npos) {
          pending_element_ = false;
          return false;
        }
        attribute.namespace_declaration = true;
      } else {
        continue;
      }
      if (attribute.value.find('&') != string::npos) {
        pending_element_ = false;
        return false;
      }
      for (const XmpNamespaceDeclaration& declaration : namespace_declarations) {
        if (declaration.prefix == prefix) {
          pending_element_ = false;
          return false;
        }
      }
      XmpNamespaceDeclaration declaration;
      declaration.prefix = prefix;
      declaration.uri = attribute.value;
      namespace_declarations.push_back(std::move(declaration));
    }

    XmpElementSpan element;
    element.qualified_name = pending_name_;
    element.parent = parent;
    element.start_begin = start_begin;
    element.namespace_declarations = namespace_declarations;
    if (!ResolveName(element.qualified_name, parent, namespace_declarations, false, &element.uri,
                     &element.local_name)) {
      pending_element_ = false;
      return false;
    }
    for (auto& attribute : pending_attributes_) {
      if (!attribute.namespace_declaration &&
          !ResolveName(attribute.qualified_name, parent, namespace_declarations, true,
                       &attribute.uri, &attribute.local_name)) {
        pending_element_ = false;
        return false;
      }
      element.attributes.push_back(std::move(attribute));
    }
    size_t last = start_end - 1;
    while (last > start_begin && IsXmlWhitespace(xml_[last - 1])) --last;
    element.self_closing = last > start_begin && xml_[last - 1] == '/';
    element.end_begin = element.self_closing ? start_begin : 0;
    element.end_end = element.self_closing ? start_end : 0;
    elements_.push_back(std::move(element));
    const size_t index = elements_.size() - 1;
    if (parent == kNoXmpElement) {
      if (root_index_ != kNoXmpElement) {
        pending_element_ = false;
        return false;
      }
      root_index_ = index;
    }
    last_element_was_self_closing_ = elements_[index].self_closing;
    if (!elements_[index].self_closing) stack_.push_back(index);
    else if (stack_.empty()) root_closed_ = true;
    pending_element_ = false;
    return true;
  }

  const string& xml_;
  vector<XmpElementSpan> elements_;
  vector<size_t> stack_;
  size_t root_index_ = kNoXmpElement;
  bool root_closed_ = false;
  bool valid_ = true;
  bool pending_element_ = false;
  string pending_name_;
  size_t pending_name_begin_ = 0;
  vector<XmpAttributeSpan> pending_attributes_;
  size_t pending_attribute_index_ = kNoXmpElement;
  bool last_element_was_self_closing_ = false;
};

string GeneratePrimaryDescription(size_t secondary_image_length,
                                  uhdr_gainmap_metadata_ext_t& metadata) {
  const vector<string> con_dir_seq({kConDirectory, string("rdf:Seq")});
  stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("rdf:Description");
  writer.WriteXmlns("rdf", kRdfUri);
  writer.WriteXmlns(kContainerPrefix, kContainerUri);
  writer.WriteXmlns(kItemPrefix, kItemUri);
  writer.WriteXmlns(kGainMapPrefix, kGainMapUri);
  writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
  writer.StartWritingElements(con_dir_seq);

  const size_t item_depth = writer.StartWritingElement("rdf:li");
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

string MergePrimaryXmp(const string& existing_xmp, size_t secondary_image_length,
                      uhdr_gainmap_metadata_ext_t& metadata) {
  const string synthetic_open = "<XmpMergeRoot>";
  const string synthetic_close = "</XmpMergeRoot>";
  const size_t offset = synthetic_open.size();
  const string parse_xml = synthetic_open + existing_xmp + synthetic_close;

  XmpMergeXmlHandler handler(parse_xml);
  MessageHandler message_handler;
  unique_ptr<XmlRule> rule(new XmlElementRule);
  XmlReader reader(&handler, &message_handler);
  if (!reader.StartParse(std::move(rule)) || !reader.Parse(parse_xml) || !reader.FinishParse() ||
      reader.HasErrors() || !handler.IsComplete()) {
    return string();
  }

  const vector<XmpElementSpan>& elements = handler.elements();
  const size_t synthetic_root = handler.root_index();
  size_t packet_root = kNoXmpElement;
  for (size_t index = 0; index < elements.size(); ++index) {
    if (elements[index].parent == synthetic_root) {
      if (packet_root != kNoXmpElement) return string();
      packet_root = index;
    }
  }
  if (packet_root == kNoXmpElement) return string();

  size_t rdf_root = kNoXmpElement;
  if (elements[packet_root].uri == kRdfUri && elements[packet_root].local_name == "RDF") {
    rdf_root = packet_root;
  } else if (elements[packet_root].local_name == "xmpmeta" &&
             elements[packet_root].uri == "adobe:ns:meta/") {
    for (size_t index = 0; index < elements.size(); ++index) {
      if (elements[index].parent == packet_root && elements[index].uri == kRdfUri &&
          elements[index].local_name == "RDF") {
        if (rdf_root != kNoXmpElement) return string();
        rdf_root = index;
      }
    }
  } else {
    return string();
  }
  if (rdf_root == kNoXmpElement || elements[rdf_root].self_closing ||
      elements[rdf_root].end_begin <= elements[rdf_root].start_begin) {
    return string();
  }

  vector<size_t> primary_descriptions;
  for (size_t index = 0; index < elements.size(); ++index) {
    const XmpElementSpan& element = elements[index];
    if (element.parent != rdf_root || element.uri != kRdfUri ||
        element.local_name != "Description") {
      continue;
    }
    bool has_about = false;
    bool about_empty = true;
    bool has_non_primary_id = false;
    for (const XmpAttributeSpan& attribute : element.attributes) {
      if (attribute.uri == kRdfUri && attribute.local_name == "about") {
        has_about = true;
        about_empty = attribute.value.empty();
      } else if (attribute.uri == kRdfUri &&
                 (attribute.local_name == "ID" || attribute.local_name == "nodeID")) {
        has_non_primary_id = true;
      }
    }
    if (!has_non_primary_id && (!has_about || about_empty)) primary_descriptions.push_back(index);
  }

  vector<pair<size_t, size_t>> removals;
  for (const size_t description : primary_descriptions) {
    const XmpElementSpan& primary = elements[description];
    for (const XmpAttributeSpan& attribute : primary.attributes) {
      if ((attribute.uri == kContainerUri && attribute.local_name == "Directory") ||
          (attribute.uri == kGainMapUri && attribute.local_name == "Version")) {
        removals.emplace_back(attribute.name_begin, attribute.value_end);
      }
    }
    for (const XmpElementSpan& child : elements) {
      if (child.parent == description &&
          ((child.uri == kContainerUri && child.local_name == "Directory") ||
           (child.uri == kGainMapUri && child.local_name == "Version"))) {
        removals.emplace_back(child.start_begin, child.end_end);
      }
    }
  }

  if (elements[rdf_root].end_begin < offset ||
      elements[rdf_root].end_begin - offset > existing_xmp.size()) {
    return string();
  }
  const size_t insertion = elements[rdf_root].end_begin - offset;
  for (auto& removal : removals) {
    if (removal.first < offset || removal.second < removal.first) return string();
    removal.first -= offset;
    removal.second -= offset;
    if (removal.second > insertion) return string();
  }
  sort(removals.begin(), removals.end());
  for (size_t index = 1; index < removals.size(); ++index) {
    if (removals[index].first < removals[index - 1].second) return string();
  }

  const string generated_description =
      GeneratePrimaryDescription(secondary_image_length, metadata);
  string merged;
  size_t cursor = 0;
  for (const auto [begin, end] : removals) {
    if (begin < cursor || end > insertion || end > existing_xmp.size()) return string();
    merged.append(existing_xmp, cursor, begin - cursor);
    cursor = end;
  }
  merged.append(existing_xmp, cursor, insertion - cursor);
  merged.append(generated_description);
  merged.push_back('\n');
  merged.append(existing_xmp, insertion, existing_xmp.size() - insertion);
  return merged;
}

}  // namespace

string generateXmpForPrimaryImage(size_t secondary_image_length,
                                  uhdr_gainmap_metadata_ext_t& metadata,
                                  uhdr_mem_block_t* user_xmp) {
  if (user_xmp != nullptr && user_xmp->data != nullptr && user_xmp->data_sz > 0) {
    const std::string kXmpHeader = "http://ns.adobe.com/xap/1.0/";
    std::string existing_xmp;
    if (user_xmp->data_sz > kXmpHeader.size() &&
        memcmp(user_xmp->data, kXmpHeader.c_str(), kXmpHeader.size()) == 0) {
      size_t offset = kXmpHeader.size();
      if (static_cast<const char*>(user_xmp->data)[offset] == '\0') {
        offset++;
      }
      existing_xmp = std::string(static_cast<const char*>(user_xmp->data) + offset,
                                 user_xmp->data_sz - offset);
    } else {
      existing_xmp = std::string(static_cast<const char*>(user_xmp->data), user_xmp->data_sz);
    }
    return MergePrimaryXmp(existing_xmp, secondary_image_length, metadata);
  }

  const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});
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
