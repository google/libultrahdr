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

#include <algorithm>
#include <cmath>

#include "ultrahdrcommon.h"
#include "jpegr.h"
#include "jpegrutils.h"

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

DataStruct::DataStruct(int s) {
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

int DataStruct::getLength() { return length; }

int DataStruct::getBytesWritten() { return writePos; }

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

bool DataStruct::write(const void* src, int size) {
  if (writePos + size > length) {
    ALOGE("Writing out of boundary: write position: %d, size: %d, capacity: %d", writePos, size,
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
status_t Write(jr_compressed_ptr destination, const void* source, size_t length, int& position) {
  if (position + length > destination->maxLength) {
    return ERROR_JPEGR_BUFFER_TOO_SMALL;
  }

  memcpy((uint8_t*)destination->data + sizeof(uint8_t) * position, source, length);
  position += length;
  return NO_ERROR;
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
  }

  enum ParseState { NotStrarted, Started, Done };

  virtual DataMatchResult StartElement(const XmlTokenContext& context) {
    string val;
    if (context.BuildTokenValue(&val)) {
      if (!val.compare(containerName)) {
        state = Started;
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
      state = Done;
      lastAttributeName = "";
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
  ParseState state;
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

bool getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size, ultrahdr_metadata_struct* metadata) {
  string nameSpace = "http://ns.adobe.com/xap/1.0/\0";

  if (xmp_size < nameSpace.size() + 2) {
    // Data too short
    return false;
  }

  if (strncmp(reinterpret_cast<char*>(xmp_data), nameSpace.c_str(), nameSpace.size())) {
    // Not correct namespace
    return false;
  }

  // Position the pointers to the start of XMP XML portion
  xmp_data += nameSpace.size() + 1;
  xmp_size -= nameSpace.size() + 1;
  XMPXmlHandler handler;

  // We need to remove tail data until the closing tag. Otherwise parser will throw an error.
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
    // Parse error
    return false;
  }

  // Apply default values to any not-present fields, except for Version,
  // maxContentBoost, and hdrCapacityMax, which are required. Return false if
  // we encounter a present field that couldn't be parsed, since this
  // indicates it is invalid (eg. string where there should be a float).
  bool present = false;
  if (!handler.getVersion(&metadata->version, &present) || !present) {
    return false;
  }
  if (!handler.getMaxContentBoost(&metadata->maxContentBoost, &present) || !present) {
    return false;
  }
  if (!handler.getHdrCapacityMax(&metadata->hdrCapacityMax, &present) || !present) {
    return false;
  }
  if (!handler.getMinContentBoost(&metadata->minContentBoost, &present)) {
    if (present) return false;
    metadata->minContentBoost = 1.0f;
  }
  if (!handler.getGamma(&metadata->gamma, &present)) {
    if (present) return false;
    metadata->gamma = 1.0f;
  }
  if (!handler.getOffsetSdr(&metadata->offsetSdr, &present)) {
    if (present) return false;
    metadata->offsetSdr = 1.0f / 64.0f;
  }
  if (!handler.getOffsetHdr(&metadata->offsetHdr, &present)) {
    if (present) return false;
    metadata->offsetHdr = 1.0f / 64.0f;
  }
  if (!handler.getHdrCapacityMin(&metadata->hdrCapacityMin, &present)) {
    if (present) return false;
    metadata->hdrCapacityMin = 1.0f;
  }

  bool base_rendition_is_hdr;
  if (!handler.getBaseRenditionIsHdr(&base_rendition_is_hdr, &present)) {
    if (present) return false;
    base_rendition_is_hdr = false;
  }
  if (base_rendition_is_hdr) {
    ALOGE("Base rendition of HDR is not supported!");
    return false;
  }

  return true;
}

string generateXmpForPrimaryImage(int secondary_image_length, ultrahdr_metadata_struct& metadata) {
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

string generateXmpForSecondaryImage(ultrahdr_metadata_struct& metadata) {
  const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});

  std::stringstream ss;
  photos_editing_formats::image_io::XmlWriter writer(ss);
  writer.StartWritingElement("x:xmpmeta");
  writer.WriteXmlns("x", "adobe:ns:meta/");
  writer.WriteAttributeNameAndValue("x:xmptk", "Adobe XMP Core 5.1.2");
  writer.StartWritingElement("rdf:RDF");
  writer.WriteXmlns("rdf", "http://www.w3.org/1999/02/22-rdf-syntax-ns#");
  writer.StartWritingElement("rdf:Description");
  writer.WriteXmlns(kGainMapPrefix, kGainMapUri);
  writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
  writer.WriteAttributeNameAndValue(kMapGainMapMin, log2(metadata.minContentBoost));
  writer.WriteAttributeNameAndValue(kMapGainMapMax, log2(metadata.maxContentBoost));
  writer.WriteAttributeNameAndValue(kMapGamma, metadata.gamma);
  writer.WriteAttributeNameAndValue(kMapOffsetSdr, metadata.offsetSdr);
  writer.WriteAttributeNameAndValue(kMapOffsetHdr, metadata.offsetHdr);
  writer.WriteAttributeNameAndValue(kMapHDRCapacityMin, log2(metadata.hdrCapacityMin));
  writer.WriteAttributeNameAndValue(kMapHDRCapacityMax, log2(metadata.hdrCapacityMax));
  writer.WriteAttributeNameAndValue(kMapBaseRenditionIsHDR, "False");
  writer.FinishWriting();

  return ss.str();
}

}  // namespace ultrahdr
