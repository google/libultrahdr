/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <fuzzer/FuzzedDataProvider.h>

#include <string>

#include "ultrahdr/jpegrutils.h"
#include "ultrahdr/ultrahdrcommon.h"

using namespace ultrahdr;

// APP1 XMP identifier, as it appears on the wire ahead of the XML payload.
static const std::string kXmpNameSpace = std::string("http://ns.adobe.com/xap/1.0/\0", 29);

// The primary image XMP packet of a JPEG is attacker controlled: when a gain
// map is appended to an already compressed base image, that image's APP1 packet
// is inherited verbatim and handed to generateXmpForPrimaryImage(), which
// parses it, resolves namespace prefixes, rewrites the encoder owned gain map
// description in place and serializes the result. This target drives that code,
// and the XMP reader, with arbitrary bytes.
class UltraHdrXmpFuzzer {
 public:
  UltraHdrXmpFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
  void process();

 private:
  void parseXmpPacket(const std::string& xml);

  FuzzedDataProvider mFdp;
};

void UltraHdrXmpFuzzer::parseXmpPacket(const std::string& xml) {
  std::string packet = kXmpNameSpace;
  packet.append(xml);
  uhdr_gainmap_metadata_ext_t parsed;
  (void)getMetadataFromXMP(reinterpret_cast<uint8_t*>(packet.data()), packet.size(),
                           /* exif_data= */ nullptr, /* exif_size= */ 0, &parsed);
}

void UltraHdrXmpFuzzer::process() {
  uhdr_gainmap_metadata_ext_t metadata("1.0");
  bool are_all_channels_identical = mFdp.ConsumeBool();
  int channels = are_all_channels_identical ? 1 : 3;
  for (int i = 0; i < channels; i++) {
    metadata.max_content_boost[i] = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
    metadata.min_content_boost[i] = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
    metadata.gamma[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5.0f);
    metadata.offset_sdr[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
    metadata.offset_hdr[i] = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
  }
  if (are_all_channels_identical) {
    for (int i = 1; i < 3; i++) {
      metadata.max_content_boost[i] = metadata.max_content_boost[0];
      metadata.min_content_boost[i] = metadata.min_content_boost[0];
      metadata.gamma[i] = metadata.gamma[0];
      metadata.offset_sdr[i] = metadata.offset_sdr[0];
      metadata.offset_hdr[i] = metadata.offset_hdr[0];
    }
  }
  metadata.hdr_capacity_min = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
  metadata.hdr_capacity_max = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
  metadata.use_base_cg = mFdp.ConsumeBool();

  size_t secondary_image_length = mFdp.ConsumeIntegral<uint32_t>();
  bool supply_user_xmp = mFdp.ConsumeBool();
  std::string user_xmp = mFdp.ConsumeRemainingBytesAsString();

  // Merge path. An empty return value means the packet was rejected; the
  // encoder turns that into UHDR_CODEC_INVALID_PARAM.
  std::string merged;
  if (supply_user_xmp) {
    uhdr_mem_block_t user_block{user_xmp.data(), user_xmp.size(), user_xmp.size()};
    merged = generateXmpForPrimaryImage(secondary_image_length, metadata, &user_block);
  } else {
    merged = generateXmpForPrimaryImage(secondary_image_length, metadata, nullptr);
  }

  // Whatever the merge emits must survive our own reader.
  if (!merged.empty()) parseXmpPacket(merged);

  // Also drive the reader directly with the untrusted packet.
  if (!user_xmp.empty()) parseXmpPacket(user_xmp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  UltraHdrXmpFuzzer fuzzHandle(data, size);
  fuzzHandle.process();
  return 0;
}
