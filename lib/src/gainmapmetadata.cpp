/*
 * Copyright 2024 The Android Open Source Project
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

#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/gainmapmetadata.h"

namespace ultrahdr {

status_t streamWriteU8(std::vector<uint8_t> &data, uint8_t value) {
  data.push_back(value);
  return JPEGR_NO_ERROR;
}

status_t streamWriteU32(std::vector<uint8_t> &data, uint32_t value) {
  data.push_back((value >> 24) & 0xff);
  data.push_back((value >> 16) & 0xff);
  data.push_back((value >> 8) & 0xff);
  data.push_back(value & 0xff);
  return JPEGR_NO_ERROR;
}

status_t streamReadU8(const std::vector<uint8_t> &data, uint8_t &value, size_t &pos) {
  if (pos >= data.size()) {
    return ERROR_JPEGR_METADATA_ERROR;
  }
  value = data[pos++];
  return JPEGR_NO_ERROR;
}

status_t streamReadU32(const std::vector<uint8_t> &data, uint32_t &value, size_t &pos) {
  if (pos >= data.size() - 3) {
    return ERROR_JPEGR_METADATA_ERROR;
  }
  value = (data[pos] << 24 | data[pos + 1] << 16 | data[pos + 2] << 8 | data[pos + 3]);
  pos += 4;
  return JPEGR_NO_ERROR;
}

status_t gain_map_metadata::encodeGainmapMetadata(const gain_map_metadata *metadata,
                                                  std::vector<uint8_t> &out_data) {
  if (metadata == nullptr) {
    return ERROR_JPEGR_METADATA_ERROR;
  }

  const uint8_t version = 0;
  streamWriteU8(out_data, version);

  uint8_t flags = 0u;
  // Always write three channels for now for simplicity.
  // TODO(maryla): the draft says that this specifies the count of channels of the
  // gain map. But tone mapping is done in RGB space so there are always three
  // channels, even if the gain map is grayscale. Should this be revised?
  const bool allChannelsIdentical =
      metadata->gainMapMinN[0] == metadata->gainMapMinN[1] &&
      metadata->gainMapMinN[0] == metadata->gainMapMinN[2] &&
      metadata->gainMapMinD[0] == metadata->gainMapMinD[1] &&
      metadata->gainMapMinD[0] == metadata->gainMapMinD[2] &&
      metadata->gainMapMaxN[0] == metadata->gainMapMaxN[1] &&
      metadata->gainMapMaxN[0] == metadata->gainMapMaxN[2] &&
      metadata->gainMapMaxD[0] == metadata->gainMapMaxD[1] &&
      metadata->gainMapMaxD[0] == metadata->gainMapMaxD[2] &&
      metadata->gainMapGammaN[0] == metadata->gainMapGammaN[1] &&
      metadata->gainMapGammaN[0] == metadata->gainMapGammaN[2] &&
      metadata->gainMapGammaD[0] == metadata->gainMapGammaD[1] &&
      metadata->gainMapGammaD[0] == metadata->gainMapGammaD[2] &&
      metadata->baseOffsetN[0] == metadata->baseOffsetN[1] &&
      metadata->baseOffsetN[0] == metadata->baseOffsetN[2] &&
      metadata->baseOffsetD[0] == metadata->baseOffsetD[1] &&
      metadata->baseOffsetD[0] == metadata->baseOffsetD[2] &&
      metadata->alternateOffsetN[0] == metadata->alternateOffsetN[1] &&
      metadata->alternateOffsetN[0] == metadata->alternateOffsetN[2] &&
      metadata->alternateOffsetD[0] == metadata->alternateOffsetD[1] &&
      metadata->alternateOffsetD[0] == metadata->alternateOffsetD[2];
  const uint8_t channelCount = allChannelsIdentical ? 1u : 3u;

  if (channelCount == 3) {
    flags |= 1;
  }
  if (metadata->useBaseColorSpace) {
    flags |= 2;
  }
  if (metadata->backwardDirection) {
    flags |= 4;
  }

  const uint32_t denom = metadata->baseHdrHeadroomD;
  bool useCommonDenominator = true;
  if (metadata->baseHdrHeadroomD != denom || metadata->alternateHdrHeadroomD != denom) {
    useCommonDenominator = false;
  }
  for (int c = 0; c < channelCount; ++c) {
    if (metadata->gainMapMinD[c] != denom || metadata->gainMapMaxD[c] != denom ||
        metadata->gainMapGammaD[c] != denom || metadata->baseOffsetD[c] != denom ||
        metadata->alternateOffsetD[c] != denom) {
      useCommonDenominator = false;
    }
  }
  if (useCommonDenominator) {
    flags |= 8;
  }
  streamWriteU8(out_data, flags);

  if (useCommonDenominator) {
    streamWriteU32(out_data, denom);
    streamWriteU32(out_data, metadata->baseHdrHeadroomN);
    streamWriteU32(out_data, metadata->alternateHdrHeadroomN);
    for (int c = 0; c < channelCount; ++c) {
      streamWriteU32(out_data, (uint32_t)metadata->gainMapMinN[c]);
      streamWriteU32(out_data, (uint32_t)metadata->gainMapMaxN[c]);
      streamWriteU32(out_data, metadata->gainMapGammaN[c]);
      streamWriteU32(out_data, (uint32_t)metadata->baseOffsetN[c]);
      streamWriteU32(out_data, (uint32_t)metadata->alternateOffsetN[c]);
    }
  } else {
    streamWriteU32(out_data, metadata->baseHdrHeadroomN);
    streamWriteU32(out_data, metadata->baseHdrHeadroomD);
    streamWriteU32(out_data, metadata->alternateHdrHeadroomN);
    streamWriteU32(out_data, metadata->alternateHdrHeadroomD);
    for (int c = 0; c < channelCount; ++c) {
      streamWriteU32(out_data, (uint32_t)metadata->gainMapMinN[c]);
      streamWriteU32(out_data, metadata->gainMapMinD[c]);
      streamWriteU32(out_data, (uint32_t)metadata->gainMapMaxN[c]);
      streamWriteU32(out_data, metadata->gainMapMaxD[c]);
      streamWriteU32(out_data, metadata->gainMapGammaN[c]);
      streamWriteU32(out_data, metadata->gainMapGammaD[c]);
      streamWriteU32(out_data, (uint32_t)metadata->baseOffsetN[c]);
      streamWriteU32(out_data, metadata->baseOffsetD[c]);
      streamWriteU32(out_data, (uint32_t)metadata->alternateOffsetN[c]);
      streamWriteU32(out_data, metadata->alternateOffsetD[c]);
    }
  }

  return JPEGR_NO_ERROR;
}

status_t gain_map_metadata::decodeGainmapMetadata(const std::vector<uint8_t> &data,
                                                  gain_map_metadata *out_metadata) {
  if (out_metadata == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }

  size_t pos = 0;
  uint8_t version = 0xff;
  JPEGR_CHECK(streamReadU8(data, version, pos))

  if (version != 0) {
    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
  }

  uint8_t flags = 0xff;
  JPEGR_CHECK(streamReadU8(data, flags, pos))

  uint8_t channelCount = (flags & 1) * 2 + 1;

  if (!(channelCount == 1 || channelCount == 3)) {
    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
  }
  out_metadata->useBaseColorSpace = (flags & 2) != 0;
  out_metadata->backwardDirection = (flags & 4) != 0;
  const bool useCommonDenominator = (flags & 8) != 0;

  if (useCommonDenominator) {
    uint32_t commonDenominator;
    JPEGR_CHECK(streamReadU32(data, commonDenominator, pos))

    JPEGR_CHECK(streamReadU32(data, out_metadata->baseHdrHeadroomN, pos))
    out_metadata->baseHdrHeadroomD = commonDenominator;
    JPEGR_CHECK(streamReadU32(data, out_metadata->alternateHdrHeadroomN, pos))
    out_metadata->alternateHdrHeadroomD = commonDenominator;

    for (int c = 0; c < channelCount; ++c) {
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMinN[c], pos))
      out_metadata->gainMapMinD[c] = commonDenominator;
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMaxN[c], pos))
      out_metadata->gainMapMaxD[c] = commonDenominator;
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapGammaN[c], pos))
      out_metadata->gainMapGammaD[c] = commonDenominator;
      JPEGR_CHECK(streamReadU32(data, out_metadata->baseOffsetN[c], pos))
      out_metadata->baseOffsetD[c] = commonDenominator;
      JPEGR_CHECK(streamReadU32(data, out_metadata->alternateOffsetN[c], pos))
      out_metadata->alternateOffsetD[c] = commonDenominator;
    }
  } else {
    JPEGR_CHECK(streamReadU32(data, out_metadata->baseHdrHeadroomN, pos))
    JPEGR_CHECK(streamReadU32(data, out_metadata->baseHdrHeadroomD, pos))
    JPEGR_CHECK(streamReadU32(data, out_metadata->alternateHdrHeadroomN, pos))
    JPEGR_CHECK(streamReadU32(data, out_metadata->alternateHdrHeadroomD, pos))
    for (int c = 0; c < channelCount; ++c) {
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMinN[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMinD[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMaxN[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMaxD[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapGammaN[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapGammaD[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->baseOffsetN[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->baseOffsetD[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->alternateOffsetN[c], pos))
      JPEGR_CHECK(streamReadU32(data, out_metadata->alternateOffsetD[c], pos))
    }
  }

  // Fill the remaining values by copying those from the first channel.
  for (int c = channelCount; c < 3; ++c) {
    out_metadata->gainMapMinN[c] = out_metadata->gainMapMinN[0];
    out_metadata->gainMapMinD[c] = out_metadata->gainMapMinD[0];
    out_metadata->gainMapMaxN[c] = out_metadata->gainMapMaxN[0];
    out_metadata->gainMapMaxD[c] = out_metadata->gainMapMaxD[0];
    out_metadata->gainMapGammaN[c] = out_metadata->gainMapGammaN[0];
    out_metadata->gainMapGammaD[c] = out_metadata->gainMapGammaD[0];
    out_metadata->baseOffsetN[c] = out_metadata->baseOffsetN[0];
    out_metadata->baseOffsetD[c] = out_metadata->baseOffsetD[0];
    out_metadata->alternateOffsetN[c] = out_metadata->alternateOffsetN[0];
    out_metadata->alternateOffsetD[c] = out_metadata->alternateOffsetD[0];
  }

  return JPEGR_NO_ERROR;
}

#define CHECK_NOT_ZERO(x)                \
  do {                                   \
    if (x == 0) {                        \
      return ERROR_JPEGR_METADATA_ERROR; \
    }                                    \
  } while (0)

status_t gain_map_metadata::gainmapMetadataFractionToFloat(const gain_map_metadata *from,
                                                           ultrahdr_metadata_ptr to) {
  if (from == nullptr || to == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }

  CHECK_NOT_ZERO(from->baseHdrHeadroomD);
  CHECK_NOT_ZERO(from->alternateHdrHeadroomD);
  for (int i = 0; i < 3; ++i) {
    CHECK_NOT_ZERO(from->gainMapMaxD[i]);
    CHECK_NOT_ZERO(from->gainMapGammaD[i]);
    CHECK_NOT_ZERO(from->gainMapMinD[i]);
    CHECK_NOT_ZERO(from->baseOffsetD[i]);
    CHECK_NOT_ZERO(from->alternateOffsetD[i]);
  }
  to->version = kGainMapVersion;
  to->maxContentBoost = (float)from->gainMapMaxN[0] / from->gainMapMaxD[0];
  to->minContentBoost = (float)from->gainMapMinN[0] / from->gainMapMinD[0];
  to->gamma = (float)from->gainMapGammaN[0] / from->gainMapGammaD[0];

  // BaseRenditionIsHDR is false
  to->offsetSdr = (float)from->baseOffsetN[0] / from->baseOffsetD[0];
  to->offsetHdr = (float)from->alternateOffsetN[0] / from->alternateOffsetD[0];
  to->hdrCapacityMax = (float)from->alternateHdrHeadroomN / from->alternateHdrHeadroomD;
  to->hdrCapacityMin = (float)from->baseHdrHeadroomN / from->baseHdrHeadroomD;

  return JPEGR_NO_ERROR;
}

status_t gain_map_metadata::gainmapMetadataFloatToFraction(const ultrahdr_metadata_ptr from,
                                                           gain_map_metadata *to) {
  if (from == nullptr || to == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }

  to->backwardDirection = false;
  to->useBaseColorSpace = true;

  floatToUnsignedFraction(from->maxContentBoost, &to->gainMapMaxN[0], &to->gainMapMaxD[0]);
  to->gainMapMaxN[2] = to->gainMapMaxN[1] = to->gainMapMaxN[0];
  to->gainMapMaxD[2] = to->gainMapMaxD[1] = to->gainMapMaxD[0];

  floatToUnsignedFraction(from->minContentBoost, &to->gainMapMinN[0], &to->gainMapMinD[0]);
  to->gainMapMinN[2] = to->gainMapMinN[1] = to->gainMapMinN[0];
  to->gainMapMinD[2] = to->gainMapMinD[1] = to->gainMapMinD[0];

  floatToUnsignedFraction(from->gamma, &to->gainMapGammaN[0], &to->gainMapGammaD[0]);
  to->gainMapGammaN[2] = to->gainMapGammaN[1] = to->gainMapGammaN[0];
  to->gainMapGammaD[2] = to->gainMapGammaD[1] = to->gainMapGammaD[0];

  floatToUnsignedFraction(from->offsetSdr, &to->baseOffsetN[0], &to->baseOffsetD[0]);
  to->baseOffsetN[2] = to->baseOffsetN[1] = to->baseOffsetN[0];
  to->baseOffsetD[2] = to->baseOffsetD[1] = to->baseOffsetD[0];

  floatToUnsignedFraction(from->offsetHdr, &to->alternateOffsetN[0], &to->alternateOffsetD[0]);
  to->alternateOffsetN[2] = to->alternateOffsetN[1] = to->alternateOffsetN[0];
  to->alternateOffsetD[2] = to->alternateOffsetD[1] = to->alternateOffsetD[0];

  floatToUnsignedFraction(from->hdrCapacityMin, &to->baseHdrHeadroomN, &to->baseHdrHeadroomD);

  floatToUnsignedFraction(from->hdrCapacityMax, &to->alternateHdrHeadroomN,
                          &to->alternateHdrHeadroomD);

  return JPEGR_NO_ERROR;
}

}  // namespace ultrahdr
