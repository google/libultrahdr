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

#ifndef ULTRAHDR_GAINMAPMETADATA_H
#define ULTRAHDR_GAINMAPMETADATA_H

#include "ultrahdr/ultrahdr.h"

#include <memory>
#include <vector>

namespace ultrahdr {
  // Gain map metadata, for tone mapping between SDR and HDR.
  // This is the fraction version of {@code ultrahdr_metadata_struct}.
  struct gain_map_metadata {
    uint32_t gainMapMinN[3];
    uint32_t gainMapMinD[3];
    uint32_t gainMapMaxN[3];
    uint32_t gainMapMaxD[3];
    uint32_t gainMapGammaN[3];
    uint32_t gainMapGammaD[3];

    uint32_t baseOffsetN[3];
    uint32_t baseOffsetD[3];
    uint32_t alternateOffsetN[3];
    uint32_t alternateOffsetD[3];

    uint32_t baseHdrHeadroomN;
    uint32_t baseHdrHeadroomD;
    uint32_t alternateHdrHeadroomN;
    uint32_t alternateHdrHeadroomD;

    bool backwardDirection;
    bool useBaseColorSpace;

    static status_t encodeGainmapMetadata(const gain_map_metadata* gain_map_metadata,
                                          std::vector<uint8_t> &out_data);

    static status_t decodeGainmapMetadata(const std::vector<uint8_t> &data,
                                          gain_map_metadata* out_gain_map_metadata);

    static status_t gainmapMetadataFractionToFloat(const gain_map_metadata* from,
                                                   ultrahdr_metadata_ptr to);

    static status_t gainmapMetadataFloatToFraction(const ultrahdr_metadata_ptr from,
                                                   gain_map_metadata* to);

    void dump() const {
      printf("GAIN MAP METADATA: \n");
      printf("min numerator:                       %d, %d, %d\n",
              gainMapMinN[0], gainMapMinN[1], gainMapMinN[2]);
      printf("min denominator:                     %d, %d, %d\n",
              gainMapMinD[0], gainMapMinD[1], gainMapMinD[2]);
      printf("max numerator:                       %d, %d, %d\n",
              gainMapMaxN[0], gainMapMaxN[1], gainMapMaxN[2]);
      printf("max denominator:                     %d, %d, %d\n",
              gainMapMaxD[0], gainMapMaxD[1], gainMapMaxD[2]);
      printf("gamma numerator:                     %d, %d, %d\n",
              gainMapGammaN[0], gainMapGammaN[1], gainMapGammaN[2]);
      printf("gamma denominator:                   %d, %d, %d\n",
              gainMapGammaD[0], gainMapGammaD[1], gainMapGammaD[2]);
      printf("SDR offset numerator:                %d, %d, %d\n",
              baseOffsetN[0], baseOffsetN[1], baseOffsetN[2]);
      printf("SDR offset denominator:              %d, %d, %d\n",
              baseOffsetD[0], baseOffsetD[1], baseOffsetD[2]);
      printf("HDR offset numerator:                %d, %d, %d\n",
              alternateOffsetN[0], alternateOffsetN[1], alternateOffsetN[2]);
      printf("HDR offset denominator:              %d, %d, %d\n",
              alternateOffsetD[0], alternateOffsetD[1], alternateOffsetD[2]);
      printf("base HDR head room numerator:        %d\n",
              baseHdrHeadroomN);
      printf("base HDR head room denominator:      %d\n",
              baseHdrHeadroomD);
      printf("alternate HDR head room numerator:   %d\n",
              alternateHdrHeadroomN);
      printf("alternate HDR head room denominator: %d\n",
              alternateHdrHeadroomD);
      printf("backwardDirection:                   %s\n",
              backwardDirection ? "true" : "false");
      printf("use base color space:                %s\n",
              useBaseColorSpace ? "true" : "false");
    }
  };
}  // namespace ultrahdr

#endif  // ULTRAHDR_GAINMAPMETADATA_H
