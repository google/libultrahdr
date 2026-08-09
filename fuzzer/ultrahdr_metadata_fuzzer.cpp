/*
 * Copyright 2026 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include "ultrahdr/icc.h"
#include "ultrahdr/gainmapmetadata.h"
#include "ultrahdr/jpegrutils.h"
#include "ultrahdr/multipictureformat.h"

using namespace ultrahdr;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  int api_to_fuzz = fdp.ConsumeIntegralInRange<int>(0, 3);

  switch (api_to_fuzz) {
    case 0: {
      // Fuzz getMetadataFromXMP
      std::vector<uint8_t> xmp_data = fdp.ConsumeRemainingBytes<uint8_t>();
      uhdr_gainmap_metadata_ext_t metadata;
      getMetadataFromXMP(xmp_data.data(), xmp_data.size(), &metadata);
      break;
    }
    case 1: {
      // Fuzz generateMpf
      size_t primary_image_size = fdp.ConsumeIntegral<size_t>();
      size_t primary_image_offset = fdp.ConsumeIntegral<size_t>();
      size_t secondary_image_size = fdp.ConsumeIntegral<size_t>();
      size_t secondary_image_offset = fdp.ConsumeIntegral<size_t>();
      generateMpf(primary_image_size, primary_image_offset, secondary_image_size,
                  secondary_image_offset);
      break;
    }
    case 2: {
      // Fuzz ICC profile
      std::vector<uint8_t> icc_data = fdp.ConsumeRemainingBytes<uint8_t>();
      if (icc_data.size() > 0) {
        IccHelper::readIccColorGamut(icc_data.data(), icc_data.size());
      }
      break;
    }
    case 3: {
      // Fuzz Gainmap binary metadata (ISO 21496-1)
      std::vector<uint8_t> gm_data = fdp.ConsumeRemainingBytes<uint8_t>();
      if (gm_data.size() > 0) {
        uhdr_gainmap_metadata_frac decodedMetadata;
        uhdr_gainmap_metadata_frac::decodeGainmapMetadata(gm_data, &decodedMetadata);

        uhdr_gainmap_metadata_ext_t extMetadata;
        uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata, &extMetadata);
      }
      break;
    }
  }

  return 0;
}
