/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef ULTRAHDR_AGTM_H
#define ULTRAHDR_AGTM_H

#include <memory>

#include "ultrahdr_api.h"
#include "ultrahdr/gainmapmath.h"

#ifdef UHDR_ENABLE_SMPTE2094_50
namespace smpte2094_50 {
struct DynamicMetadata;
}

namespace ultrahdr {

/**
 * Generates a gain map from an image and SMPTE 2094-50 dynamic metadata.
 *
 * @param image The input HDR image.
 * @param metadata The SMPTE 2094-50 dynamic metadata.
 * @param gainmap_metadata Output gain map metadata.
 * @param gainmap_img Output gain map image.
 * @param hdr_capacity_max Maximum display boost value for which the map is applied completely.
 * @return UHDR_CODEC_OK on success, or an error code on failure.
 */
uhdr_error_info_t generateGainMap(uhdr_raw_image_t* image,
                                  const smpte2094_50::DynamicMetadata& metadata,
                                  uhdr_gainmap_metadata_ext_t* gainmap_metadata,
                                  std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                  float hdr_capacity_max = -1.0f);

}  // namespace ultrahdr
#endif

#endif  // ULTRAHDR_AGTM_H
