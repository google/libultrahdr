#ifndef ULTRAHDR_AVIFENCODER_H
#define ULTRAHDR_AVIFENCODER_H

#include <cstring>

#include "libheif/heif.h"

namespace ultrahdr {
namespace internal {

static inline heif_error get_encoder_for_format(heif_context* ctx,
                                                heif_compression_format format,
                                                bool use_realtime_aom_speed,
                                                heif_encoder** encoder) {
  if (!use_realtime_aom_speed || format != heif_compression_AV1) {
    return heif_context_get_encoder_for_format(ctx, format, encoder);
  }

  // The first descriptor is libheif's normal priority-selected encoder for this format.
  const heif_encoder_descriptor* descriptor = nullptr;
  if (heif_get_encoder_descriptors(format, nullptr, &descriptor, 1) <= 0 ||
      descriptor == nullptr) {
    return heif_context_get_encoder_for_format(ctx, format, encoder);
  }

  heif_error error = heif_context_get_encoder(ctx, descriptor, encoder);
  if (error.code != heif_error_Ok) return error;

  const char* encoder_id = heif_encoder_descriptor_get_id_name(descriptor);
  if (encoder_id == nullptr || std::strcmp(encoder_id, "aom") != 0) return error;

  error = heif_encoder_set_parameter_integer(*encoder, "speed", 8);
  if (error.code != heif_error_Ok &&
      !(error.code == heif_error_Usage_error &&
        error.subcode == heif_suberror_Unsupported_parameter)) {
    return error;
  }

  return {heif_error_Ok, heif_suberror_Unspecified, nullptr};
}

}  // namespace internal
}  // namespace ultrahdr

#endif  // ULTRAHDR_AVIFENCODER_H
