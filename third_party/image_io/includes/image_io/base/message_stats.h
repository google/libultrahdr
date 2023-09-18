#ifndef IMAGE_IO_BASE_MESSAGE_STATS_H_  // NOLINT
#define IMAGE_IO_BASE_MESSAGE_STATS_H_  // NOLINT

#include "image_io/base/types.h"

namespace photos_editing_formats {
namespace image_io {

/// A structure for holding message stats.
struct MessageStats {
  MessageStats() { Clear(); }
  void Clear() { error_count = warning_count = status_count = 0; }
  size_t error_count;
  size_t warning_count;
  size_t status_count;
};

}  // namespace image_io
}  // namespace photos_editing_formats

#endif  // IMAGE_IO_BASE_MESSAGE_STATS_H_  // NOLINT
