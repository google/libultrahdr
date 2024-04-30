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

#include <arm_neon.h>
#include <cstring>

#include "ultrahdr/editorhelper.h"

namespace ultrahdr {

#define vrev128q_u8(src, dst) \
  dst = vrev64q_u8(src);      \
  dst = vextq_u8(dst, dst, 8);

#define vrev128q_u16(src, dst) \
  dst = vrev64q_u16(src);      \
  dst = vextq_u16(dst, dst, 4);

#define vrev128q_u32(src, dst) \
  dst = vrev64q_u32(src);      \
  dst = vextq_u32(dst, dst, 2);

#define vrev128q_u64(a) a = vextq_u64(a, a, 1)

static void mirror_buffer_horizontal_neon_uint8_t(uint8_t* src_buffer, uint8_t* dst_buffer,
                                                  int src_w, int src_h, int src_stride,
                                                  int dst_stride) {
  uint8_t* src_row = src_buffer;
  uint8_t* dst_row = dst_buffer;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row += dst_stride) {
    uint8_t* src_blk = src_row + src_w;
    uint8_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 64 <= src_w; src_blk -= 64, dst_blk += 64, j += 64) {
      uint8x16x4_t s0 = vld1q_u8_x4(src_blk - 64);
      uint8x16x4_t d0;
      vrev128q_u8(s0.val[0], d0.val[3]);
      vrev128q_u8(s0.val[1], d0.val[2]);
      vrev128q_u8(s0.val[2], d0.val[1]);
      vrev128q_u8(s0.val[3], d0.val[0]);
      vst1q_u8_x4(dst_blk, d0);
    }

    for (; j + 32 <= src_w; src_blk -= 32, dst_blk += 32, j += 32) {
      uint8x16x2_t s0 = vld1q_u8_x2(src_blk - 32);
      uint8x16x2_t d0;
      vrev128q_u8(s0.val[0], d0.val[1]);
      vrev128q_u8(s0.val[1], d0.val[0]);
      vst1q_u8_x2(dst_blk, d0);
    }

    for (; j + 16 <= src_w; src_blk -= 16, dst_blk += 16, j += 16) {
      uint8x16_t s0 = vld1q_u8(src_blk - 16);
      vrev128q_u8(s0, s0);
      vst1q_u8(dst_blk, s0);
    }

    for (; j + 8 <= src_w; src_blk -= 8, dst_blk += 8, j += 8) {
      uint8x8_t s0 = vld1_u8(src_blk - 8);
      s0 = vrev64_u8(s0);
      vst1_u8(dst_blk, s0);
    }

    for (int k = 0; k < src_w - j; k++) {
      dst_blk[k] = src_row[src_w - j - k - 1];
    }
  }
}

static void mirror_buffer_horizontal_neon_uint16_t(uint16_t* src_buffer, uint16_t* dst_buffer,
                                                   int src_w, int src_h, int src_stride,
                                                   int dst_stride) {
  uint16_t* src_row = src_buffer;
  uint16_t* dst_row = dst_buffer;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row += dst_stride) {
    uint16_t* src_blk = src_row + src_w;
    uint16_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 32 <= src_w; src_blk -= 32, dst_blk += 32, j += 32) {
      uint16x8x4_t s0 = vld1q_u16_x4(src_blk - 32);
      uint16x8x4_t d0;
      vrev128q_u16(s0.val[0], d0.val[3]);
      vrev128q_u16(s0.val[1], d0.val[2]);
      vrev128q_u16(s0.val[2], d0.val[1]);
      vrev128q_u16(s0.val[3], d0.val[0]);
      vst1q_u16_x4(dst_blk, d0);
    }

    for (; j + 16 <= src_w; src_blk -= 16, dst_blk += 16, j += 16) {
      uint16x8x2_t s0 = vld1q_u16_x2(src_blk - 16);
      uint16x8x2_t d0;
      vrev128q_u16(s0.val[0], d0.val[1]);
      vrev128q_u16(s0.val[1], d0.val[0]);
      vst1q_u16_x2(dst_blk, d0);
    }

    for (; j + 8 <= src_w; src_blk -= 8, dst_blk += 8, j += 8) {
      uint16x8_t s0 = vld1q_u16(src_blk - 8);
      vrev128q_u16(s0, s0);
      vst1q_u16(dst_blk, s0);
    }

    for (int k = 0; k < src_w - j; k++) {
      dst_blk[k] = src_row[src_w - j - k - 1];
    }
  }
}

static void mirror_buffer_horizontal_neon_uint32_t(uint32_t* src_buffer, uint32_t* dst_buffer,
                                                   int src_w, int src_h, int src_stride,
                                                   int dst_stride) {
  uint32_t* src_row = src_buffer;
  uint32_t* dst_row = dst_buffer;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row += dst_stride) {
    uint32_t* src_blk = src_row + src_w;
    uint32_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 16 <= src_w; src_blk -= 16, dst_blk += 16, j += 16) {
      uint32x4x4_t s0 = vld1q_u32_x4(src_blk - 16);
      uint32x4x4_t d0;
      vrev128q_u32(s0.val[0], d0.val[3]);
      vrev128q_u32(s0.val[1], d0.val[2]);
      vrev128q_u32(s0.val[2], d0.val[1]);
      vrev128q_u32(s0.val[3], d0.val[0]);
      vst1q_u32_x4(dst_blk, d0);
    }

    for (; j + 8 <= src_w; src_blk -= 8, dst_blk += 8, j += 8) {
      uint32x4x2_t s0 = vld1q_u32_x2(src_blk - 8);
      uint32x4x2_t d0;
      vrev128q_u32(s0.val[0], d0.val[1]);
      vrev128q_u32(s0.val[1], d0.val[0]);
      vst1q_u32_x2(dst_blk, d0);
    }

    for (; j + 4 <= src_w; src_blk -= 4, dst_blk += 4, j += 4) {
      uint32x4_t s0 = vld1q_u32(src_blk - 4);
      vrev128q_u32(s0, s0);
      vst1q_u32(dst_blk, s0);
    }

    for (int k = 0; k < src_w - j; k++) {
      dst_blk[k] = src_row[src_w - j - k - 1];
    }
  }
}

static void mirror_buffer_horizontal_neon_uint64_t(uint64_t* src_buffer, uint64_t* dst_buffer,
                                                   int src_w, int src_h, int src_stride,
                                                   int dst_stride) {
  uint64_t* src_row = src_buffer;
  uint64_t* dst_row = dst_buffer;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row += dst_stride) {
    uint64_t* src_blk = src_row + src_w;
    uint64_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 2 <= src_w; src_blk -= 2, dst_blk += 2, j += 2) {
      uint64x2_t s0 = vld1q_u64(src_blk - 2);
      vrev128q_u64(s0);
      vst1q_u64(dst_blk, s0);
    }
    for (int k = 0; k < src_w - j; k++) {
      dst_blk[k] = src_row[src_w - j - k - 1];
    }
  }
}

static void mirror_buffer_vertical_neon_uint8_t(uint8_t* src_buffer, uint8_t* dst_buffer, int src_w,
                                                int src_h, int src_stride, int dst_stride) {
  uint8_t* src_row = src_buffer;
  uint8_t* dst_row = dst_buffer + (src_h - 1) * dst_stride;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row -= dst_stride) {
    uint8_t* src_blk = src_row;
    uint8_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 64 <= src_w; src_blk += 64, dst_blk += 64, j += 64) {
      uint8x16x4_t s0 = vld1q_u8_x4(src_blk);
      vst1q_u8_x4(dst_blk, s0);
    }

    for (; j + 32 <= src_w; src_blk += 32, dst_blk += 32, j += 32) {
      uint8x16x2_t s0 = vld1q_u8_x2(src_blk);
      vst1q_u8_x2(dst_blk, s0);
    }

    for (; j + 16 <= src_w; src_blk += 16, dst_blk += 16, j += 16) {
      uint8x16_t s0 = vld1q_u8(src_blk);
      vst1q_u8(dst_blk, s0);
    }

    for (; j + 8 <= src_w; src_blk += 8, dst_blk += 8, j += 8) {
      uint8x8_t s0 = vld1_u8(src_blk);
      vst1_u8(dst_blk, s0);
    }

    if (j < src_w) memcpy(dst_blk, src_blk, src_w - j);
  }
}

static void mirror_buffer_vertical_neon_uint16_t(uint16_t* src_buffer, uint16_t* dst_buffer,
                                                 int src_w, int src_h, int src_stride,
                                                 int dst_stride) {
  uint16_t* src_row = src_buffer;
  uint16_t* dst_row = dst_buffer + (src_h - 1) * dst_stride;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row -= dst_stride) {
    uint16_t* src_blk = src_row;
    uint16_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 32 <= src_w; src_blk += 32, dst_blk += 32, j += 32) {
      uint16x8x4_t s0 = vld1q_u16_x4(src_blk);
      vst1q_u16_x4(dst_blk, s0);
    }

    for (; j + 16 <= src_w; src_blk += 16, dst_blk += 16, j += 16) {
      uint16x8x2_t s0 = vld1q_u16_x2(src_blk);
      vst1q_u16_x2(dst_blk, s0);
    }

    for (; j + 8 <= src_w; src_blk += 8, dst_blk += 8, j += 8) {
      uint16x8_t s0 = vld1q_u16(src_blk);
      vst1q_u16(dst_blk, s0);
    }

    if (j < src_w) memcpy(dst_blk, src_blk, (src_w - j) * sizeof(uint16_t));
  }
}

static void mirror_buffer_vertical_neon_uint32_t(uint32_t* src_buffer, uint32_t* dst_buffer,
                                                 int src_w, int src_h, int src_stride,
                                                 int dst_stride) {
  uint32_t* src_row = src_buffer;
  uint32_t* dst_row = dst_buffer + (src_h - 1) * dst_stride;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row -= dst_stride) {
    uint32_t* src_blk = src_row;
    uint32_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 16 <= src_w; src_blk += 16, dst_blk += 16, j += 16) {
      uint32x4x4_t s0 = vld1q_u32_x4(src_blk);
      vst1q_u32_x4(dst_blk, s0);
    }

    for (; j + 8 <= src_w; src_blk += 8, dst_blk += 8, j += 8) {
      uint32x4x2_t s0 = vld1q_u32_x2(src_blk);
      vst1q_u32_x2(dst_blk, s0);
    }

    for (; j + 4 <= src_w; src_blk += 4, dst_blk += 4, j += 4) {
      uint32x4_t s0 = vld1q_u32(src_blk);
      vst1q_u32(dst_blk, s0);
    }

    if (j < src_w) memcpy(dst_blk, src_blk, (src_w - j) * sizeof(uint32_t));
  }
}

static void mirror_buffer_vertical_neon_uint64_t(uint64_t* src_buffer, uint64_t* dst_buffer,
                                                 int src_w, int src_h, int src_stride,
                                                 int dst_stride) {
  uint64_t* src_row = src_buffer;
  uint64_t* dst_row = dst_buffer + (src_h - 1) * dst_stride;

  for (int i = 0; i < src_h; i++, src_row += src_stride, dst_row -= dst_stride) {
    uint64_t* src_blk = src_row;
    uint64_t* dst_blk = dst_row;
    int j = 0;

    for (; j + 2 <= src_w; src_blk += 2, dst_blk += 2, j += 2) {
      uint64x2_t s0 = vld1q_u64(src_blk);
      vst1q_u64(dst_blk, s0);
    }

    if (j < src_w) memcpy(dst_blk, src_blk, (src_w - j) * sizeof(uint64_t));
  }
}

template <typename T>
void mirror_buffer_neon(T* src_buffer, T* dst_buffer, int src_w, int src_h, int src_stride,
                        int dst_stride, uhdr_mirror_direction_t direction) {
  if (direction == UHDR_MIRROR_VERTICAL) {
    if constexpr (sizeof(T) == 1) {
      mirror_buffer_vertical_neon_uint8_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                          dst_stride);
    } else if constexpr (sizeof(T) == 2) {
      mirror_buffer_vertical_neon_uint16_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                           dst_stride);
    } else if constexpr (sizeof(T) == 4) {
      mirror_buffer_vertical_neon_uint32_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                           dst_stride);
    } else if constexpr (sizeof(T) == 8) {
      mirror_buffer_vertical_neon_uint64_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                           dst_stride);
    }

  } else if (direction == UHDR_MIRROR_HORIZONTAL) {
    if constexpr (sizeof(T) == 1) {
      mirror_buffer_horizontal_neon_uint8_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                            dst_stride);
    } else if constexpr (sizeof(T) == 2) {
      mirror_buffer_horizontal_neon_uint16_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                             dst_stride);
    } else if constexpr (sizeof(T) == 4) {
      mirror_buffer_horizontal_neon_uint32_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                             dst_stride);
    } else if constexpr (sizeof(T) == 8) {
      mirror_buffer_horizontal_neon_uint64_t(src_buffer, dst_buffer, src_w, src_h, src_stride,
                                             dst_stride);
    }
  }
}

template <typename T>
void rotate_buffer_clockwise_180_neon(T* src_buffer, T* dst_buffer, int src_w, int src_h,
                                      int src_stride, int dst_stride) {
  if constexpr (sizeof(T) == 1) {
    mirror_buffer_horizontal_neon_uint8_t(src_buffer + (src_h - 1) * src_stride, dst_buffer, src_w,
                                          src_h, -src_stride, dst_stride);
  } else if constexpr (sizeof(T) == 2) {
    mirror_buffer_horizontal_neon_uint16_t(src_buffer + (src_h - 1) * src_stride, dst_buffer, src_w,
                                           src_h, -src_stride, dst_stride);
  } else if constexpr (sizeof(T) == 4) {
    mirror_buffer_horizontal_neon_uint32_t(src_buffer + (src_h - 1) * src_stride, dst_buffer, src_w,
                                           src_h, -src_stride, dst_stride);
  } else if constexpr (sizeof(T) == 8) {
    mirror_buffer_horizontal_neon_uint64_t(src_buffer + (src_h - 1) * src_stride, dst_buffer, src_w,
                                           src_h, -src_stride, dst_stride);
  }
}

template <typename T>
void rotate_buffer_clockwise_neon(T* src_buffer, T* dst_buffer, int src_w, int src_h,
                                  int src_stride, int dst_stride, int degrees) {
  if (degrees == 180) {
    rotate_buffer_clockwise_180_neon(src_buffer, dst_buffer, src_w, src_h, src_stride, dst_stride);

  } else {
    rotate_buffer_clockwise(src_buffer, dst_buffer, src_w, src_h, src_stride, dst_stride, degrees);
  }
}

template void mirror_buffer_neon<uint8_t>(uint8_t*, uint8_t*, int, int, int, int,
                                          uhdr_mirror_direction_t);
template void mirror_buffer_neon<uint16_t>(uint16_t*, uint16_t*, int, int, int, int,
                                           uhdr_mirror_direction_t);
template void mirror_buffer_neon<uint32_t>(uint32_t*, uint32_t*, int, int, int, int,
                                           uhdr_mirror_direction_t);
template void mirror_buffer_neon<uint64_t>(uint64_t*, uint64_t*, int, int, int, int,
                                           uhdr_mirror_direction_t);

template void rotate_buffer_clockwise_neon<uint8_t>(uint8_t*, uint8_t*, int, int, int, int, int);
template void rotate_buffer_clockwise_neon<uint16_t>(uint16_t*, uint16_t*, int, int, int, int, int);
template void rotate_buffer_clockwise_neon<uint32_t>(uint32_t*, uint32_t*, int, int, int, int, int);
template void rotate_buffer_clockwise_neon<uint64_t>(uint64_t*, uint64_t*, int, int, int, int, int);

}  // namespace ultrahdr