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

#include <cstring>
#include <cstdint>

#include "ultrahdr/editorhelper.h"

namespace ultrahdr {

template <typename T>
void rotate_buffer_clockwise(T* src_buffer, T* dst_buffer, int src_w, int src_h, int src_stride,
                             int dst_stride, int degree) {
  if (degree == 90) {
    int dst_w = src_h;
    int dst_h = src_w;
    for (int i = 0; i < dst_h; i++) {
      for (int j = 0; j < dst_w; j++) {
        dst_buffer[i * dst_stride + j] = src_buffer[(src_h - j - 1) * src_stride + i];
      }
    }
  } else if (degree == 180) {
    int dst_w = src_w;
    int dst_h = src_h;
    for (int i = 0; i < dst_h; i++) {
      for (int j = 0; j < dst_w; j++) {
        dst_buffer[i * dst_stride + j] = src_buffer[(src_h - i - 1) * src_stride + (src_w - j - 1)];
      }
    }
  } else if (degree == 270) {
    int dst_w = src_h;
    int dst_h = src_w;
    for (int i = 0; i < dst_h; i++) {
      for (int j = 0; j < dst_w; j++) {
        dst_buffer[i * dst_stride + j] = src_buffer[j * src_stride + (src_w - i - 1)];
      }
    }
  }
}

template <typename T>
void mirror_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int src_stride,
                   int dst_stride, uhdr_mirror_direction_t direction) {
  if (direction == UHDR_MIRROR_VERTICAL) {
    for (int i = 0; i < src_h; i++) {
      memcpy(&dst_buffer[(src_h - i - 1) * dst_stride], &src_buffer[i * src_stride],
             src_w * sizeof(T));
    }
  } else if (direction == UHDR_MIRROR_HORIZONTAL) {
    for (int i = 0; i < src_h; i++) {
      for (int j = 0; j < src_w; j++) {
        dst_buffer[i * dst_stride + j] = src_buffer[i * src_stride + (src_w - j - 1)];
      }
    }
  }
}

template <typename T>
void resize_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int dst_w, int dst_h,
                   int src_stride, int dst_stride) {
  for (int i = 0; i < dst_h; i++) {
    for (int j = 0; j < dst_w; j++) {
      dst_buffer[i * dst_stride + j] =
          src_buffer[i * (src_h / dst_h) * src_stride + j * (src_w / dst_w)];
    }
  }
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(uhdr_raw_image_t* src, int degree) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst;

  if (degree == 90 || degree == 270) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->h,
                                                 src->w, 1);
  } else if (degree == 180) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->w,
                                                 src->h, 1);
  } else {
    return nullptr;
  }

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    rotate_buffer_clockwise(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                            dst->stride[UHDR_PLANE_Y], degree);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    rotate_buffer_clockwise(src_uv_buffer, dst_uv_buffer, src->w / 2, src->h / 2,
                            src->stride[UHDR_PLANE_UV] / 2, dst->stride[UHDR_PLANE_UV] / 2, degree);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    rotate_buffer_clockwise(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                            dst->stride[UHDR_PLANE_Y], degree);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        rotate_buffer_clockwise(src_buffer, dst_buffer, src->w / 2, src->h / 2, src->stride[i],
                                dst->stride[i], degree);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    rotate_buffer_clockwise(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], degree);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    rotate_buffer_clockwise(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], degree);
  }
  return std::move(dst);
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(uhdr_raw_image_t* src,
                                                   uhdr_mirror_direction_t direction) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
      src->fmt, src->cg, src->ct, src->range, src->w, src->h, 1);

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    mirror_buffer(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                  dst->stride[UHDR_PLANE_Y], direction);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    mirror_buffer(src_uv_buffer, dst_uv_buffer, src->w / 2, src->h / 2,
                  src->stride[UHDR_PLANE_UV] / 2, dst->stride[UHDR_PLANE_UV] / 2, direction);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    mirror_buffer(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                  dst->stride[UHDR_PLANE_Y], direction);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        mirror_buffer(src_buffer, dst_buffer, src->w / 2, src->h / 2, src->stride[i],
                      dst->stride[i], direction);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    mirror_buffer(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                  dst->stride[UHDR_PLANE_PACKED], direction);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    mirror_buffer(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                  dst->stride[UHDR_PLANE_PACKED], direction);
  }
  return std::move(dst);
}

void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht) {
  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    src->planes[UHDR_PLANE_Y] = &src_buffer[top * src->stride[UHDR_PLANE_Y] + left];
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    src->planes[UHDR_PLANE_UV] =
        &src_uv_buffer[(top / 2) * (src->stride[UHDR_PLANE_UV] / 2) + (left / 2)];
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    src->planes[UHDR_PLANE_Y] = &src_buffer[top * src->stride[UHDR_PLANE_Y] + left];
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src->planes[i] = &src_buffer[(top / 2) * src->stride[i] + (left / 2)];
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    src->planes[UHDR_PLANE_PACKED] = &src_buffer[top * src->stride[UHDR_PLANE_PACKED] + left];
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    src->planes[UHDR_PLANE_PACKED] = &src_buffer[top * src->stride[UHDR_PLANE_PACKED] + left];
  }
  src->w = wd;
  src->h = ht;
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(uhdr_raw_image_t* src, int dst_w, int dst_h) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
      src->fmt, src->cg, src->ct, src->range, dst_w, dst_h, 1);

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    resize_buffer(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h, src->stride[UHDR_PLANE_Y],
                  dst->stride[UHDR_PLANE_Y]);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    resize_buffer(src_uv_buffer, dst_uv_buffer, src->w / 4, src->h / 2, dst->w / 4, dst->h / 2,
                  src->stride[UHDR_PLANE_UV] / 2, dst->stride[UHDR_PLANE_UV] / 2);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    resize_buffer(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h, src->stride[UHDR_PLANE_Y],
                  dst->stride[UHDR_PLANE_Y]);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        resize_buffer(src_buffer, dst_buffer, src->w / 2, src->h / 2, dst->w / 2, dst->h / 2,
                      src->stride[i], dst->stride[i]);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    resize_buffer(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                  src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    resize_buffer(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                  src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
  }
  return std::move(dst);
}
}  // namespace ultrahdr
