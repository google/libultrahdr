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
#include <cmath>

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

// TODO (dichenzhang): legacy method, need to be removed
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

// This function performs bicubic interpolation on a 1D signal.
double bicubic_interpolate(double p0, double p1, double p2, double p3, double x) {
  // Calculate the weights for the four neighboring points.
  double w0 = (1 - x) * (1 - x) * (1 - x);
  double w1 = 3 * x * (1 - x) * (1 - x);
  double w2 = 3 * x * x * (1 - x);
  double w3 = x * x * x;

  // Calculate the interpolated value.
  return w0 * p0 + w1 * p1 + w2 * p2 + w3 * p3;
}

template <typename T>
void resize_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int dst_w, int dst_h,
                   int src_stride, int dst_stride, uhdr_img_fmt_t img_fmt, size_t plane) {
  double scale_x = (double)src_w / dst_w;
  double scale_y = (double)src_h / dst_h;
  for (int y = 0; y < dst_h; y++) {
    for (int x = 0; x < dst_w; x++) {
      double ori_x = x * scale_x;
      double ori_y = y * scale_y;
      int p0_x = (int)floor(ori_x);
      int p0_y = (int)floor(ori_y);
      int p1_x = p0_x + 1;
      int p1_y = p0_y;
      int p2_x = p0_x;
      int p2_y = p0_y + 1;
      int p3_x = p0_x + 1;
      int p3_y = p0_y + 1;

      if ((img_fmt == UHDR_IMG_FMT_8bppYCbCr400) ||
          (img_fmt == UHDR_IMG_FMT_12bppYCbCr420 && plane == UHDR_PLANE_Y) ||
          (img_fmt == UHDR_IMG_FMT_12bppYCbCr420 && plane == UHDR_PLANE_U) ||
          (img_fmt == UHDR_IMG_FMT_12bppYCbCr420 && plane == UHDR_PLANE_V)) {
        double p0 = (double)src_buffer[p0_y * src_stride + p0_x];
        double p1 = (double)src_buffer[p1_y * src_stride + p1_x];
        double p2 = (double)src_buffer[p2_y * src_stride + p2_x];
        double p3 = (double)src_buffer[p3_y * src_stride + p3_x];

        double new_pix_val = bicubic_interpolate(p0, p1, p2, p3, ori_x - p0_x);

        dst_buffer[y * dst_stride + x] = (uint8_t)floor(new_pix_val + 0.5);
      } else {
        // Unsupported feature.
        return;
      }
    }
  }
}

template void mirror_buffer<uint8_t>(uint8_t*, uint8_t*, int, int, int, int,
                                     uhdr_mirror_direction_t);
template void mirror_buffer<uint16_t>(uint16_t*, uint16_t*, int, int, int, int,
                                      uhdr_mirror_direction_t);
template void mirror_buffer<uint32_t>(uint32_t*, uint32_t*, int, int, int, int,
                                      uhdr_mirror_direction_t);
template void mirror_buffer<uint64_t>(uint64_t*, uint64_t*, int, int, int, int,
                                      uhdr_mirror_direction_t);

template void rotate_buffer_clockwise<uint8_t>(uint8_t*, uint8_t*, int, int, int, int, int);
template void rotate_buffer_clockwise<uint16_t>(uint16_t*, uint16_t*, int, int, int, int, int);
template void rotate_buffer_clockwise<uint32_t>(uint32_t*, uint32_t*, int, int, int, int, int);
template void rotate_buffer_clockwise<uint64_t>(uint64_t*, uint64_t*, int, int, int, int, int);

template void resize_buffer<uint8_t>(uint8_t*, uint8_t*, int, int, int, int, int, int);
template void resize_buffer<uint16_t>(uint16_t*, uint16_t*, int, int, int, int, int, int);
template void resize_buffer<uint32_t>(uint32_t*, uint32_t*, int, int, int, int, int, int);
template void resize_buffer<uint64_t>(uint64_t*, uint64_t*, int, int, int, int, int, int);

uhdr_mirror_effect::uhdr_mirror_effect(uhdr_mirror_direction_t direction) : m_direction{direction} {
  m_mirror_uint8_t = mirror_buffer<uint8_t>;
  m_mirror_uint16_t = mirror_buffer<uint16_t>;
  m_mirror_uint32_t = mirror_buffer<uint32_t>;
  m_mirror_uint64_t = mirror_buffer<uint64_t>;
}

uhdr_rotate_effect::uhdr_rotate_effect(int degree) : m_degree{degree} {
  m_rotate_uint8_t = rotate_buffer_clockwise<uint8_t>;
  m_rotate_uint16_t = rotate_buffer_clockwise<uint16_t>;
  m_rotate_uint32_t = rotate_buffer_clockwise<uint32_t>;
  m_rotate_uint64_t = rotate_buffer_clockwise<uint64_t>;
}

uhdr_resize_effect::uhdr_resize_effect(int width, int height) : m_width{width}, m_height{height} {
  m_resize_uint8_t = resize_buffer<uint8_t>;
  m_resize_uint16_t = resize_buffer<uint16_t>;
  m_resize_uint32_t = resize_buffer<uint32_t>;
  m_resize_uint64_t = resize_buffer<uint64_t>;
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(ultrahdr::uhdr_rotate_effect_t* desc,
                                                   uhdr_raw_image_t* src) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst;

  if (desc->m_degree == 90 || desc->m_degree == 270) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->h,
                                                 src->w, 1);
  } else if (desc->m_degree == 180) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->w,
                                                 src->h, 1);
  } else {
    return nullptr;
  }

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_rotate_uint16_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                            dst->stride[UHDR_PLANE_Y], desc->m_degree);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    desc->m_rotate_uint32_t(src_uv_buffer, dst_uv_buffer, src->w / 2, src->h / 2,
                            src->stride[UHDR_PLANE_UV] / 2, dst->stride[UHDR_PLANE_UV] / 2,
                            desc->m_degree);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_rotate_uint8_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                           dst->stride[UHDR_PLANE_Y], desc->m_degree);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        desc->m_rotate_uint8_t(src_buffer, dst_buffer, src->w / 2, src->h / 2, src->stride[i],
                               dst->stride[i], desc->m_degree);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_rotate_uint32_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], desc->m_degree);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_rotate_uint64_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], desc->m_degree);
  }
  return std::move(dst);
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(ultrahdr::uhdr_mirror_effect_t* desc,
                                                   uhdr_raw_image_t* src) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
      src->fmt, src->cg, src->ct, src->range, src->w, src->h, 1);

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_mirror_uint16_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                            dst->stride[UHDR_PLANE_Y], desc->m_direction);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    desc->m_mirror_uint32_t(src_uv_buffer, dst_uv_buffer, src->w / 2, src->h / 2,
                            src->stride[UHDR_PLANE_UV] / 2, dst->stride[UHDR_PLANE_UV] / 2,
                            desc->m_direction);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_mirror_uint8_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_Y],
                           dst->stride[UHDR_PLANE_Y], desc->m_direction);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        desc->m_mirror_uint8_t(src_buffer, dst_buffer, src->w / 2, src->h / 2, src->stride[i],
                               dst->stride[i], desc->m_direction);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_mirror_uint32_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], desc->m_direction);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_mirror_uint64_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], desc->m_direction);
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

std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_t* desc,
                                                   uhdr_raw_image_t* src, int dst_w, int dst_h) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
      src->fmt, src->cg, src->ct, src->range, dst_w, dst_h, 1);

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_resize_uint16_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                            src->stride[UHDR_PLANE_Y], dst->stride[UHDR_PLANE_Y]);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    desc->m_resize_uint32_t(src_uv_buffer, dst_uv_buffer, src->w / 2, src->h / 2, dst->w / 2,
                            dst->h / 2, src->stride[UHDR_PLANE_UV] / 2,
                            dst->stride[UHDR_PLANE_UV] / 2);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_resize_uint8_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                           src->stride[UHDR_PLANE_Y], dst->stride[UHDR_PLANE_Y]);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        desc->m_resize_uint8_t(src_buffer, dst_buffer, src->w / 2, src->h / 2, dst->w / 2,
                               dst->h / 2, src->stride[i], dst->stride[i]);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_resize_uint32_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                            src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_resize_uint64_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                            src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
  }
  return std::move(dst);
}
}  // namespace ultrahdr
