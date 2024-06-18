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
#include "ultrahdr/gainmapmath.h"

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
void crop_buffer(T* src_buffer, T* dst_buffer, int src_stride, int dst_stride, int left, int top,
                 int wd, int ht) {
  for (int row = 0; row < ht; row++) {
    memcpy(&dst_buffer[row * dst_stride], &src_buffer[(top + row) * src_stride + left],
           wd * sizeof(T));
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
                   int src_row_stride, int dst_row_stride, int src_pixel_stride,
                   int dst_pixel_stride, T low_limit, T high_limit) {
  double scale_x = (double)src_w / dst_w;
  double scale_y = (double)src_h / dst_h;
  for (int y = 0; y < dst_h; y++) {
    for (int x = 0; x < dst_w; x++) {
      double ori_x = x * scale_x;
      double ori_y = y * scale_y;
      int p0_x = CLIP3((int)floor(ori_x), 0, src_w - 1);
      int p0_y = CLIP3((int)floor(ori_y), 0, src_h - 1);
      int p1_x = CLIP3((p0_x + 1), 0, src_w - 1);
      int p1_y = p0_y;
      int p2_x = p0_x;
      int p2_y = CLIP3((p0_y + 1), 0, src_h - 1);
      int p3_x = CLIP3((p0_x + 1), 0, src_w - 1);
      int p3_y = CLIP3((p0_y + 1), 0, src_h - 1);

      double p0 = (double)src_buffer[p0_y * src_row_stride + p0_x * src_pixel_stride];
      double p1 = (double)src_buffer[p1_y * src_row_stride + p1_x * src_pixel_stride];
      double p2 = (double)src_buffer[p2_y * src_row_stride + p2_x * src_pixel_stride];
      double p3 = (double)src_buffer[p3_y * src_row_stride + p3_x * src_pixel_stride];

      double new_pix_val = bicubic_interpolate(p0, p1, p2, p3, ori_x - p0_x);

      dst_buffer[y * dst_row_stride + x * dst_pixel_stride] =
          static_cast<T>(CLIP3((new_pix_val + 0.5), low_limit, high_limit));
    }
  }
}

void resize_buffer_rgba1010102(uint32_t* src_buffer, uint32_t* dst_buffer, int src_w, int src_h,
                              int dst_w, int dst_h, int src_row_stride, int dst_row_stride) {
  double scale_x = (double)src_w / dst_w;
  double scale_y = (double)src_h / dst_h;
  for (int y = 0; y < dst_h; y++) {
    for (int x = 0; x < dst_w; x++) {
      double ori_x = x * scale_x;
      double ori_y = y * scale_y;
      int p0_x = CLIP3((int)floor(ori_x), 0, src_w - 1);
      int p0_y = CLIP3((int)floor(ori_y), 0, src_h - 1);
      int p1_x = CLIP3((p0_x + 1), 0, src_w - 1);
      int p1_y = p0_y;
      int p2_x = p0_x;
      int p2_y = CLIP3((p0_y + 1), 0, src_h - 1);
      int p3_x = CLIP3((p0_x + 1), 0, src_w - 1);
      int p3_y = CLIP3((p0_y + 1), 0, src_h - 1);

      uint32_t p0 = src_buffer[p0_y * src_row_stride + p0_x];
      uint32_t p1 = src_buffer[p1_y * src_row_stride + p1_x];
      uint32_t p2 = src_buffer[p2_y * src_row_stride + p2_x];
      uint32_t p3 = src_buffer[p3_y * src_row_stride + p3_x];

      double r = bicubic_interpolate(p0 & 0x3ff, p1 & 0x3ff, p2 & 0x3ff, p3 & 0x3ff, ori_x - p0_x);
      double g = bicubic_interpolate(((p0 >> 10) & 0x3ff), ((p1 >> 10) & 0x3ff),
                                     ((p2 >> 10) & 0x3ff), ((p3 >> 10) & 0x3ff), ori_x - p0_x);
      double b = bicubic_interpolate(((p0 >> 20) & 0x3ff), ((p1 >> 20) & 0x3ff),
                                     ((p2 >> 20) & 0x3ff), ((p3 >> 20) & 0x3ff), ori_x - p0_x);

      r = CLIP3(r + 0.5f, 0.0f, 1023.0f);
      g = CLIP3(g + 0.5f, 0.0f, 1023.0f);
      b = CLIP3(b + 0.5f, 0.0f, 1023.0f);
      uint32_t r0 = uint32_t(r);
      uint32_t g0 = uint32_t(g);
      uint32_t b0 = uint32_t(b);
      dst_buffer[y * dst_row_stride + x] =
          (0x3ff & r0) | ((0x3ff & g0) << 10) | ((0x3ff & b0) << 20) | (0x3 << 30);
    }
  }
}

void resize_buffer_rgbahalffloat(uint64_t* src_buffer, uint64_t* dst_buffer, int src_w, int src_h,
                                 int dst_w, int dst_h, int src_row_stride, int dst_row_stride) {
  double scale_x = (double)src_w / dst_w;
  double scale_y = (double)src_h / dst_h;
  for (int y = 0; y < dst_h; y++) {
    for (int x = 0; x < dst_w; x++) {
      double ori_x = x * scale_x;
      double ori_y = y * scale_y;
      int p0_x = CLIP3((int)floor(ori_x), 0, src_w - 1);
      int p0_y = CLIP3((int)floor(ori_y), 0, src_h - 1);
      int p1_x = CLIP3((p0_x + 1), 0, src_w - 1);
      int p1_y = p0_y;
      int p2_x = p0_x;
      int p2_y = CLIP3((p0_y + 1), 0, src_h - 1);
      int p3_x = CLIP3((p0_x + 1), 0, src_w - 1);
      int p3_y = CLIP3((p0_y + 1), 0, src_h - 1);

      uint64_t p0 = src_buffer[p0_y * src_row_stride + p0_x];
      uint64_t p1 = src_buffer[p1_y * src_row_stride + p1_x];
      uint64_t p2 = src_buffer[p2_y * src_row_stride + p2_x];
      uint64_t p3 = src_buffer[p3_y * src_row_stride + p3_x];

      Color pixel;
      pixel.r =
          bicubic_interpolate(halfToFloat(p0 & 0xffff), halfToFloat(p1 & 0xffff),
                              halfToFloat(p2 & 0xffff), halfToFloat(p3 & 0xffff), ori_x - p0_x);
      pixel.g = bicubic_interpolate(
          halfToFloat((p0 >> 16) & 0xffff), halfToFloat((p1 >> 16) & 0xffff),
          halfToFloat((p2 >> 16) & 0xffff), halfToFloat((p3 >> 16) & 0xffff), ori_x - p0_x);
      pixel.b = bicubic_interpolate(
          halfToFloat((p0 >> 32) & 0xffff), halfToFloat((p1 >> 32) & 0xffff),
          halfToFloat((p2 >> 32) & 0xffff), halfToFloat((p3 >> 32) & 0xffff), ori_x - p0_x);

      pixel.r = CLIP3(pixel.r, 0.0f, 1.0f);
      pixel.g = CLIP3(pixel.g, 0.0f, 1.0f);
      pixel.b = CLIP3(pixel.b, 0.0f, 1.0f);
      dst_buffer[y * dst_row_stride + x] = colorToRgbaF16(pixel);
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

template void resize_buffer<uint8_t>(uint8_t*, uint8_t*, int, int, int, int, int, int, int, int,
                                     uint8_t, uint8_t);
template void resize_buffer<uint16_t>(uint16_t*, uint16_t*, int, int, int, int, int, int, int, int,
                                      uint16_t, uint16_t);

uhdr_mirror_effect::uhdr_mirror_effect(uhdr_mirror_direction_t direction) : m_direction{direction} {
#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
  m_mirror_uint8_t = mirror_buffer_neon<uint8_t>;
  m_mirror_uint16_t = mirror_buffer_neon<uint16_t>;
  m_mirror_uint32_t = mirror_buffer_neon<uint32_t>;
  m_mirror_uint64_t = mirror_buffer_neon<uint64_t>;
#else
  m_mirror_uint8_t = mirror_buffer<uint8_t>;
  m_mirror_uint16_t = mirror_buffer<uint16_t>;
  m_mirror_uint32_t = mirror_buffer<uint32_t>;
  m_mirror_uint64_t = mirror_buffer<uint64_t>;
#endif
}

uhdr_rotate_effect::uhdr_rotate_effect(int degree) : m_degree{degree} {
#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
  m_rotate_uint8_t = rotate_buffer_clockwise_neon<uint8_t>;
  m_rotate_uint16_t = rotate_buffer_clockwise_neon<uint16_t>;
  m_rotate_uint32_t = rotate_buffer_clockwise_neon<uint32_t>;
  m_rotate_uint64_t = rotate_buffer_clockwise_neon<uint64_t>;
#else
  m_rotate_uint8_t = rotate_buffer_clockwise<uint8_t>;
  m_rotate_uint16_t = rotate_buffer_clockwise<uint16_t>;
  m_rotate_uint32_t = rotate_buffer_clockwise<uint32_t>;
  m_rotate_uint64_t = rotate_buffer_clockwise<uint64_t>;
#endif
}

uhdr_crop_effect::uhdr_crop_effect(int left, int right, int top, int bottom)
    : m_left(left), m_right(right), m_top(top), m_bottom(bottom) {
  m_crop_uint8_t = crop_buffer<uint8_t>;
  m_crop_uint16_t = crop_buffer<uint16_t>;
  m_crop_uint32_t = crop_buffer<uint32_t>;
  m_crop_uint64_t = crop_buffer<uint64_t>;
}

uhdr_resize_effect::uhdr_resize_effect(int width, int height) : m_width{width}, m_height{height} {
  m_resize_uint8_t = resize_buffer<uint8_t>;
  m_resize_uint16_t = resize_buffer<uint16_t>;
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(ultrahdr::uhdr_rotate_effect_t* desc,
                                                   uhdr_raw_image_t* src,
                                                   [[maybe_unused]] void* gl_ctxt,
                                                   [[maybe_unused]] void* texture) {
#ifdef UHDR_ENABLE_GLES
  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
    return apply_rotate_gles(desc, src, static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
                             static_cast<GLuint*>(texture));
  }
#endif
  std::unique_ptr<uhdr_raw_image_ext_t> dst;

  if (desc->m_degree == 90 || desc->m_degree == 270) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->h,
                                                 src->w, 64);
  } else if (desc->m_degree == 180) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->w,
                                                 src->h, 64);
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
  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
      desc->m_rotate_uint8_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i], dst->stride[i],
                             desc->m_degree);
    }
  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
      desc->m_rotate_uint16_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i],
                              dst->stride[i], desc->m_degree);
    }
  }
  return dst;
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(ultrahdr::uhdr_mirror_effect_t* desc,
                                                   uhdr_raw_image_t* src,
                                                   [[maybe_unused]] void* gl_ctxt,
                                                   [[maybe_unused]] void* texture) {
#ifdef UHDR_ENABLE_GLES
  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
    return apply_mirror_gles(desc, src, static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
                             static_cast<GLuint*>(texture));
  }
#endif
  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
      src->fmt, src->cg, src->ct, src->range, src->w, src->h, 64);

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
  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
      desc->m_mirror_uint8_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i], dst->stride[i],
                             desc->m_direction);
    }
  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
      desc->m_mirror_uint16_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i],
                              dst->stride[i], desc->m_direction);
    }
  }
  return dst;
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_crop(ultrahdr::uhdr_crop_effect_t* desc,
                                                 uhdr_raw_image_t* src, int left, int top, int wd,
                                                 int ht, [[maybe_unused]] void* gl_ctxt,
                                                 [[maybe_unused]] void* texture) {
#ifdef UHDR_ENABLE_GLES
  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
    return apply_crop_gles(src, left, top, wd, ht,
                           static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
                           static_cast<GLuint*>(texture));
  }
#endif
  std::unique_ptr<uhdr_raw_image_ext_t> dst =
      std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, wd, ht, 64);

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_crop_uint16_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_Y],
                          dst->stride[UHDR_PLANE_Y], left, top, wd, ht);
    uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
    desc->m_crop_uint32_t(src_uv_buffer, dst_uv_buffer, src->stride[UHDR_PLANE_UV] / 2,
                          dst->stride[UHDR_PLANE_UV] / 2, left / 2, top / 2, wd / 2, ht / 2);
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_crop_uint8_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_Y],
                         dst->stride[UHDR_PLANE_Y], left, top, wd, ht);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        desc->m_crop_uint8_t(src_buffer, dst_buffer, src->stride[i], dst->stride[i], left / 2,
                             top / 2, wd / 2, ht / 2);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_crop_uint32_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_PACKED],
                          dst->stride[UHDR_PLANE_PACKED], left, top, wd, ht);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    desc->m_crop_uint64_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_PACKED],
                          dst->stride[UHDR_PLANE_PACKED], left, top, wd, ht);
  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
      desc->m_crop_uint8_t(src_buffer, dst_buffer, src->stride[i], dst->stride[i], left, top, wd,
                           ht);
    }
  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
      desc->m_crop_uint16_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_PACKED],
                            dst->stride[UHDR_PLANE_PACKED], left, top, wd, ht);
    }
  }
  return dst;
}

std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_t* desc,
                                                   uhdr_raw_image_t* src,
                                                   [[maybe_unused]] void* gl_ctxt,
                                                   [[maybe_unused]] void* texture) {
#ifdef UHDR_ENABLE_GLES
  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
    return apply_resize_gles(src, dst_w, dst_h, static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
                             static_cast<GLuint*>(texture));
  }
#endif
  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
      src->fmt, src->cg, src->ct, src->range, desc->m_width, desc->m_height, 64);

  if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_resize_uint16_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                            src->stride[UHDR_PLANE_Y], dst->stride[UHDR_PLANE_Y], 1, 1,
                            src->range == UHDR_CR_LIMITED_RANGE ? 64 : 0,
                            src->range == UHDR_CR_LIMITED_RANGE ? 940 : 1023);
    uint16_t* src_uv_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_UV]);
    uint16_t* dst_uv_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_UV]);
    for (int i = 0; i <= 1; i++) {
      desc->m_resize_uint16_t(src_uv_buffer + i, dst_uv_buffer + i, src->w / 2, src->h / 2,
                              dst->w / 2, dst->h / 2, src->stride[UHDR_PLANE_UV],
                              dst->stride[UHDR_PLANE_UV], 2, 2,
                              src->range == UHDR_CR_LIMITED_RANGE ? 64 : 0,
                              src->range == UHDR_CR_LIMITED_RANGE ? 960 : 1023);
    }
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    desc->m_resize_uint8_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                           src->stride[UHDR_PLANE_Y], dst->stride[UHDR_PLANE_Y], 1, 1,
                           src->range == UHDR_CR_LIMITED_RANGE ? 16 : 0,
                           src->range == UHDR_CR_LIMITED_RANGE ? 235 : 255);
    if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      for (int i = 1; i < 3; i++) {
        src_buffer = static_cast<uint8_t*>(src->planes[i]);
        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
        desc->m_resize_uint8_t(src_buffer, dst_buffer, src->w / 2, src->h / 2, dst->w / 2,
                               dst->h / 2, src->stride[i], dst->stride[i], 1, 1,
                               src->range == UHDR_CR_LIMITED_RANGE ? 16 : 0,
                               src->range == UHDR_CR_LIMITED_RANGE ? 240 : 255);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_24bppRGB888 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    uint8_t* r_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint8_t* r_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_PACKED]);
    int pixel_stride = src->fmt == UHDR_IMG_FMT_24bppRGB888 ? 3 : 4;

    for (int i = 0; i < 3; i++) {
      resize_buffer<uint8_t>(r_src + i, r_dst + i, src->w, src->h, desc->m_width, desc->m_height,
                             src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED],
                             pixel_stride, pixel_stride, 0, 255);
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
    uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
    resize_buffer_rgba1010102(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                              src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
  } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
    resize_buffer_rgbahalffloat(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                                src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
      desc->m_resize_uint8_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h, src->stride[i],
                             dst->stride[i], 1, 1, src->range == UHDR_CR_LIMITED_RANGE ? 16 : 0,
                             src->range == UHDR_CR_LIMITED_RANGE ? 235 : 255);
    }
  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
    for (int i = 0; i < 3; i++) {
      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
      desc->m_resize_uint16_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                              src->stride[i], dst->stride[i], 1, 1,
                              src->range == UHDR_CR_LIMITED_RANGE ? 64 : 0,
                              src->range == UHDR_CR_LIMITED_RANGE ? 940 : 1023);
    }
  }
  return dst;
}

}  // namespace ultrahdr
