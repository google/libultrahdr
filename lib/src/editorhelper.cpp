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

#include <algorithm>
#include <cmath>
#include <string.h>

#include <fstream>
#include <iostream>

#include "ultrahdr/editorhelper.h"

using namespace std;

namespace ultrahdr {
status_t crop(jr_uncompressed_ptr const in_img,
              int left, int right, int top, int bottom,
              jr_uncompressed_ptr out_img) {
  if (in_img == nullptr || in_img->data == nullptr ||
      out_img == nullptr || out_img->data == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (left < 0 || right >= in_img->width || top < 0 || bottom >= in_img->height) {
    return ERROR_JPEGR_INVALID_CROPPING_PARAMETERS;
  }
  if (in_img->pixelFormat != ULTRAHDR_PIX_FMT_YUV420 &&
          in_img->pixelFormat != ULTRAHDR_PIX_FMT_MONOCHROME) {
    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
  }

  out_img->colorGamut = in_img->colorGamut;
  out_img->pixelFormat = in_img->pixelFormat;

  int in_luma_stride = in_img->luma_stride != 0 ? in_img->luma_stride : in_img->width;
  out_img->width = right - left + 1;
  out_img->height = bottom - top + 1;
  out_img->luma_stride = out_img->width;
  uint8_t* src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * top + left;
  uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->data);

  for (int i = 0; i < out_img->height; i++) {
    memcpy(dest + i * out_img->luma_stride, src + i * in_luma_stride, out_img->width);
  }

  if (in_img->pixelFormat == ULTRAHDR_PIX_FMT_MONOCHROME) {
    return JPEGR_NO_ERROR;
  }

  // Assume input is YUV 420
  int in_chroma_stride = in_img->chroma_stride != 0 ?
          in_img->chroma_stride : (in_luma_stride >> 1);
  out_img->chroma_stride = out_img->luma_stride / 2;
  out_img->chroma_data = reinterpret_cast<uint8_t*>(out_img->data) +
          out_img->luma_stride * out_img->height;
  src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
  if (src == nullptr) {
    src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
  }
  src = src + in_chroma_stride * (top / 2) + (left / 2);
  dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
  for (int i = 0; i < out_img->height; i++) {
    memcpy(dest + i * out_img->chroma_stride, src + i * in_chroma_stride, out_img->width / 2);
  }

  return JPEGR_NO_ERROR;
}

status_t mirror(jr_uncompressed_ptr const in_img,
                ultrahdr_mirroring_direction mirror_dir,
                jr_uncompressed_ptr out_img) {
  if (in_img == nullptr || in_img->data == nullptr ||
      out_img == nullptr || out_img->data == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (in_img->pixelFormat != ULTRAHDR_PIX_FMT_YUV420 &&
          in_img->pixelFormat != ULTRAHDR_PIX_FMT_MONOCHROME) {
    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
  }

  out_img->colorGamut = in_img->colorGamut;
  out_img->pixelFormat = in_img->pixelFormat;

  int in_luma_stride = in_img->luma_stride != 0 ? in_img->luma_stride : in_img->width;
  out_img->width = in_img->width;
  out_img->height = in_img->height;
  out_img->luma_stride = in_luma_stride;
  if (mirror_dir == ULTRAHDR_MIRROR_VERTICAL) {
    uint8_t* src = reinterpret_cast<uint8_t*>(in_img->data);
    uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->data);
    for (int i = 0; i < out_img->height; i++) {
      memcpy(dest + (out_img->height - i - 1) * out_img->luma_stride,
             src + i * in_luma_stride,
             out_img->width);
    }
  } else {
    for (int i = 0; i < out_img->height; i++) {
      for (int j = 0; j < out_img->width; j++) {
        *(reinterpret_cast<uint8_t*>(out_img->data) + i * out_img->luma_stride + j) =
                *(reinterpret_cast<uint8_t*>(in_img->data) +
                i * in_luma_stride + (in_img->width - j - 1));
      }
    }
  }

  if (in_img->pixelFormat == ULTRAHDR_PIX_FMT_MONOCHROME) {
    return JPEGR_NO_ERROR;
  }

  // Assume input is YUV 420
  int in_chroma_stride = in_img->chroma_stride != 0 ?
          in_img->chroma_stride : (in_luma_stride >> 1);
  out_img->chroma_stride = out_img->luma_stride / 2;
  out_img->chroma_data = reinterpret_cast<uint8_t*>(out_img->data) +
          out_img->luma_stride * out_img->height;
  if (mirror_dir == ULTRAHDR_MIRROR_VERTICAL) {
    // U
    uint8_t* src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
    if (src == nullptr) {
      src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
    }
    uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
    for (int i = 0; i < out_img->height / 2; i++) {
      memcpy(dest + (out_img->height / 2 - i - 1) * out_img->chroma_stride,
             src + i * in_chroma_stride,
             out_img->width / 2);
    }
    // V
    src = src + in_chroma_stride * (in_img->height / 2);
    dest = dest + out_img->chroma_stride * (out_img->height / 2);
    for (int i = 0; i < out_img->height / 2; i++) {
      memcpy(dest + (out_img->height / 2 - i - 1) * out_img->chroma_stride,
             src + i * in_chroma_stride,
             out_img->width / 2);
    }
  } else {
    // U
    uint8_t* src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
    if (src == nullptr) {
      src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
    }
    uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + i * in_chroma_stride + (in_img->width / 2 - j - 1));
      }
    }
    // V
    src = src + in_chroma_stride * (in_img->height / 2);
    dest = dest + out_img->chroma_stride * (out_img->height / 2);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + i * in_chroma_stride + (in_img->width / 2 - j - 1));
      }
    }
  }

  return JPEGR_NO_ERROR;
}

status_t rotate(jr_uncompressed_ptr const in_img, int clockwise_degree,
                jr_uncompressed_ptr out_img) {
  if (in_img == nullptr || in_img->data == nullptr ||
      out_img == nullptr || out_img->data == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (clockwise_degree != 90 && clockwise_degree != 180 && clockwise_degree != 270) {
    return ERROR_JPEGR_INVALID_CROPPING_PARAMETERS;
  }
  if (in_img->pixelFormat != ULTRAHDR_PIX_FMT_YUV420 &&
          in_img->pixelFormat != ULTRAHDR_PIX_FMT_MONOCHROME) {
    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
  }

  out_img->colorGamut = in_img->colorGamut;
  out_img->pixelFormat = in_img->pixelFormat;

  int in_luma_stride = in_img->luma_stride != 0 ? in_img->luma_stride : in_img->width;
  if (clockwise_degree == 90) {
    out_img->width = in_img->height;
    out_img->height = in_img->width;
    out_img->luma_stride = out_img->width;
    for (int i = 0; i < out_img->height; i++) {
      for (int j = 0; j < out_img->width; j++) {
        *(reinterpret_cast<uint8_t*>(out_img->data) + i * out_img->luma_stride + j) =
                *(reinterpret_cast<uint8_t*>(in_img->data) +
                (in_img->height - j - 1) * in_luma_stride + i);
      }
    }
  } else if (clockwise_degree == 180) {
    out_img->width = in_img->width;
    out_img->height = in_img->height;
    out_img->luma_stride = in_luma_stride;
    for (int i = 0; i < out_img->height; i++) {
      for (int j = 0; j < out_img->width; j++) {
        *(reinterpret_cast<uint8_t*>(out_img->data) + i * out_img->luma_stride + j) =
                *(reinterpret_cast<uint8_t*>(in_img->data) +
                (in_img->height - i - 1) * in_luma_stride + (in_img->width - j - 1));
      }
    }
  } else if (clockwise_degree == 270) {
    out_img->width = in_img->height;
    out_img->height = in_img->width;
    out_img->luma_stride = out_img->width;
    for (int i = 0; i < out_img->height; i++) {
      for (int j = 0; j < out_img->width; j++) {
        *(reinterpret_cast<uint8_t*>(out_img->data) + i * out_img->luma_stride + j) =
                *(reinterpret_cast<uint8_t*>(in_img->data) +
                j * in_luma_stride + (in_img->width - i - 1));
      }
    }
  }

  if (in_img->pixelFormat == ULTRAHDR_PIX_FMT_MONOCHROME) {
    return JPEGR_NO_ERROR;
  }

  // Assume input is YUV 420
  int in_chroma_stride = in_img->chroma_stride != 0 ?
          in_img->chroma_stride : (in_luma_stride >> 1);
  out_img->chroma_stride = out_img->luma_stride / 2;
  out_img->chroma_data = reinterpret_cast<uint8_t*>(out_img->data) +
          out_img->luma_stride * out_img->height;
  if (clockwise_degree == 90) {
    // U
    uint8_t* src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
    if (src == nullptr) {
      src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
    }
    uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + (in_img->height / 2 - j - 1) * in_chroma_stride + i);
      }
    }
    // V
    src = src + in_chroma_stride * (in_img->height / 2);
    dest = dest + out_img->chroma_stride * (out_img->height / 2);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + (in_img->height / 2 - j - 1) * in_chroma_stride + i);
      }
    }
  } else if (clockwise_degree == 180) {
    // U
    uint8_t* src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
    if (src == nullptr) {
      src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
    }
    uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + (in_img->height / 2 - i - 1) * in_chroma_stride +
                (in_img->width / 2 - j - 1));
      }
    }
    // V
    src = src + in_chroma_stride * (in_img->height / 2);
    dest = dest + out_img->chroma_stride * (out_img->height / 2);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + (in_img->height / 2 - i - 1) * in_chroma_stride +
                (in_img->width / 2 - j - 1));
      }
    }
  } else if (clockwise_degree == 270) {
    // U
    uint8_t* src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
    if (src == nullptr) {
      src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
    }
    uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + j * in_chroma_stride + (in_img->width / 2 - i - 1));
      }
    }
    // V
    src = src + in_chroma_stride * (in_img->height / 2);
    dest = dest + out_img->chroma_stride * (out_img->height / 2);
    for (int i = 0; i < out_img->height / 2; i++) {
      for (int j = 0; j < out_img->width / 2; j++) {
        *(dest + i * out_img->chroma_stride + j) =
                *(src + j * in_chroma_stride + (in_img->width / 2 - i - 1));
      }
    }
  }

  return JPEGR_NO_ERROR;
}

status_t resize(jr_uncompressed_ptr const in_img, int out_width, int out_height,
                jr_uncompressed_ptr out_img) {
  if (in_img == nullptr || in_img->data == nullptr ||
      out_img == nullptr || out_img->data == nullptr) {
    return ERROR_JPEGR_BAD_PTR;
  }
  if (in_img->pixelFormat != ULTRAHDR_PIX_FMT_YUV420 &&
          in_img->pixelFormat != ULTRAHDR_PIX_FMT_MONOCHROME) {
    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
  }

  out_img->colorGamut = in_img->colorGamut;
  out_img->pixelFormat = in_img->pixelFormat;

  int in_luma_stride = in_img->luma_stride != 0 ? in_img->luma_stride : in_img->width;
  out_img->width = out_width;
  out_img->height = out_height;
  out_img->luma_stride = out_img->width;

  for (int i = 0; i < out_img->height; i++) {
    for (int j = 0; j < out_img->width; j++) {
      *(reinterpret_cast<uint8_t*>(out_img->data) + i * out_img->luma_stride + j) =
              *(reinterpret_cast<uint8_t*>(in_img->data) +
              i * in_img->height / out_img->height * in_luma_stride +
              j * in_img->width / out_img->width );
    }
  }

  if (in_img->pixelFormat == ULTRAHDR_PIX_FMT_MONOCHROME) {
    return JPEGR_NO_ERROR;
  }

  // Assume input is YUV 420
  int in_chroma_stride = in_img->chroma_stride != 0 ?
          in_img->chroma_stride : (in_luma_stride >> 1);
  out_img->chroma_stride = out_img->luma_stride / 2;
  out_img->chroma_data = reinterpret_cast<uint8_t*>(out_img->data) +
          out_img->luma_stride * out_img->height;
  uint8_t* src = reinterpret_cast<uint8_t*>(in_img->chroma_data);
  if (src == nullptr) {
    src = reinterpret_cast<uint8_t*>(in_img->data) + in_luma_stride * in_img->height;
  }
  uint8_t* dest = reinterpret_cast<uint8_t*>(out_img->chroma_data);
  for (int i = 0; i < out_img->height; i++) {
    for (int j = 0; j < out_img->width / 2; j++) {
      *(dest + i * out_img->chroma_stride + j) =
              *(src + i * in_img->height / out_img->height * in_chroma_stride +
              j * in_img->width / out_img->width );
    }
  }

  return JPEGR_NO_ERROR;
}

}  // namespace ultrahdr
