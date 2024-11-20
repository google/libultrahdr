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

#include "ultrahdr/gainmapmath.h"
#include <riscv_vector.h>

namespace ultrahdr {

void convert_rgb_to_yuv_rvv(uhdr_raw_image_ext_t* dst, const uhdr_raw_image_t* src) {
  uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
  unsigned int srcStride = src->stride[UHDR_PLANE_PACKED];

  uint8_t* yData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
  uint8_t* uData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
  uint8_t* vData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);

  size_t vl;

  for (size_t i = 0; i < dst->h; i++) {
    for (size_t j = 0; j < dst->w; j += vl) {
      vl = __riscv_vsetvl_e32m8(dst->w - j);

      vuint32m8_t vrgb = __riscv_vle32_v_u32m8(rgbData + srcStride * i + j, vl);
      vfloat32m8_t vr = __riscv_vreinterpret_v_u32m8_f32m8(__riscv_vand_vx_u32m8(vrgb, 0xff, vl));
      vfloat32m8_t vg = __riscv_vreinterpret_v_u32m8_f32m8(
          __riscv_vand_vx_u32m8(__riscv_vsrl_vx_u32m8(vrgb, 8, vl), 0xff, vl));
      vfloat32m8_t vb = __riscv_vreinterpret_v_u32m8_f32m8(
          __riscv_vand_vx_u32m8(__riscv_vsrl_vx_u32m8(vrgb, 16, vl), 0xff, vl));

      // Normalize to [0, 1] range
      vr = __riscv_vfdiv_vf_f32m8(vr, 255.0f, vl);
      vg = __riscv_vfdiv_vf_f32m8(vg, 255.0f, vl);
      vb = __riscv_vfdiv_vf_f32m8(vb, 255.0f, vl);

      vfloat32m8_t vy = __riscv_vfadd_vf_f32m8(__riscv_vfmul_vf_f32m8(vr, 255.0f, vl), 0.5f, vl);
      vfloat32m8_t vu = __riscv_vfadd_vf_f32m8(__riscv_vfmul_vf_f32m8(vg, 255.0f, vl), 128.5f, vl);
      vfloat32m8_t vv = __riscv_vfadd_vf_f32m8(__riscv_vfmul_vf_f32m8(vb, 255.0f, vl), 128.5f, vl);

      vy = __riscv_vfmin_vf_f32m8(vy, 0.0f, vl);
      vy = __riscv_vfmax_vf_f32m8(vy, 255.0f, vl);
      vu = __riscv_vfmin_vf_f32m8(vu, 0.0f, vl);
      vu = __riscv_vfmax_vf_f32m8(vu, 255.0f, vl);
      vv = __riscv_vfmin_vf_f32m8(vv, 0.0f, vl);
      vv = __riscv_vfmax_vf_f32m8(vv, 255.0f, vl);

      // Store the results
      vuint16m4_t vy_u16 = __riscv_vfncvt_rtz_xu_f_w_u16m4(vy, vl);
      vuint16m4_t vu_u16 = __riscv_vfncvt_rtz_xu_f_w_u16m4(vu, vl);
      vuint16m4_t vv_u16 = __riscv_vfncvt_rtz_xu_f_w_u16m4(vv, vl);
      vuint8m2_t vy_u8 = __riscv_vncvt_x_x_w_u8m2(vy_u16, vl);
      vuint8m2_t vu_u8 = __riscv_vncvt_x_x_w_u8m2(vu_u16, vl);
      vuint8m2_t vv_u8 = __riscv_vncvt_x_x_w_u8m2(vv_u16, vl);

      __riscv_vse8_v_u8m2(yData + dst->stride[UHDR_PLANE_Y] * i + j, vy_u8, vl);
      __riscv_vse8_v_u8m2(uData + dst->stride[UHDR_PLANE_U] * i + j, vu_u8, vl);
      __riscv_vse8_v_u8m2(vData + dst->stride[UHDR_PLANE_V] * i + j, vv_u8, vl);
    }
  }
}

std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr_rvv(uhdr_raw_image_t* src) {
  if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    std::unique_ptr<uhdr_raw_image_ext_t> dst = nullptr;
    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppYCbCr444, src->cg, src->ct,
                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
    convert_rgb_to_yuv_rvv(dst.get(), src);
    return dst;
  }
  return nullptr;
}
}  // namespace ultrahdr
