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
#include <cassert>

namespace ultrahdr {

static inline vuint16m8_t zip_self(vuint16m4_t a, size_t vl) {
  vuint32m8_t a_wide = __riscv_vzext_vf2_u32m8(a, vl / 2);
  vuint16m8_t a_zero = __riscv_vreinterpret_v_u32m8_u16m8(a_wide);
  vuint16m8_t a_zero_slide = __riscv_vslide1up_vx_u16m8(a_zero, 0, vl);
  vuint16m8_t a_zip = __riscv_vadd_vv_u16m8(a_zero, a_zero_slide, vl);
  return a_zip;
}

static inline vint16m4_t vqrshrn_n_s32(vint32m8_t a, const int b, size_t vl) {
  return __riscv_vnclip_wx_i16m4(a, b, vl);
}

static inline vuint8m4_t vget_low_u8(vuint8m8_t u) { return __riscv_vget_v_u8m8_u8m4(u, 0); }

static inline vuint8m4_t vget_high_u8(vuint8m8_t u, size_t vl) {
  return __riscv_vget_v_u8m8_u8m4(__riscv_vslidedown_vx_u8m8(u, vl / 2, vl), 0);
}

static inline vint16m4_t vget_low_s16(vint16m8_t u) { return __riscv_vget_v_i16m8_i16m4(u, 0); }

static inline vint16m4_t vget_high_s16(vint16m8_t u, size_t vl) {
  return __riscv_vget_v_i16m8_i16m4(__riscv_vslidedown_vx_i16m8(u, vl / 2, vl), 0);
}

static inline vuint16m4_t vget_low_u16(vuint16m8_t u) { return __riscv_vget_v_u16m8_u16m4(u, 0); }

static inline vuint16m2_t vget_low_u16m4(vuint16m4_t u) { return __riscv_vget_v_u16m4_u16m2(u, 0); }

static inline vuint16m4_t vget_high_u16(vuint16m8_t u, size_t vl) {
  return __riscv_vget_v_u16m8_u16m4(__riscv_vslidedown_vx_u16m8(u, vl / 2, vl), 0);
}

static inline vuint16m2_t vget_high_u16m4(vuint16m4_t u, size_t vl) {
  return __riscv_vget_v_u16m4_u16m2(__riscv_vslidedown_vx_u16m4(u, vl / 2, vl), 0);
}

static inline vint16m8_t vcombine_s16(vint16m4_t a, vint16m4_t b, size_t vl) {
  vint16m8_t a_wide = __riscv_vlmul_ext_v_i16m4_i16m8(a);
  vint16m8_t b_wide = __riscv_vlmul_ext_v_i16m4_i16m8(b);
  return __riscv_vslideup_vx_i16m8(a_wide, b_wide, vl / 2, vl);
}

static inline vuint8m8_t vcombine_u8(vuint8m4_t a, vuint8m4_t b, size_t vl) {
  vuint8m8_t a_wide = __riscv_vlmul_ext_v_u8m4_u8m8(a);
  vuint8m8_t b_wide = __riscv_vlmul_ext_v_u8m4_u8m8(b);
  return __riscv_vslideup_vx_u8m8(a_wide, b_wide, vl / 2, vl);
}

static inline vuint16m8_t vcombine_u16(vuint16m4_t a, vuint16m4_t b, size_t vl) {
  vuint16m8_t a_wide = __riscv_vlmul_ext_v_u16m4_u16m8(a);
  vuint16m8_t b_wide = __riscv_vlmul_ext_v_u16m4_u16m8(b);
  return __riscv_vslideup_vx_u16m8(a_wide, b_wide, vl / 2, vl);
}

static inline vuint8m4_t vmovn_u16(vuint16m8_t a, size_t vl) {
  return __riscv_vnsrl_wx_u8m4(a, 0, vl);
}

static inline vuint8m4_t vqmovun_s16(vint16m8_t a, size_t vl) {
  vuint16m8_t a_non_neg = __riscv_vreinterpret_v_i16m8_u16m8(__riscv_vmax_vx_i16m8(a, 0, vl));
  return __riscv_vnclipu_wx_u8m4(a_non_neg, 0, vl);
}

static inline vuint16m4_t vmovl_u8(vuint8m4_t a, size_t vl) {
  vuint16m8_t a_16 = __riscv_vzext_vf2_u16m8(a, vl);
  return __riscv_vlmul_trunc_v_u16m8_u16m4(a_16);
}

static inline vuint16m4_t vrshrn_n_u32(vuint32m4_t a, const int b, size_t vl) {
  vuint32m4_t a_round = __riscv_vadd_vx_u32m4(a, 1 << (b - 1), vl);
  return __riscv_vnsrl_wx_u16m4(__riscv_vlmul_ext_v_u32m4_u32m8(a_round), b, vl);
}

static inline vint16m8_t yConversion_rvv(vuint8m4_t y, vint16m8_t u, vint16m8_t v,
                                         const int16_t* coeffs, size_t vl) {
  vint32m8_t u_lo = __riscv_vwmul_vx_i32m8(vget_low_s16(u), coeffs[0], vl / 2);
  vint32m8_t u_hi = __riscv_vwmul_vx_i32m8(vget_high_s16(u, vl), coeffs[0], vl / 2);

  vint32m8_t v_lo = __riscv_vwmul_vx_i32m8(vget_low_s16(v), coeffs[1], vl / 2);
  vint32m8_t v_hi = __riscv_vwmul_vx_i32m8(vget_high_s16(v, vl), coeffs[1], vl / 2);

  vint32m8_t lo = __riscv_vadd_vv_i32m8(u_lo, v_lo, vl / 2);
  vint32m8_t hi = __riscv_vadd_vv_i32m8(u_hi, v_hi, vl / 2);

  vint16m4_t lo_shr = vqrshrn_n_s32(lo, 14, vl / 2);
  vint16m4_t hi_shr = vqrshrn_n_s32(hi, 14, vl / 2);

  vint16m8_t y_output = vcombine_s16(lo_shr, hi_shr, vl);
  vuint16m8_t y_u16 = __riscv_vreinterpret_v_i16m8_u16m8(y_output);
  vuint16m8_t y_ret = __riscv_vwaddu_wv_u16m8(y_u16, y, vl);
  return __riscv_vreinterpret_v_u16m8_i16m8(y_ret);
}

static inline vint16m8_t uConversion_rvv(vint16m8_t u, vint16m8_t v, const int16_t* coeffs,
                                         size_t vl) {
  vint32m8_t u_lo = __riscv_vwmul_vx_i32m8(vget_low_s16(u), coeffs[2], vl / 2);
  vint32m8_t u_hi = __riscv_vwmul_vx_i32m8(vget_high_s16(u, vl), coeffs[2], vl / 2);

  vint32m8_t v_lo = __riscv_vwmul_vx_i32m8(vget_low_s16(v), coeffs[3], vl / 2);
  vint32m8_t v_hi = __riscv_vwmul_vx_i32m8(vget_high_s16(v, vl), coeffs[3], vl / 2);

  vint32m8_t lo = __riscv_vadd_vv_i32m8(u_lo, v_lo, vl / 2);
  vint32m8_t hi = __riscv_vadd_vv_i32m8(u_hi, v_hi, vl / 2);

  vint16m4_t lo_shr = vqrshrn_n_s32(lo, 14, vl / 2);
  vint16m4_t hi_shr = vqrshrn_n_s32(hi, 14, vl / 2);

  vint16m8_t u_output = vcombine_s16(lo_shr, hi_shr, vl);
  return u_output;
}

static inline vint16m8_t vConversion_rvv(vint16m8_t u, vint16m8_t v, const int16_t* coeffs,
                                         size_t vl) {
  vint32m8_t u_lo = __riscv_vwmul_vx_i32m8(vget_low_s16(u), coeffs[4], vl / 2);
  vint32m8_t u_hi = __riscv_vwmul_vx_i32m8(vget_high_s16(u, vl), coeffs[4], vl / 2);

  vint32m8_t v_lo = __riscv_vwmul_vx_i32m8(vget_low_s16(v), coeffs[5], vl / 2);
  vint32m8_t v_hi = __riscv_vwmul_vx_i32m8(vget_high_s16(v, vl), coeffs[5], vl / 2);

  vint32m8_t lo = __riscv_vadd_vv_i32m8(u_lo, v_lo, vl / 2);
  vint32m8_t hi = __riscv_vadd_vv_i32m8(u_hi, v_hi, vl / 2);

  vint16m4_t lo_shr = vqrshrn_n_s32(lo, 14, vl / 2);
  vint16m4_t hi_shr = vqrshrn_n_s32(hi, 14, vl / 2);

  vint16m8_t v_output = vcombine_s16(lo_shr, hi_shr, vl);
  return v_output;
}

void transformYuv420_rvv(uhdr_raw_image_t* image, const int16_t* coeffs_ptr) {
  assert(image->w % 16 == 0);
  uint8_t* y0_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
  uint8_t* y1_ptr = y0_ptr + image->stride[UHDR_PLANE_Y];
  uint8_t* u_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
  uint8_t* v_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
  size_t vl;
  size_t h = 0;
  do {
    size_t w = 0;
    do {
      vl = __riscv_vsetvl_e8m8((image->w) - w);
      assert((vl % 4) == 0 && vl >= 4);

      vuint8m8_t y0 = __riscv_vle8_v_u8m8(y0_ptr + w * 2, vl);
      vuint8m8_t y1 = __riscv_vle8_v_u8m8(y1_ptr + w * 2, vl);

      vuint8m4_t u8 = __riscv_vle8_v_u8m4(u_ptr + w, vl / 2);
      vuint8m4_t v8 = __riscv_vle8_v_u8m4(v_ptr + w, vl / 2);

      vuint16m8_t u16_wide = __riscv_vwsubu_vx_u16m8(u8, 128, vl / 2);
      vuint16m8_t v16_wide = __riscv_vwsubu_vx_u16m8(v8, 128, vl / 2);

      vuint16m8_t uu_wide_lo = zip_self(__riscv_vget_v_u16m8_u16m4(u16_wide, 0), vl / 2);
      vuint16m8_t uu_wide_hi = zip_self(vget_high_u16(u16_wide, vl / 2), vl / 2);
      vuint16m8_t uv_wide_lo = zip_self(__riscv_vget_v_u16m8_u16m4(v16_wide, 0), vl / 2);
      vuint16m8_t uv_wide_hi = zip_self(vget_high_u16(v16_wide, vl / 2), vl / 2);

      vint16m8_t u_wide_lo = __riscv_vreinterpret_v_u16m8_i16m8(uu_wide_lo);
      vint16m8_t v_wide_lo = __riscv_vreinterpret_v_u16m8_i16m8(uv_wide_lo);
      vint16m8_t u_wide_hi = __riscv_vreinterpret_v_u16m8_i16m8(uu_wide_hi);
      vint16m8_t v_wide_hi = __riscv_vreinterpret_v_u16m8_i16m8(uv_wide_hi);

      vint16m8_t y0_lo = yConversion_rvv(vget_low_u8(y0), u_wide_lo, v_wide_lo, coeffs_ptr, vl / 2);
      vint16m8_t y1_lo = yConversion_rvv(vget_low_u8(y1), u_wide_lo, v_wide_lo, coeffs_ptr, vl / 2);
      vint16m8_t y0_hi =
          yConversion_rvv(vget_high_u8(y0, vl / 2), u_wide_hi, v_wide_hi, coeffs_ptr, vl / 2);
      vint16m8_t y1_hi =
          yConversion_rvv(vget_high_u8(y1, vl / 2), u_wide_hi, v_wide_hi, coeffs_ptr, vl / 2);

      vint16m8_t u_wide_s16 = __riscv_vreinterpret_v_u16m8_i16m8(u16_wide);
      vint16m8_t v_wide_s16 = __riscv_vreinterpret_v_u16m8_i16m8(v16_wide);
      vint16m8_t new_u = uConversion_rvv(u_wide_s16, v_wide_s16, coeffs_ptr, vl / 2);
      vint16m8_t new_v = vConversion_rvv(u_wide_s16, v_wide_s16, coeffs_ptr, vl / 2);

      vuint8m8_t y0_output =
          vcombine_u8(vqmovun_s16(y0_lo, vl / 2), vqmovun_s16(y0_hi, vl / 2), vl);
      vuint8m8_t y1_output =
          vcombine_u8(vqmovun_s16(y1_lo, vl / 2), vqmovun_s16(y1_hi, vl / 2), vl);
      vuint8m4_t u_output = vqmovun_s16(__riscv_vadd_vx_i16m8(new_u, 128, vl / 2), vl / 2);
      vuint8m4_t v_output = vqmovun_s16(__riscv_vadd_vx_i16m8(new_v, 128, vl / 2), vl / 2);

      __riscv_vse8_v_u8m8(y0_ptr + w * 2, y0_output, vl);
      __riscv_vse8_v_u8m8(y1_ptr + w * 2, y1_output, vl);
      __riscv_vse8_v_u8m4(u_ptr + w, u_output, vl / 2);
      __riscv_vse8_v_u8m4(v_ptr + w, v_output, vl / 2);

      w += (vl / 2);
    } while (w < image->w / 2);
    y0_ptr += image->stride[UHDR_PLANE_Y] * 2;
    y1_ptr += image->stride[UHDR_PLANE_Y] * 2;
    u_ptr += image->stride[UHDR_PLANE_U];
    v_ptr += image->stride[UHDR_PLANE_V];
  } while (++h < image->h / 2);
}

void transformYuv444_rvv(uhdr_raw_image_t* image, const int16_t* coeffs_ptr) {
  // Implementation assumes image buffer is multiple of 16.
  assert(image->w % 16 == 0);
  uint8_t* y_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
  uint8_t* u_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
  uint8_t* v_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);

  size_t vl;
  size_t h = 0;
  do {
    size_t w = 0;
    do {
      vl = __riscv_vsetvl_e8m8((image->w) - w);

      vuint8m8_t y = __riscv_vle8_v_u8m8(y_ptr + w, vl);
      vuint8m8_t u = __riscv_vle8_v_u8m8(u_ptr + w, vl);
      vuint8m8_t v = __riscv_vle8_v_u8m8(v_ptr + w, vl);

      vuint16m8_t u16_wide_low = __riscv_vwsubu_vx_u16m8(vget_low_u8(u), 128, vl / 2);
      vuint16m8_t v16_wide_low = __riscv_vwsubu_vx_u16m8(vget_low_u8(v), 128, vl / 2);
      vuint16m8_t u16_wide_high = __riscv_vwsubu_vx_u16m8(vget_high_u8(u, vl), 128, vl / 2);
      vuint16m8_t v16_wide_high = __riscv_vwsubu_vx_u16m8(vget_high_u8(v, vl), 128, vl / 2);

      vint16m8_t u_wide_low_s16 = __riscv_vreinterpret_v_u16m8_i16m8(u16_wide_low);
      vint16m8_t v_wide_low_s16 = __riscv_vreinterpret_v_u16m8_i16m8(v16_wide_low);
      vint16m8_t u_wide_high_s16 = __riscv_vreinterpret_v_u16m8_i16m8(u16_wide_high);
      vint16m8_t v_wide_high_s16 = __riscv_vreinterpret_v_u16m8_i16m8(v16_wide_high);

      vint16m8_t y_lo =
          yConversion_rvv(vget_low_u8(y), u_wide_low_s16, v_wide_low_s16, coeffs_ptr, vl / 2);
      vint16m8_t y_hi = yConversion_rvv(vget_high_u8(y, vl / 2), u_wide_high_s16, v_wide_high_s16,
                                        coeffs_ptr, vl / 2);

      vint16m8_t new_u_lo = uConversion_rvv(u_wide_low_s16, v_wide_low_s16, coeffs_ptr, vl / 2);
      vint16m8_t new_v_lo = vConversion_rvv(u_wide_low_s16, v_wide_low_s16, coeffs_ptr, vl / 2);
      vint16m8_t new_u_hi = uConversion_rvv(u_wide_high_s16, v_wide_high_s16, coeffs_ptr, vl / 2);
      vint16m8_t new_v_hi = vConversion_rvv(u_wide_high_s16, v_wide_high_s16, coeffs_ptr, vl / 2);

      // Narrow from 16-bit to 8-bit with saturation.
      vuint8m8_t y_output = vcombine_u8(vqmovun_s16(y_lo, vl / 2), vqmovun_s16(y_hi, vl / 2), vl);
      vuint8m4_t u_output_hi = vqmovun_s16(__riscv_vadd_vx_i16m8(new_u_hi, 128, vl / 2), vl / 2);
      vuint8m4_t u_output_lo = vqmovun_s16(__riscv_vadd_vx_i16m8(new_u_lo, 128, vl / 2), vl / 2);
      vuint8m4_t v_output_hi = vqmovun_s16(__riscv_vadd_vx_i16m8(new_v_hi, 128, vl / 2), vl / 2);
      vuint8m4_t v_output_lo = vqmovun_s16(__riscv_vadd_vx_i16m8(new_v_lo, 128, vl / 2), vl / 2);

      vuint8m8_t u_output = vcombine_u8(u_output_lo, u_output_hi, vl);
      vuint8m8_t v_output = vcombine_u8(v_output_lo, v_output_hi, vl);

      __riscv_vse8_v_u8m8(y_ptr + w, y_output, vl);
      __riscv_vse8_v_u8m8(u_ptr + w, u_output, vl);
      __riscv_vse8_v_u8m8(v_ptr + w, v_output, vl);

      w += vl;
    } while (w < image->w);
    y_ptr += image->stride[UHDR_PLANE_Y];
    u_ptr += image->stride[UHDR_PLANE_U];
    v_ptr += image->stride[UHDR_PLANE_V];
  } while (++h < image->h);
}

uhdr_error_info_t convertYuv_rvv(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
                                 uhdr_color_gamut_t dst_encoding) {
  uhdr_error_info_t status = g_no_error;
  const int16_t* coeffs = nullptr;

  switch (src_encoding) {
    case UHDR_CG_BT_709:
      switch (dst_encoding) {
        case UHDR_CG_BT_709:
          return status;
        case UHDR_CG_DISPLAY_P3:
          coeffs = kYuv709To601_coeffs_simd;
          break;
        case UHDR_CG_BT_2100:
          coeffs = kYuv709To2100_coeffs_simd;
          break;
        default:
          status.error_code = UHDR_CODEC_INVALID_PARAM;
          status.has_detail = 1;
          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
                   dst_encoding);
          return status;
      }
      break;
    case UHDR_CG_DISPLAY_P3:
      switch (dst_encoding) {
        case UHDR_CG_BT_709:
          coeffs = kYuv601To709_coeffs_simd;
          break;
        case UHDR_CG_DISPLAY_P3:
          return status;
        case UHDR_CG_BT_2100:
          coeffs = kYuv601To2100_coeffs_simd;
          break;
        default:
          status.error_code = UHDR_CODEC_INVALID_PARAM;
          status.has_detail = 1;
          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
                   dst_encoding);
          return status;
      }
      break;
    case UHDR_CG_BT_2100:
      switch (dst_encoding) {
        case UHDR_CG_BT_709:
          coeffs = kYuv2100To709_coeffs_simd;
          break;
        case UHDR_CG_DISPLAY_P3:
          coeffs = kYuv2100To601_coeffs_simd;
          break;
        case UHDR_CG_BT_2100:
          return status;
        default:
          status.error_code = UHDR_CODEC_INVALID_PARAM;
          status.has_detail = 1;
          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
                   dst_encoding);
          return status;
      }
      break;
    default:
      status.error_code = UHDR_CODEC_INVALID_PARAM;
      status.has_detail = 1;
      snprintf(status.detail, sizeof status.detail, "Unrecognized src color gamut %d",
               src_encoding);
      return status;
  }

  if (image->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    transformYuv420_rvv(image, coeffs);
  } else if (image->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
    transformYuv444_rvv(image, coeffs);
  } else {
    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
    status.has_detail = 1;
    snprintf(status.detail, sizeof status.detail,
             "No implementation available for performing gamut conversion for color format %d",
             image->fmt);
    return status;
  }

  return status;
}

static void ConvertRgba8888ToYuv444_rvv(uhdr_raw_image_t* src, uhdr_raw_image_t* dst,
                                        const uint16_t* coeffs_ptr) {
  assert(src->stride[UHDR_PLANE_PACKED] % 16 == 0);
  uint8_t* rgba_base_ptr = static_cast<uint8_t*>(src->planes[UHDR_PLANE_PACKED]);

  uint8_t* y_base_ptr = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
  uint8_t* u_base_ptr = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
  uint8_t* v_base_ptr = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);

  uint32_t bias = (128 << 14) + 8191;

  size_t vl;
  size_t h = 0;
  do {
    size_t w = 0;
    uint8_t* rgba_ptr = rgba_base_ptr + (size_t)src->stride[UHDR_PLANE_PACKED] * 4 * h;
    uint8_t* y_ptr = y_base_ptr + (size_t)dst->stride[UHDR_PLANE_Y] * h;
    uint8_t* u_ptr = u_base_ptr + (size_t)dst->stride[UHDR_PLANE_U] * h;
    uint8_t* v_ptr = v_base_ptr + (size_t)dst->stride[UHDR_PLANE_V] * h;
    do {
      vl = __riscv_vsetvl_e8m8((src->w) - w);
      assert(vl % 4 == 0);

      vuint8m8_t r = __riscv_vlse8_v_u8m8(rgba_ptr, 4, vl);
      vuint8m8_t g = __riscv_vlse8_v_u8m8(rgba_ptr, 4, vl);
      vuint8m8_t b = __riscv_vlse8_v_u8m8(rgba_ptr, 4, vl);

      vuint16m4_t r_l = vmovl_u8(vget_low_u8(r), vl / 2);
      vuint16m4_t r_h = vmovl_u8(vget_high_u8(r, vl / 2), vl / 2);
      vuint16m4_t g_l = vmovl_u8(vget_low_u8(g), vl / 2);
      vuint16m4_t g_h = vmovl_u8(vget_high_u8(g, vl / 2), vl / 2);
      vuint16m4_t b_l = vmovl_u8(vget_low_u8(b), vl / 2);
      vuint16m4_t b_h = vmovl_u8(vget_high_u8(b, vl / 2), vl / 2);

      vuint32m4_t y_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(r_l), coeffs_ptr[0], vl / 4);
      y_ll = __riscv_vwmaccu_vx_u32m4(y_ll, coeffs_ptr[1], vget_low_u16m4(g_l), vl / 4);
      y_ll = __riscv_vwmaccu_vx_u32m4(y_ll, coeffs_ptr[2], vget_low_u16m4(b_l), vl / 4);
      vuint32m4_t y_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(r_l, vl / 2), coeffs_ptr[0], vl / 4);
      y_lh = __riscv_vwmaccu_vx_u32m4(y_lh, coeffs_ptr[1], vget_high_u16m4(g_l, vl / 2), vl / 4);
      y_lh = __riscv_vwmaccu_vx_u32m4(y_lh, coeffs_ptr[2], vget_high_u16m4(b_l, vl / 2), vl / 4);
      vuint32m4_t y_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(r_h), coeffs_ptr[0], vl / 4);
      y_hl = __riscv_vwmaccu_vx_u32m4(y_hl, coeffs_ptr[1], vget_low_u16m4(g_h), vl / 4);
      y_hl = __riscv_vwmaccu_vx_u32m4(y_hl, coeffs_ptr[2], vget_low_u16m4(b_h), vl / 4);
      vuint32m4_t y_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(r_h, vl / 2), coeffs_ptr[0], vl / 4);
      y_hh = __riscv_vwmaccu_vx_u32m4(y_hh, coeffs_ptr[1], vget_high_u16m4(g_h, vl / 2), vl / 4);
      y_hh = __riscv_vwmaccu_vx_u32m4(y_hh, coeffs_ptr[2], vget_high_u16m4(b_h, vl / 2), vl / 4);

      // B - R - G + bias
      vuint32m4_t cb_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(b_l), coeffs_ptr[5], vl / 4);
      vuint32m4_t cb_r_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(r_l), coeffs_ptr[3], vl / 4);
      cb_ll = __riscv_vsub_vv_u32m4(cb_ll, cb_r_ll, vl / 4);
      vuint32m4_t cb_g_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(g_l), coeffs_ptr[4], vl / 4);
      cb_ll = __riscv_vsub_vv_u32m4(cb_ll, cb_g_ll, vl / 4);
      cb_ll = __riscv_vadd_vx_u32m4(cb_ll, bias, vl / 4);

      vuint32m4_t cb_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(b_l, vl / 2), coeffs_ptr[5], vl / 4);
      vuint32m4_t cb_r_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(r_l, vl / 2), coeffs_ptr[3], vl / 4);
      cb_lh = __riscv_vsub_vv_u32m4(cb_lh, cb_r_lh, vl / 4);
      vuint32m4_t cb_g_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(g_l, vl / 2), coeffs_ptr[4], vl / 4);
      cb_lh = __riscv_vsub_vv_u32m4(cb_lh, cb_g_lh, vl / 4);
      cb_lh = __riscv_vadd_vx_u32m4(cb_lh, bias, vl / 4);

      vuint32m4_t cb_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(b_h), coeffs_ptr[5], vl / 4);
      vuint32m4_t cb_r_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(r_h), coeffs_ptr[3], vl / 4);
      cb_hl = __riscv_vsub_vv_u32m4(cb_hl, cb_r_hl, vl / 4);
      vuint32m4_t cb_g_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(g_h), coeffs_ptr[4], vl / 4);
      cb_hl = __riscv_vsub_vv_u32m4(cb_hl, cb_g_hl, vl / 4);
      cb_hl = __riscv_vadd_vx_u32m4(cb_hl, bias, vl / 4);

      vuint32m4_t cb_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(b_h, vl / 2), coeffs_ptr[5], vl / 4);
      vuint32m4_t cb_r_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(r_h, vl / 2), coeffs_ptr[3], vl / 4);
      cb_hh = __riscv_vsub_vv_u32m4(cb_hh, cb_r_hh, vl / 4);
      vuint32m4_t cb_g_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(g_h, vl / 2), coeffs_ptr[4], vl / 4);
      cb_hh = __riscv_vsub_vv_u32m4(cb_hh, cb_g_hh, vl / 4);
      cb_hh = __riscv_vadd_vx_u32m4(cb_hh, bias, vl / 4);

      // R - G - B + bias
      vuint32m4_t cr_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(r_l), coeffs_ptr[5], vl / 4);
      vuint32m4_t cr_g_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(g_l), coeffs_ptr[6], vl / 4);
      cr_ll = __riscv_vsub_vv_u32m4(cr_ll, cr_g_ll, vl / 4);
      vuint32m4_t cr_b_ll = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(b_l), coeffs_ptr[7], vl / 4);
      cr_ll = __riscv_vsub_vv_u32m4(cr_ll, cr_b_ll, vl / 4);
      cr_ll = __riscv_vadd_vx_u32m4(cr_ll, bias, vl / 4);

      vuint32m4_t cr_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(r_l, vl / 2), coeffs_ptr[5], vl / 4);
      vuint32m4_t cr_g_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(g_l, vl / 2), coeffs_ptr[6], vl / 4);
      cr_lh = __riscv_vsub_vv_u32m4(cr_lh, cr_g_lh, vl / 4);
      vuint32m4_t cr_b_lh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(b_l, vl / 2), coeffs_ptr[7], vl / 4);
      cr_lh = __riscv_vsub_vv_u32m4(cr_lh, cr_b_lh, vl / 4);
      cr_lh = __riscv_vadd_vx_u32m4(cr_lh, bias, vl / 4);

      vuint32m4_t cr_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(r_h), coeffs_ptr[5], vl / 4);
      vuint32m4_t cr_g_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(g_h), coeffs_ptr[6], vl / 4);
      cr_hl = __riscv_vsub_vv_u32m4(cr_hl, cr_g_hl, vl / 4);
      vuint32m4_t cr_b_hl = __riscv_vwmulu_vx_u32m4(vget_low_u16m4(b_h), coeffs_ptr[7], vl / 4);
      cr_hl = __riscv_vsub_vv_u32m4(cr_hl, cr_b_hl, vl / 4);
      cr_hl = __riscv_vadd_vx_u32m4(cr_hl, bias, vl / 4);

      vuint32m4_t cr_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(r_h, vl / 2), coeffs_ptr[5], vl / 4);
      vuint32m4_t cr_g_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(g_h, vl / 2), coeffs_ptr[6], vl / 4);
      cr_hh = __riscv_vsub_vv_u32m4(cr_hh, cr_g_hh, vl / 4);
      vuint32m4_t cr_b_hh =
          __riscv_vwmulu_vx_u32m4(vget_high_u16m4(b_h, vl / 2), coeffs_ptr[7], vl / 4);
      cr_hh = __riscv_vsub_vv_u32m4(cr_hh, cr_b_hh, vl / 4);
      cr_hh = __riscv_vadd_vx_u32m4(cr_hh, bias, vl / 4);

      vuint16m8_t y_l =
          vcombine_u16(vrshrn_n_u32(y_ll, 14, vl / 4), vrshrn_n_u32(y_lh, 14, vl / 4), vl / 2);
      vuint16m8_t y_h =
          vcombine_u16(vrshrn_n_u32(y_hl, 14, vl / 4), vrshrn_n_u32(y_hh, 14, vl / 4), vl / 2);
      vuint16m8_t cb_l =
          vcombine_u16(vrshrn_n_u32(cb_ll, 14, vl / 4), vrshrn_n_u32(cb_lh, 14, vl / 4), vl / 2);
      vuint16m8_t cb_h =
          vcombine_u16(vrshrn_n_u32(cb_hl, 14, vl / 4), vrshrn_n_u32(cb_hh, 14, vl / 4), vl / 2);
      vuint16m8_t cr_l =
          vcombine_u16(vrshrn_n_u32(cr_ll, 14, vl / 4), vrshrn_n_u32(cr_lh, 14, vl / 4), vl / 2);
      vuint16m8_t cr_h =
          vcombine_u16(vrshrn_n_u32(cr_hl, 14, vl / 4), vrshrn_n_u32(cr_hh, 14, vl / 4), vl / 2);

      __riscv_vse8_v_u8m8(y_ptr, vcombine_u8(vmovn_u16(y_l, vl / 2), vmovn_u16(y_h, vl / 2), vl),
                          vl);
      __riscv_vse8_v_u8m8(u_ptr, vcombine_u8(vmovn_u16(cb_l, vl / 2), vmovn_u16(cb_h, vl / 2), vl),
                          vl);
      __riscv_vse8_v_u8m8(v_ptr, vcombine_u8(vmovn_u16(cr_l, vl / 2), vmovn_u16(cr_h, vl / 2), vl),
                          vl);

      /* Increment pointers. */
      rgba_ptr += (vl * 4);
      y_ptr += vl;
      u_ptr += vl;
      v_ptr += vl;

      w += vl;
    } while (w < src->w);
    rgba_base_ptr += src->stride[UHDR_PLANE_PACKED];
    y_base_ptr += dst->stride[UHDR_PLANE_Y];
    u_base_ptr += dst->stride[UHDR_PLANE_U];
    v_base_ptr += dst->stride[UHDR_PLANE_V];
  } while (++h < src->h);
}

std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr_rvv(uhdr_raw_image_t* src) {
  if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    std::unique_ptr<uhdr_raw_image_ext_t> dst = nullptr;
    const uint16_t* coeffs_ptr = nullptr;

    if (src->cg == UHDR_CG_BT_709) {
      coeffs_ptr = kRgb709ToYuv_coeffs_simd;
    } else if (src->cg == UHDR_CG_BT_2100) {
      coeffs_ptr = kRgbDispP3ToYuv_coeffs_simd;
    } else if (src->cg == UHDR_CG_DISPLAY_P3) {
      coeffs_ptr = kRgb2100ToYuv_coeffs_simd;
    } else {
      return dst;
    }
    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppYCbCr444, src->cg, src->ct,
                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
    ConvertRgba8888ToYuv444_rvv(src, dst.get(), coeffs_ptr);
    return dst;
  }
  return nullptr;
}

}  // namespace ultrahdr
