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

// Scale all coefficients by 2^14 to avoid needing floating-point arithmetic. This can cause an off
// by one error compared to the scalar floating-point implementation.

// Removing conversion coefficients 1 and 0 from the group for each standard leaves 6 coefficients.
// Pack them into a single 128-bit vector as follows, zeroing the remaining elements:
// {Y1, Y2, U1, U2, V1, V2, 0, 0}

// Yuv Bt709 -> Yuv Bt601
// Y' = (1.0f * Y) + ( 0.101579f * U) + ( 0.196076f * V)
// U' = (0.0f * Y) + ( 0.989854f * U) + (-0.110653f * V)
// V' = (0.0f * Y) + (-0.072453f * U) + ( 0.983398f * V)
__attribute__((aligned(16)))
const int16_t kYuv709To601_coeffs_rvv[8] = {1664, 3213, 16218, -1813, -1187, 16112, 0, 0};

// Yuv Bt709 -> Yuv Bt2100
// Y' = (1.0f * Y) + (-0.016969f * U) + ( 0.096312f * V)
// U' = (0.0f * Y) + ( 0.995306f * U) + (-0.051192f * V)
// V' = (0.0f * Y) + ( 0.011507f * U) + ( 1.002637f * V)
__attribute__((aligned(16)))
const int16_t kYuv709To2100_coeffs_rvv[8] = {-278, 1578, 16307, -839, 189, 16427, 0, 0};

// Yuv Bt601 -> Yuv Bt709
// Y' = (1.0f * Y) + (-0.118188f * U) + (-0.212685f * V),
// U' = (0.0f * Y) + ( 1.018640f * U) + ( 0.114618f * V),
// V' = (0.0f * Y) + ( 0.075049f * U) + ( 1.025327f * V);
__attribute__((aligned(16)))
const int16_t kYuv601To709_coeffs_rvv[8] = {-1936, -3485, 16689, 1878, 1230, 16799, 0, 0};

// Yuv Bt601 -> Yuv Bt2100
// Y' = (1.0f * Y) + (-0.128245f * U) + (-0.115879f * V)
// U' = (0.0f * Y) + ( 1.010016f * U) + ( 0.061592f * V)
// V' = (0.0f * Y) + ( 0.086969f * U) + ( 1.029350f * V)
__attribute__((aligned(16)))
const int16_t kYuv601To2100_coeffs_rvv[8] = {-2101, -1899, 16548, 1009, 1425, 16865, 0, 0};

// Yuv Bt2100 -> Yuv Bt709
// Y' = (1.0f * Y) + ( 0.018149f * U) + (-0.095132f * V)
// U' = (0.0f * Y) + ( 1.004123f * U) + ( 0.051267f * V)
// V' = (0.0f * Y) + (-0.011524f * U) + ( 0.996782f * V)
__attribute__((aligned(16)))
const int16_t kYuv2100To709_coeffs_rvv[8] = {297, -1559, 16452, 840, -189, 16331, 0, 0};

// Yuv Bt2100 -> Yuv Bt601
// Y' = (1.0f * Y) + ( 0.117887f * U) + ( 0.105521f * V)
// U' = (0.0f * Y) + ( 0.995211f * U) + (-0.059549f * V)
// V' = (0.0f * Y) + (-0.084085f * U) + ( 0.976518f * V)
__attribute__((aligned(16)))
const int16_t kYuv2100To601_coeffs_rvv[8] = {1931, 1729, 16306, -976, -1378, 15999, 0, 0};

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

static inline vuint16m4_t vget_high_u16(vuint16m8_t u, size_t vl) {
  return __riscv_vget_v_u16m8_u16m4(__riscv_vslidedown_vx_u16m8(u, vl / 2, vl), 0);
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

static inline vuint8m4_t vqmovun_s16(vint16m8_t a, size_t vl) {
  vuint16m8_t a_non_neg = __riscv_vreinterpret_v_i16m8_u16m8(__riscv_vmax_vx_i16m8(a, 0, vl));
  return __riscv_vnclipu_wx_u8m4(a_non_neg, 0, vl);
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
          coeffs = kYuv709To601_coeffs_rvv;
          break;
        case UHDR_CG_BT_2100:
          coeffs = kYuv709To2100_coeffs_rvv;
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
          coeffs = kYuv601To709_coeffs_rvv;
          break;
        case UHDR_CG_DISPLAY_P3:
          return status;
        case UHDR_CG_BT_2100:
          coeffs = kYuv601To2100_coeffs_rvv;
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
          coeffs = kYuv2100To709_coeffs_rvv;
          break;
        case UHDR_CG_DISPLAY_P3:
          coeffs = kYuv2100To601_coeffs_rvv;
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
}  // namespace ultrahdr
