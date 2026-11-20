/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/icc.h"

namespace ultrahdr {

static void Matrix3x3_apply(const Matrix3x3* m, float* x) {
  float y0 = x[0] * m->vals[0][0] + x[1] * m->vals[0][1] + x[2] * m->vals[0][2];
  float y1 = x[0] * m->vals[1][0] + x[1] * m->vals[1][1] + x[2] * m->vals[1][2];
  float y2 = x[0] * m->vals[2][0] + x[1] * m->vals[2][1] + x[2] * m->vals[2][2];
  x[0] = y0;
  x[1] = y1;
  x[2] = y2;
}

bool Matrix3x3_invert(const Matrix3x3* src, Matrix3x3* dst) {
  double a00 = src->vals[0][0];
  double a01 = src->vals[1][0];
  double a02 = src->vals[2][0];
  double a10 = src->vals[0][1];
  double a11 = src->vals[1][1];
  double a12 = src->vals[2][1];
  double a20 = src->vals[0][2];
  double a21 = src->vals[1][2];
  double a22 = src->vals[2][2];

  double b0 = a00 * a11 - a01 * a10;
  double b1 = a00 * a12 - a02 * a10;
  double b2 = a01 * a12 - a02 * a11;
  double b3 = a20;
  double b4 = a21;
  double b5 = a22;

  double determinant = b0 * b5 - b1 * b4 + b2 * b3;

  if (determinant == 0) {
    return false;
  }

  double invdet = 1.0 / determinant;
  if (invdet > +FLT_MAX || invdet < -FLT_MAX || !isfinitef_((float)invdet)) {
    return false;
  }

  b0 *= invdet;
  b1 *= invdet;
  b2 *= invdet;
  b3 *= invdet;
  b4 *= invdet;
  b5 *= invdet;

  dst->vals[0][0] = (float)(a11 * b5 - a12 * b4);
  dst->vals[1][0] = (float)(a02 * b4 - a01 * b5);
  dst->vals[2][0] = (float)(+b2);
  dst->vals[0][1] = (float)(a12 * b3 - a10 * b5);
  dst->vals[1][1] = (float)(a00 * b5 - a02 * b3);
  dst->vals[2][1] = (float)(-b1);
  dst->vals[0][2] = (float)(a10 * b4 - a11 * b3);
  dst->vals[1][2] = (float)(a01 * b3 - a00 * b4);
  dst->vals[2][2] = (float)(+b0);

  for (int r = 0; r < 3; ++r)
    for (int c = 0; c < 3; ++c) {
      if (!isfinitef_(dst->vals[r][c])) {
        return false;
      }
    }
  return true;
}

static Matrix3x3 Matrix3x3_concat(const Matrix3x3* A, const Matrix3x3* B) {
  Matrix3x3 m = {{{0, 0, 0}, {0, 0, 0}, {0, 0, 0}}};
  for (int r = 0; r < 3; r++)
    for (int c = 0; c < 3; c++) {
      m.vals[r][c] = A->vals[r][0] * B->vals[0][c] + A->vals[r][1] * B->vals[1][c] +
                     A->vals[r][2] * B->vals[2][c];
    }
  return m;
}

static void float_XYZD50_to_grid16_lab(const float* xyz_float, uint8_t* grid16_lab) {
  float v[3] = {
      xyz_float[0] / kD50_x,
      xyz_float[1] / kD50_y,
      xyz_float[2] / kD50_z,
  };
  for (size_t i = 0; i < 3; ++i) {
    v[i] = v[i] > 0.008856f ? cbrtf(v[i]) : v[i] * 7.787f + (16 / 116.0f);
  }
  const float L = v[1] * 116.0f - 16.0f;
  const float a = (v[0] - v[1]) * 500.0f;
  const float b = (v[1] - v[2]) * 200.0f;
  const float Lab_unorm[3] = {
      L * (1 / 100.f),
      (a + 128.0f) * (1 / 255.0f),
      (b + 128.0f) * (1 / 255.0f),
  };
  // This will encode L=1 as 0xFFFF. This matches how skcms will interpret the
  // table, but the spec appears to indicate that the value should be 0xFF00.
  // https://crbug.com/skia/13807
  for (size_t i = 0; i < 3; ++i) {
    const uint16_t u16 = float_round_to_unorm16(Lab_unorm[i]);
    grid16_lab[2 * i] = static_cast<uint8_t>((u16 >> 8) & 0xFFu);
    grid16_lab[2 * i + 1] = static_cast<uint8_t>(u16 & 0xFFu);
  }
}

namespace {

template <typename EnumT>
inline int loadIccEnumRaw(const EnumT& value) {
  static_assert(sizeof(EnumT) == sizeof(int), "Expected int-sized enum");
  int raw = 0;
  std::memcpy(&raw, &value, sizeof(raw));
  return raw;
}

inline uint32_t readIccBE32(const uint8_t* ptr) {
  return (static_cast<uint32_t>(ptr[0]) << 24) | (static_cast<uint32_t>(ptr[1]) << 16) |
         (static_cast<uint32_t>(ptr[2]) << 8) | static_cast<uint32_t>(ptr[3]);
}

inline void writeIccBE32(uint8_t* ptr, uint32_t val) {
  ptr[0] = static_cast<uint8_t>((val >> 24) & 0xFFu);
  ptr[1] = static_cast<uint8_t>((val >> 16) & 0xFFu);
  ptr[2] = static_cast<uint8_t>((val >> 8) & 0xFFu);
  ptr[3] = static_cast<uint8_t>(val & 0xFFu);
}

inline const char* getDescLiteral(int tf_raw, int gamut_raw) {
  switch (gamut_raw) {
    case UHDR_CG_BT_709:
      switch (tf_raw) {
        case UHDR_CT_SRGB:
          return "sRGB Gamut with sRGB Transfer";
        case UHDR_CT_LINEAR:
          return "sRGB Gamut with Linear Transfer";
        case UHDR_CT_PQ:
          return "sRGB Gamut with PQ Transfer";
        case UHDR_CT_HLG:
          return "sRGB Gamut with HLG Transfer";
        default:
          return nullptr;
      }
    case UHDR_CG_DISPLAY_P3:
      switch (tf_raw) {
        case UHDR_CT_SRGB:
          return "Display P3 Gamut with sRGB Transfer";
        case UHDR_CT_LINEAR:
          return "Display P3 Gamut with Linear Transfer";
        case UHDR_CT_PQ:
          return "Display P3 Gamut with PQ Transfer";
        case UHDR_CT_HLG:
          return "Display P3 Gamut with HLG Transfer";
        default:
          return nullptr;
      }
    case UHDR_CG_BT_2100:
      switch (tf_raw) {
        case UHDR_CT_SRGB:
          return "Rec2020 Gamut with sRGB Transfer";
        case UHDR_CT_LINEAR:
          return "Rec2020 Gamut with Linear Transfer";
        case UHDR_CT_PQ:
          return "Rec2020 Gamut with PQ Transfer";
        case UHDR_CT_HLG:
          return "Rec2020 Gamut with HLG Transfer";
        default:
          return nullptr;
      }
    default:
      return nullptr;
  }
}

inline size_t textTagPaddedSize(size_t text_length) { return ALIGNM(28 + text_length * 2, 4); }

inline void writeTextTagBytes(uint8_t* dst, const char* text, size_t text_length,
                              size_t padded_length) {
  writeIccBE32(dst, kTAG_TextType);
  writeIccBE32(dst + 4, 0u);
  writeIccBE32(dst + 8, 1u);
  writeIccBE32(dst + 12, 12u);
  writeIccBE32(dst + 16, SetFourByteTag('e', 'n', 'U', 'S'));
  writeIccBE32(dst + 20, static_cast<uint32_t>(2u * text_length));
  writeIccBE32(dst + 24, 28u);
  for (size_t i = 0; i < text_length; ++i) {
    dst[28 + 2 * i] = 0u;
    dst[28 + 2 * i + 1] = static_cast<uint8_t>(text[i]);
  }
  const size_t unpadded = 28 + 2 * text_length;
  if (padded_length > unpadded) {
    std::memset(dst + unpadded, 0, padded_length - unpadded);
  }
}

inline void writeXyzTagBytes(uint8_t* dst, float x, float y, float z) {
  writeIccBE32(dst, kXYZ_PCSSpace);
  writeIccBE32(dst + 4, 0u);
  writeIccBE32(dst + 8, static_cast<uint32_t>(float_round_to_fixed(x)));
  writeIccBE32(dst + 12, static_cast<uint32_t>(float_round_to_fixed(y)));
  writeIccBE32(dst + 16, static_cast<uint32_t>(float_round_to_fixed(z)));
}

inline size_t curveTableTagPaddedSize(size_t table_entries) {
  return ALIGNM(12 + table_entries * 2, 4);
}

inline void writeCurveTableTagBytes(uint8_t* dst, uint32_t table_entries, const void* table_16,
                                    size_t padded_length) {
  writeIccBE32(dst, kTAG_CurveType);
  writeIccBE32(dst + 4, 0u);
  writeIccBE32(dst + 8, table_entries);
  const size_t table_bytes = static_cast<size_t>(table_entries) * 2u;
  if (table_bytes > 0) {
    std::memcpy(dst + 12, table_16, table_bytes);
  }
  const size_t unpadded = 12 + table_bytes;
  if (padded_length > unpadded) {
    std::memset(dst + unpadded, 0, padded_length - unpadded);
  }
}

inline bool isExponentialParaCurve(const TransferFunction& fn) {
  return fn.a == 1.f && fn.b == 0.f && fn.c == 0.f && fn.d == 0.f && fn.e == 0.f && fn.f == 0.f;
}

inline size_t paraCurveTagSize(const TransferFunction& fn) {
  return isExponentialParaCurve(fn) ? 16u : 40u;
}

inline void writeParaCurveTagBytes(uint8_t* dst, const TransferFunction& fn) {
  writeIccBE32(dst, kTAG_ParaCurveType);
  writeIccBE32(dst + 4, 0u);
  if (isExponentialParaCurve(fn)) {
    writeIccBE32(dst + 8, static_cast<uint32_t>(kExponential_ParaCurveType) << 16);
    writeIccBE32(dst + 12, static_cast<uint32_t>(float_round_to_fixed(fn.g)));
    return;
  }
  writeIccBE32(dst + 8, static_cast<uint32_t>(kGABCDEF_ParaCurveType) << 16);
  writeIccBE32(dst + 12, static_cast<uint32_t>(float_round_to_fixed(fn.g)));
  writeIccBE32(dst + 16, static_cast<uint32_t>(float_round_to_fixed(fn.a)));
  writeIccBE32(dst + 20, static_cast<uint32_t>(float_round_to_fixed(fn.b)));
  writeIccBE32(dst + 24, static_cast<uint32_t>(float_round_to_fixed(fn.c)));
  writeIccBE32(dst + 28, static_cast<uint32_t>(float_round_to_fixed(fn.d)));
  writeIccBE32(dst + 32, static_cast<uint32_t>(float_round_to_fixed(fn.e)));
  writeIccBE32(dst + 36, static_cast<uint32_t>(float_round_to_fixed(fn.f)));
}

inline void writeCicpTagBytes(uint8_t* dst, uint32_t color_primaries,
                              uint32_t transfer_characteristics) {
  writeIccBE32(dst, kTAG_cicp);
  writeIccBE32(dst + 4, 0u);
  dst[8] = static_cast<uint8_t>(color_primaries);
  dst[9] = static_cast<uint8_t>(transfer_characteristics);
  dst[10] = 0u;
  dst[11] = 1u;
}

inline bool isValidHagcTagSize(const void* hagc_data, size_t hagc_size) {
  return hagc_data != nullptr && hagc_size > 0 &&
         hagc_size <=
             static_cast<size_t>((std::numeric_limits<uint32_t>::max)() - kHagcTagHeaderSize - 3u);
}

inline void writeHagcTagBytes(uint8_t* dst, const void* hagc_data, size_t hagc_size,
                              size_t padded_length) {
  writeIccBE32(dst, kTAG_HAGCType);
  writeIccBE32(dst + 4, 0u);
  writeIccBE32(dst + 8, static_cast<uint32_t>(hagc_size));
  std::memcpy(dst + kHagcTagHeaderSize, hagc_data, hagc_size);
  const size_t unpadded = kHagcTagHeaderSize + hagc_size;
  if (padded_length > unpadded) {
    std::memset(dst + unpadded, 0, padded_length - unpadded);
  }
}

inline bool bufferAliasesVector(const std::vector<uint8_t>& vec, const void* ptr) {
  if (ptr == nullptr || vec.data() == nullptr || vec.capacity() == 0) {
    return false;
  }
  const uintptr_t begin = reinterpret_cast<uintptr_t>(vec.data());
  const uintptr_t end = begin + vec.capacity();
  const uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
  return addr >= begin && addr < end;
}

}  // namespace

std::string IccHelper::get_desc_string(const uhdr_color_transfer_t tf,
                                       const uhdr_color_gamut_t gamut) {
  const char* literal = getDescLiteral(loadIccEnumRaw(tf), loadIccEnumRaw(gamut));
  if (literal != nullptr) {
    return std::string(literal);
  }
  std::string result;
  switch (loadIccEnumRaw(gamut)) {
    case UHDR_CG_BT_709:
      result += "sRGB";
      break;
    case UHDR_CG_DISPLAY_P3:
      result += "Display P3";
      break;
    case UHDR_CG_BT_2100:
      result += "Rec2020";
      break;
    default:
      result += "Unknown";
      break;
  }
  result += " Gamut with ";
  switch (loadIccEnumRaw(tf)) {
    case UHDR_CT_SRGB:
      result += "sRGB";
      break;
    case UHDR_CT_LINEAR:
      result += "Linear";
      break;
    case UHDR_CT_PQ:
      result += "PQ";
      break;
    case UHDR_CT_HLG:
      result += "HLG";
      break;
    default:
      result += "Unknown";
      break;
  }
  result += " Transfer";
  return result;
}

std::shared_ptr<DataStruct> IccHelper::write_text_tag(const char* text) {
  const size_t text_length = std::strlen(text);
  const size_t total_length = textTagPaddedSize(text_length);
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeTextTagBytes(dst, text, text_length, total_length);
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_xyz_tag(float x, float y, float z) {
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(kColorantTagSize);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeXyzTagBytes(dst, x, y, z);
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_trc_tag(const int table_entries,
                                                     const void* table_16) {
  if (table_entries < 0) {
    return nullptr;
  }
  const size_t total_length = curveTableTagPaddedSize(static_cast<size_t>(table_entries));
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeCurveTableTagBytes(dst, static_cast<uint32_t>(table_entries), table_16, total_length);
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_trc_tag(const TransferFunction& fn) {
  const size_t total_length = paraCurveTagSize(fn);
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeParaCurveTagBytes(dst, fn);
  }
  return dataStruct;
}

float IccHelper::compute_tone_map_gain(const uhdr_color_transfer_t tf, float L) {
  if (L <= 0.f) {
    return 1.f;
  }
  if (tf == UHDR_CT_PQ) {
    // The PQ transfer function will map to the range [0, 1]. Linearly scale
    // it up to the range [0, 10,000/203]. We will then tone map that back
    // down to [0, 1].
    constexpr float kInputMaxLuminance = 10000 / 203.f;
    constexpr float kOutputMaxLuminance = 1.0;
    L *= kInputMaxLuminance;

    // Compute the tone map gain which will tone map from 10,000/203 to 1.0.
    constexpr float kToneMapA = kOutputMaxLuminance / (kInputMaxLuminance * kInputMaxLuminance);
    constexpr float kToneMapB = 1.f / kOutputMaxLuminance;
    return kInputMaxLuminance * (1.f + kToneMapA * L) / (1.f + kToneMapB * L);
  }
  if (tf == UHDR_CT_HLG) {
    // Let Lw be the brightness of the display in nits.
    constexpr float Lw = 203.f;
    const float gamma = 1.2f + 0.42f * std::log(Lw / 1000.f) / std::log(10.f);
    return std::pow(L, gamma - 1.f);
  }
  return 1.f;
}

std::shared_ptr<DataStruct> IccHelper::write_cicp_tag(uint32_t color_primaries,
                                                      uint32_t transfer_characteristics) {
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(kCicpTagSize);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeCicpTagBytes(dst, color_primaries, transfer_characteristics);
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_hagc_tag(const void* hagc_data, size_t hagc_size) {
  if (!isValidHagcTagSize(hagc_data, hagc_size)) {
    return nullptr;
  }
  const size_t total_length = ALIGNM(kHagcTagHeaderSize + hagc_size, 4);
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst == nullptr) {
    return nullptr;
  }
  writeHagcTagBytes(dst, hagc_data, hagc_size, total_length);
  return dataStruct;
}

void IccHelper::compute_lut_entry(const Matrix3x3& src_to_XYZD50, float rgb[3]) {
  // Compute the matrices to convert from source to Rec2020, and from Rec2020 to XYZD50.
  Matrix3x3 src_to_rec2020;
  const Matrix3x3 rec2020_to_XYZD50 = kRec2020;
  {
    Matrix3x3 XYZD50_to_rec2020;
    Matrix3x3_invert(&rec2020_to_XYZD50, &XYZD50_to_rec2020);
    src_to_rec2020 = Matrix3x3_concat(&XYZD50_to_rec2020, &src_to_XYZD50);
  }

  // Convert the source signal to linear.
  for (size_t i = 0; i < kNumChannels; ++i) {
    rgb[i] = pqOetf(rgb[i]);
  }

  // Convert source gamut to Rec2020.
  Matrix3x3_apply(&src_to_rec2020, rgb);

  // Compute the luminance of the signal.
  float L = bt2100Luminance({{{rgb[0], rgb[1], rgb[2]}}});

  // Compute the tone map gain based on the luminance.
  float tone_map_gain = compute_tone_map_gain(UHDR_CT_PQ, L);

  // Apply the tone map gain.
  for (size_t i = 0; i < kNumChannels; ++i) {
    rgb[i] *= tone_map_gain;
  }

  // Convert from Rec2020-linear to XYZD50.
  Matrix3x3_apply(&rec2020_to_XYZD50, rgb);
}

namespace {

inline size_t clutPaddedSize(size_t num_channels, const uint8_t* grid_points) {
  size_t value_count = num_channels;
  for (size_t i = 0; i < num_channels; ++i) {
    value_count *= grid_points[i];
  }
  return ALIGNM(20 + 2 * value_count, 4);
}

inline void writeClutHeaderBytes(uint8_t* dst, size_t num_channels, const uint8_t* grid_points) {
  for (size_t i = 0; i < 16; ++i) {
    dst[i] = i < num_channels ? grid_points[i] : 0u;
  }
  dst[16] = 2u;  // Grid byte width (always 16-bit)
  dst[17] = 0u;  // Reserved
  dst[18] = 0u;  // Reserved
  dst[19] = 0u;  // Reserved
}

inline void writeClutBytes(uint8_t* dst, size_t num_channels, const uint8_t* grid_points,
                           const uint8_t* grid_16, size_t padded_length) {
  writeClutHeaderBytes(dst, num_channels, grid_points);
  size_t value_count = num_channels;
  for (size_t i = 0; i < num_channels; ++i) {
    value_count *= grid_points[i];
  }
  const size_t grid_bytes = 2 * value_count;
  if (grid_bytes > 0) {
    std::memcpy(dst + 20, grid_16, grid_bytes);
  }
  const size_t unpadded = 20 + grid_bytes;
  if (padded_length > unpadded) {
    std::memset(dst + unpadded, 0, padded_length - unpadded);
  }
}

inline size_t mabOrMbaTagSize(bool has_a_curves, size_t num_channels, const uint8_t* grid_points) {
  const size_t curve_set_bytes = num_channels * paraCurveTagSize(kLinear_TransFun);
  size_t total = 32 + curve_set_bytes;
  if (has_a_curves) {
    total += clutPaddedSize(num_channels, grid_points) + curve_set_bytes;
  }
  return total;
}

inline void writeMabOrMbaHeaderAndCurves(uint8_t* dst, uint32_t type, bool has_a_curves,
                                         size_t num_channels, const uint8_t* grid_points) {
  const size_t b_curves_offset = 32;
  const size_t single_curve_len = paraCurveTagSize(kLinear_TransFun);
  const size_t curve_set_bytes = num_channels * single_curve_len;
  const size_t clut_len = has_a_curves ? clutPaddedSize(num_channels, grid_points) : 0;
  const size_t clut_offset = has_a_curves ? (b_curves_offset + curve_set_bytes) : 0;
  const size_t a_curves_offset = has_a_curves ? (clut_offset + clut_len) : 0;

  writeIccBE32(dst, type);                                         // Type signature
  writeIccBE32(dst + 4, 0u);                                       // Reserved
  dst[8] = static_cast<uint8_t>(num_channels);                     // Input channels
  dst[9] = static_cast<uint8_t>(num_channels);                     // Output channels
  dst[10] = 0u;                                                    // Reserved
  dst[11] = 0u;                                                    // Reserved
  writeIccBE32(dst + 12, static_cast<uint32_t>(b_curves_offset));  // B curve offset
  writeIccBE32(dst + 16, 0u);                                      // Matrix offset
  writeIccBE32(dst + 20, 0u);                                      // M curve offset
  writeIccBE32(dst + 24, static_cast<uint32_t>(clut_offset));      // CLUT offset
  writeIccBE32(dst + 28, static_cast<uint32_t>(a_curves_offset));  // A curve offset

  for (size_t i = 0; i < num_channels; ++i) {
    writeParaCurveTagBytes(dst + b_curves_offset + i * single_curve_len, kLinear_TransFun);
  }
  if (has_a_curves) {
    for (size_t i = 0; i < num_channels; ++i) {
      writeParaCurveTagBytes(dst + a_curves_offset + i * single_curve_len, kLinear_TransFun);
    }
  }
}

}  // namespace

std::shared_ptr<DataStruct> IccHelper::write_clut(const uint8_t* grid_points,
                                                  const uint8_t* grid_16) {
  const size_t total_length = clutPaddedSize(kNumChannels, grid_points);
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeClutBytes(dst, kNumChannels, grid_points, grid_16, total_length);
  }
  return dataStruct;
}

std::shared_ptr<DataStruct> IccHelper::write_mAB_or_mBA_tag(uint32_t type, bool has_a_curves,
                                                            const uint8_t* grid_points,
                                                            const uint8_t* grid_16) {
  const size_t total_length = mabOrMbaTagSize(has_a_curves, kNumChannels, grid_points);
  std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(total_length);
  uint8_t* dst = static_cast<uint8_t*>(dataStruct->getData());
  if (dst != nullptr) {
    writeMabOrMbaHeaderAndCurves(dst, type, has_a_curves, kNumChannels, grid_points);
    if (has_a_curves) {
      const size_t clut_offset = 32 + kNumChannels * paraCurveTagSize(kLinear_TransFun);
      const size_t clut_len = clutPaddedSize(kNumChannels, grid_points);
      writeClutBytes(dst + clut_offset, kNumChannels, grid_points, grid_16, clut_len);
    }
  }
  return dataStruct;
}

namespace {

bool unwrapIccProfile(const void* icc_data, size_t icc_size, const uint8_t*& out_profile,
                      size_t& out_profile_size, bool& out_has_jpeg_id) {
  if (icc_data == nullptr) {
    return false;
  }
  const uint8_t* bytes = static_cast<const uint8_t*>(icc_data);
  if (icc_size >= sizeof(kICCIdentifier) &&
      memcmp(bytes, kICCIdentifier, sizeof(kICCIdentifier)) == 0) {
    if (icc_size < kICCIdentifierSize + sizeof(ICCHeader)) {
      return false;
    }
    // Single-chunk APP2 ICC segments must carry chunk_index == 1 and chunk_count == 1.
    // Unreassembled multi-chunk or malformed APP2 headers are rejected.
    if (bytes[12] != 1 || bytes[13] != 1) {
      return false;
    }
    out_profile = bytes + kICCIdentifierSize;
    out_profile_size = icc_size - kICCIdentifierSize;
    out_has_jpeg_id = true;
    return true;
  }
  if (icc_size >= sizeof(ICCHeader)) {
    out_profile = bytes;
    out_profile_size = icc_size;
    out_has_jpeg_id = false;
    return true;
  }
  return false;
}

}  // namespace

struct IccHelper::Serializer {
  template <typename AllocateFn>
  static bool serializeProfile(uhdr_color_transfer_t tf, uhdr_color_gamut_t gamut,
                               const void* hagc_data, size_t hagc_size,
                               bool include_jpeg_identifier, AllocateFn&& allocate_dst) {
    const int tf_raw = loadIccEnumRaw(tf);
    const int gamut_raw = loadIccEnumRaw(gamut);
    if (tf_raw != UHDR_CT_SRGB && tf_raw != UHDR_CT_LINEAR && tf_raw != UHDR_CT_HLG &&
        tf_raw != UHDR_CT_PQ) {
      return false;
    }
    if ((hagc_data == nullptr) != (hagc_size == 0)) {
      return false;
    }
    if (hagc_size > 0 && !isValidHagcTagSize(hagc_data, hagc_size)) {
      return false;
    }

    Matrix3x3 toXYZD50;
    switch (gamut_raw) {
      case UHDR_CG_BT_709:
        toXYZD50 = kSRGB;
        break;
      case UHDR_CG_DISPLAY_P3:
        toXYZD50 = kDisplayP3;
        break;
      case UHDR_CG_BT_2100:
        toXYZD50 = kRec2020;
        break;
      default:
        return false;
    }

    const char* desc_text = getDescLiteral(tf_raw, gamut_raw);
    if (desc_text == nullptr) {
      return false;
    }
    const size_t desc_text_len = std::strlen(desc_text);
    static constexpr char kCprtText[] = "Google Inc. 2022";
    static constexpr size_t kCprtTextLen = sizeof(kCprtText) - 1;

    std::array<uint8_t, IccHelper::kTrcTableSize * 2> hlg_trc_table{};
    size_t trc_tag_len = 0;
    if (tf_raw == UHDR_CT_HLG) {
      for (uint32_t i = 0; i < IccHelper::kTrcTableSize; ++i) {
        float x = i / (IccHelper::kTrcTableSize - 1.f);
        float y = hlgOetf(x);
        y *= IccHelper::compute_tone_map_gain(UHDR_CT_HLG, y);
        float_to_table16(y, &hlg_trc_table[2 * i]);
      }
      trc_tag_len = curveTableTagPaddedSize(IccHelper::kTrcTableSize);
    } else if (tf_raw == UHDR_CT_SRGB) {
      trc_tag_len = paraCurveTagSize(kSRGB_TransFun);
    } else if (tf_raw == UHDR_CT_LINEAR) {
      trc_tag_len = paraCurveTagSize(kLinear_TransFun);
    }

    static constexpr std::array<uint8_t, IccHelper::kNumChannels> kPqGridPoints = {
        IccHelper::kGridSize, IccHelper::kGridSize, IccHelper::kGridSize};

    enum class TagKind : uint8_t {
      kDesc,
      kRxyz,
      kGxyz,
      kBxyz,
      kWtpt,
      kTrc,
      kCicp,
      kHagc,
      kA2B0,
      kB2A0,
      kCprt,
    };
    struct TagPlan {
      uint32_t sig = 0;
      TagKind kind = TagKind::kDesc;
      size_t length = 0;
    };

    ICCHeader header;
    std::array<TagPlan, 16> tags{};
    size_t num_tags = 0;

    tags[num_tags++] = {kTAG_desc, TagKind::kDesc, textTagPaddedSize(desc_text_len)};
    tags[num_tags++] = {kTAG_rXYZ, TagKind::kRxyz, kColorantTagSize};
    tags[num_tags++] = {kTAG_gXYZ, TagKind::kGxyz, kColorantTagSize};
    tags[num_tags++] = {kTAG_bXYZ, TagKind::kBxyz, kColorantTagSize};
    tags[num_tags++] = {kTAG_wtpt, TagKind::kWtpt, kColorantTagSize};

    if (tf_raw != UHDR_CT_PQ) {
      tags[num_tags++] = {kTAG_rTRC, TagKind::kTrc, trc_tag_len};
      tags[num_tags++] = {kTAG_gTRC, TagKind::kTrc, trc_tag_len};
      tags[num_tags++] = {kTAG_bTRC, TagKind::kTrc, trc_tag_len};
    }

    uint32_t color_primaries = kCICPPrimariesUnSpecified;
    uint32_t transfer_characteristics = kCICPTrfnUnSpecified;
    if (tf_raw == UHDR_CT_HLG || tf_raw == UHDR_CT_PQ || tf_raw == UHDR_CT_LINEAR) {
      header.version = Endian_SwapBE32(0x04400000);
      if (gamut_raw == UHDR_CG_BT_709) {
        color_primaries = kCICPPrimariesSRGB;
      } else if (gamut_raw == UHDR_CG_DISPLAY_P3) {
        color_primaries = kCICPPrimariesP3;
      } else if (gamut_raw == UHDR_CG_BT_2100) {
        color_primaries = kCICPPrimariesRec2020;
      }

      if (tf_raw == UHDR_CT_LINEAR) {
        transfer_characteristics = kCICPTrfnLinear;
      } else if (tf_raw == UHDR_CT_PQ) {
        transfer_characteristics = kCICPTrfnPQ;
      } else if (tf_raw == UHDR_CT_HLG) {
        transfer_characteristics = kCICPTrfnHLG;
      }
      tags[num_tags++] = {kTAG_cicp, TagKind::kCicp, kCicpTagSize};
    }

    if (hagc_size > 0) {
      header.version = Endian_SwapBE32(0x04400000);
      tags[num_tags++] = {kTAG_HAGC, TagKind::kHagc, ALIGNM(kHagcTagHeaderSize + hagc_size, 4)};
    }

    if (tf_raw == UHDR_CT_PQ) {
      tags[num_tags++] = {
          kTAG_A2B0, TagKind::kA2B0,
          mabOrMbaTagSize(/*has_a_curves=*/true, IccHelper::kNumChannels, kPqGridPoints.data())};
      tags[num_tags++] = {
          kTAG_B2A0, TagKind::kB2A0,
          mabOrMbaTagSize(/*has_a_curves=*/false, IccHelper::kNumChannels, nullptr)};
    }

    tags[num_tags++] = {kTAG_cprt, TagKind::kCprt, textTagPaddedSize(kCprtTextLen)};

    const size_t tag_table_size = kICCTagTableEntrySize * num_tags;
    size_t profile_size = kICCHeaderSize + tag_table_size;
    for (size_t i = 0; i < num_tags; ++i) {
      if (tags[i].length > (std::numeric_limits<uint32_t>::max)() - profile_size) {
        return false;
      }
      profile_size += tags[i].length;
    }

    const size_t prefix_len = include_jpeg_identifier ? kICCIdentifierSize : 0;
    if (profile_size > (std::numeric_limits<size_t>::max)() - prefix_len) {
      return false;
    }
    uint8_t* dst = allocate_dst(prefix_len + profile_size);
    if (dst == nullptr) {
      return false;
    }

    if (include_jpeg_identifier) {
      std::memcpy(dst, kICCIdentifier, sizeof(kICCIdentifier));
      dst[12] = 1;
      dst[13] = 1;
      dst += kICCIdentifierSize;
    }

    header.data_color_space = Endian_SwapBE32(Signature_RGB);
    header.pcs = Endian_SwapBE32(tf_raw == UHDR_CT_PQ ? Signature_Lab : Signature_XYZ);
    header.size = Endian_SwapBE32(static_cast<uint32_t>(profile_size));
    header.tag_count = Endian_SwapBE32(static_cast<uint32_t>(num_tags));
    std::memcpy(dst, &header, sizeof(header));

    size_t tag_offset = sizeof(header) + tag_table_size;
    for (size_t i = 0; i < num_tags; ++i) {
      uint8_t* entry = dst + sizeof(header) + i * kICCTagTableEntrySize;
      writeIccBE32(entry, tags[i].sig);
      writeIccBE32(entry + 4, static_cast<uint32_t>(tag_offset));
      writeIccBE32(entry + 8, static_cast<uint32_t>(tags[i].length));

      uint8_t* tag_dst = dst + tag_offset;
      switch (tags[i].kind) {
        case TagKind::kDesc:
          writeTextTagBytes(tag_dst, desc_text, desc_text_len, tags[i].length);
          break;
        case TagKind::kRxyz:
          writeXyzTagBytes(tag_dst, toXYZD50.vals[0][0], toXYZD50.vals[1][0], toXYZD50.vals[2][0]);
          break;
        case TagKind::kGxyz:
          writeXyzTagBytes(tag_dst, toXYZD50.vals[0][1], toXYZD50.vals[1][1], toXYZD50.vals[2][1]);
          break;
        case TagKind::kBxyz:
          writeXyzTagBytes(tag_dst, toXYZD50.vals[0][2], toXYZD50.vals[1][2], toXYZD50.vals[2][2]);
          break;
        case TagKind::kWtpt:
          writeXyzTagBytes(tag_dst, kD50_x, kD50_y, kD50_z);
          break;
        case TagKind::kTrc:
          if (tf_raw == UHDR_CT_HLG) {
            writeCurveTableTagBytes(tag_dst, IccHelper::kTrcTableSize, hlg_trc_table.data(),
                                    tags[i].length);
          } else if (tf_raw == UHDR_CT_SRGB) {
            writeParaCurveTagBytes(tag_dst, kSRGB_TransFun);
          } else {
            writeParaCurveTagBytes(tag_dst, kLinear_TransFun);
          }
          break;
        case TagKind::kCicp:
          writeCicpTagBytes(tag_dst, color_primaries, transfer_characteristics);
          break;
        case TagKind::kHagc:
          writeHagcTagBytes(tag_dst, hagc_data, hagc_size, tags[i].length);
          break;
        case TagKind::kA2B0: {
          writeMabOrMbaHeaderAndCurves(tag_dst, kTAG_mABType, /*has_a_curves=*/true,
                                       IccHelper::kNumChannels, kPqGridPoints.data());
          const size_t clut_offset =
              32 + IccHelper::kNumChannels * paraCurveTagSize(kLinear_TransFun);
          const size_t clut_len = clutPaddedSize(IccHelper::kNumChannels, kPqGridPoints.data());
          uint8_t* clut_dst = tag_dst + clut_offset;
          writeClutHeaderBytes(clut_dst, IccHelper::kNumChannels, kPqGridPoints.data());
          uint8_t* grid_dst = clut_dst + 20;
          size_t grid_byte_off = 0;
          for (uint32_t r_index = 0; r_index < IccHelper::kGridSize; ++r_index) {
            for (uint32_t g_index = 0; g_index < IccHelper::kGridSize; ++g_index) {
              for (uint32_t b_index = 0; b_index < IccHelper::kGridSize; ++b_index) {
                float rgb[3] = {
                    r_index / (IccHelper::kGridSize - 1.f),
                    g_index / (IccHelper::kGridSize - 1.f),
                    b_index / (IccHelper::kGridSize - 1.f),
                };
                IccHelper::compute_lut_entry(toXYZD50, rgb);
                float_XYZD50_to_grid16_lab(rgb, grid_dst + grid_byte_off);
                grid_byte_off += 6;
              }
            }
          }
          const size_t unpadded = 20 + grid_byte_off;
          if (clut_len > unpadded) {
            std::memset(clut_dst + unpadded, 0, clut_len - unpadded);
          }
          break;
        }
        case TagKind::kB2A0:
          writeMabOrMbaHeaderAndCurves(tag_dst, kTAG_mBAType, /*has_a_curves=*/false,
                                       IccHelper::kNumChannels, nullptr);
          break;
        case TagKind::kCprt:
          writeTextTagBytes(tag_dst, kCprtText, kCprtTextLen, tags[i].length);
          break;
      }
      tag_offset += tags[i].length;
    }
    return true;
  }

  template <typename AllocateFn>
  static bool injectHagc(const void* icc_data, size_t icc_size, const void* hagc_data,
                         size_t hagc_size, bool force_raw_output, AllocateFn&& allocate_dst) {
    const uint8_t* profile = nullptr;
    size_t profile_buf_size = 0;
    bool has_jpeg_id = false;
    if (!unwrapIccProfile(icc_data, icc_size, profile, profile_buf_size, has_jpeg_id) ||
        !isValidHagcTagSize(hagc_data, hagc_size)) {
      return false;
    }

    const size_t encoded_size = readIccBE32(profile);
    if (encoded_size < sizeof(ICCHeader) || encoded_size > profile_buf_size) {
      return false;
    }
    if (readIccBE32(profile + offsetof(ICCHeader, signature)) != kACSP_Signature) {
      return false;
    }
    const uint32_t orig_version = readIccBE32(profile + offsetof(ICCHeader, version));
    if ((orig_version >> 24) > 4u) {
      return false;
    }
    const uint32_t pcs = readIccBE32(profile + offsetof(ICCHeader, pcs));
    if (pcs != Signature_XYZ && pcs != Signature_Lab) {
      return false;
    }

    const size_t tag_count = readIccBE32(profile + offsetof(ICCHeader, tag_count));
    const size_t max_tags = (encoded_size - sizeof(ICCHeader)) / kICCTagTableEntrySize;
    if (tag_count == 0 || tag_count > max_tags) {
      return false;
    }

    const size_t old_table_end = sizeof(ICCHeader) + tag_count * kICCTagTableEntrySize;
    struct KeptTag {
      uint32_t sig = 0;
      size_t old_off = 0;
      size_t old_sz = 0;
      size_t new_off = 0;
    };
    struct PlacedSlice {
      size_t old_off = 0;
      size_t old_sz = 0;
      size_t new_off = 0;
    };

    constexpr size_t kInlineTagCap = 32;
    std::array<KeptTag, kInlineTagCap> inline_kept{};
    std::vector<KeptTag> heap_kept;
    KeptTag* kept_ptr = inline_kept.data();
    if (tag_count > kInlineTagCap) {
      heap_kept.resize(tag_count);
      kept_ptr = heap_kept.data();
    }

    size_t kept_count = 0;
    for (size_t i = 0; i < tag_count; ++i) {
      const uint8_t* entry = profile + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      const uint32_t sig = readIccBE32(entry);
      const size_t off = readIccBE32(entry + 4);
      const size_t sz = readIccBE32(entry + 8);
      if (sz < 4 || off < old_table_end || off > encoded_size || sz > encoded_size - off) {
        return false;
      }
      if (sig == kTAG_HAGC) {
        continue;
      }
      kept_ptr[kept_count++] = {sig, off, sz, 0};
    }
    if (kept_count == 0) {
      return false;
    }

    std::array<PlacedSlice, kInlineTagCap> inline_slices{};
    std::vector<PlacedSlice> heap_slices;
    PlacedSlice* slices_ptr = inline_slices.data();
    if (kept_count > kInlineTagCap) {
      heap_slices.resize(kept_count);
      slices_ptr = heap_slices.data();
    }
    size_t slice_count = 0;

    const size_t new_tag_count = kept_count + 1;
    const size_t new_table_end = sizeof(ICCHeader) + new_tag_count * kICCTagTableEntrySize;
    size_t current_off = new_table_end;

    for (size_t i = 0; i < kept_count; ++i) {
      KeptTag& tag = kept_ptr[i];
      bool reused = false;
      for (size_t s = 0; s < slice_count; ++s) {
        if (slices_ptr[s].old_off == tag.old_off && slices_ptr[s].old_sz == tag.old_sz) {
          tag.new_off = slices_ptr[s].new_off;
          reused = true;
          break;
        }
      }
      if (!reused) {
        tag.new_off = current_off;
        slices_ptr[slice_count++] = {tag.old_off, tag.old_sz, current_off};
        const size_t padded_sz = ALIGNM(tag.old_sz, 4);
        if (padded_sz > (std::numeric_limits<uint32_t>::max)() - current_off) {
          return false;
        }
        current_off += padded_sz;
      }
    }

    const size_t hagc_tag_len = ALIGNM(kHagcTagHeaderSize + hagc_size, 4);
    if (hagc_tag_len > (std::numeric_limits<uint32_t>::max)() - current_off) {
      return false;
    }
    const size_t hagc_new_off = current_off;
    current_off += hagc_tag_len;
    const size_t new_profile_size = current_off;

    const bool emit_jpeg_id = !force_raw_output && has_jpeg_id;
    const size_t prefix_len = emit_jpeg_id ? kICCIdentifierSize : 0;
    if (new_profile_size > (std::numeric_limits<size_t>::max)() - prefix_len) {
      return false;
    }
    uint8_t* dst = allocate_dst(prefix_len + new_profile_size);
    if (dst == nullptr) {
      return false;
    }

    if (emit_jpeg_id) {
      std::memcpy(dst, kICCIdentifier, sizeof(kICCIdentifier));
      dst[12] = 1;
      dst[13] = 1;
      dst += kICCIdentifierSize;
    }

    // Copy 128-byte header + 4-byte tag_count, then update size, version (>= 4.4),
    // clear any stale MD5 Profile ID checksum, and write updated tag_count.
    std::memcpy(dst, profile, sizeof(ICCHeader));
    writeIccBE32(dst + offsetof(ICCHeader, size), static_cast<uint32_t>(new_profile_size));
    if (orig_version < 0x04400000u) {
      writeIccBE32(dst + offsetof(ICCHeader, version), 0x04400000u);
    }
    std::memset(dst + offsetof(ICCHeader, profile_id), 0, sizeof(ICCHeader::profile_id));
    writeIccBE32(dst + offsetof(ICCHeader, tag_count), static_cast<uint32_t>(new_tag_count));

    for (size_t i = 0; i < kept_count; ++i) {
      uint8_t* entry = dst + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
      writeIccBE32(entry, kept_ptr[i].sig);
      writeIccBE32(entry + 4, static_cast<uint32_t>(kept_ptr[i].new_off));
      writeIccBE32(entry + 8, static_cast<uint32_t>(kept_ptr[i].old_sz));
    }
    {
      uint8_t* hagc_entry = dst + sizeof(ICCHeader) + kept_count * kICCTagTableEntrySize;
      writeIccBE32(hagc_entry, kTAG_HAGC);
      writeIccBE32(hagc_entry + 4, static_cast<uint32_t>(hagc_new_off));
      writeIccBE32(hagc_entry + 8, static_cast<uint32_t>(hagc_tag_len));
    }

    for (size_t s = 0; s < slice_count; ++s) {
      const PlacedSlice& slice = slices_ptr[s];
      std::memcpy(dst + slice.new_off, profile + slice.old_off, slice.old_sz);
      const size_t padded_sz = ALIGNM(slice.old_sz, 4);
      if (padded_sz > slice.old_sz) {
        std::memset(dst + slice.new_off + slice.old_sz, 0, padded_sz - slice.old_sz);
      }
    }
    writeHagcTagBytes(dst + hagc_new_off, hagc_data, hagc_size, hagc_tag_len);
    return true;
  }
};

std::shared_ptr<DataStruct> IccHelper::writeIccProfile(uhdr_color_transfer_t tf,
                                                       uhdr_color_gamut_t gamut,
                                                       const void* hagc_data, size_t hagc_size) {
  std::shared_ptr<DataStruct> out;
  if (!Serializer::serializeProfile(tf, gamut, hagc_data, hagc_size,
                                    /*include_jpeg_identifier=*/true,
                                    [&out](size_t total_size) -> uint8_t* {
                                      out = std::make_shared<DataStruct>(total_size);
                                      return static_cast<uint8_t*>(out->getData());
                                    })) {
    return nullptr;
  }
  return out;
}

std::shared_ptr<DataStruct> IccHelper::writeRawIccProfile(uhdr_color_transfer_t tf,
                                                          uhdr_color_gamut_t gamut,
                                                          const void* hagc_data, size_t hagc_size) {
  std::shared_ptr<DataStruct> out;
  if (!Serializer::serializeProfile(tf, gamut, hagc_data, hagc_size,
                                    /*include_jpeg_identifier=*/false,
                                    [&out](size_t total_size) -> uint8_t* {
                                      out = std::make_shared<DataStruct>(total_size);
                                      return static_cast<uint8_t*>(out->getData());
                                    })) {
    return nullptr;
  }
  return out;
}

bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix, const uint8_t* red_tag,
                                  const uint8_t* green_tag, const uint8_t* blue_tag) {
  const float tolerance = 0.001f;
  Fixed r_x_fixed = static_cast<Fixed>(readIccBE32(red_tag + 8));
  Fixed r_y_fixed = static_cast<Fixed>(readIccBE32(red_tag + 12));
  Fixed r_z_fixed = static_cast<Fixed>(readIccBE32(red_tag + 16));
  float r_x = FixedToFloat(r_x_fixed);
  float r_y = FixedToFloat(r_y_fixed);
  float r_z = FixedToFloat(r_z_fixed);
  if (fabs(r_x - matrix.vals[0][0]) > tolerance || fabs(r_y - matrix.vals[1][0]) > tolerance ||
      fabs(r_z - matrix.vals[2][0]) > tolerance) {
    return false;
  }

  Fixed g_x_fixed = static_cast<Fixed>(readIccBE32(green_tag + 8));
  Fixed g_y_fixed = static_cast<Fixed>(readIccBE32(green_tag + 12));
  Fixed g_z_fixed = static_cast<Fixed>(readIccBE32(green_tag + 16));
  float g_x = FixedToFloat(g_x_fixed);
  float g_y = FixedToFloat(g_y_fixed);
  float g_z = FixedToFloat(g_z_fixed);
  if (fabs(g_x - matrix.vals[0][1]) > tolerance || fabs(g_y - matrix.vals[1][1]) > tolerance ||
      fabs(g_z - matrix.vals[2][1]) > tolerance) {
    return false;
  }

  Fixed b_x_fixed = static_cast<Fixed>(readIccBE32(blue_tag + 8));
  Fixed b_y_fixed = static_cast<Fixed>(readIccBE32(blue_tag + 12));
  Fixed b_z_fixed = static_cast<Fixed>(readIccBE32(blue_tag + 16));
  float b_x = FixedToFloat(b_x_fixed);
  float b_y = FixedToFloat(b_y_fixed);
  float b_z = FixedToFloat(b_z_fixed);
  if (fabs(b_x - matrix.vals[0][2]) > tolerance || fabs(b_y - matrix.vals[1][2]) > tolerance ||
      fabs(b_z - matrix.vals[2][2]) > tolerance) {
    return false;
  }

  return true;
}

uhdr_color_gamut_t IccHelper::readIccColorGamut(void* icc_data, size_t icc_size) {
  const uint8_t* raw_profile = nullptr;
  size_t profile_size = 0;
  bool has_jpeg_id = false;
  if (!unwrapIccProfile(icc_data, icc_size, raw_profile, profile_size, has_jpeg_id)) {
    return UHDR_CG_UNSPECIFIED;
  }
  if (!has_jpeg_id &&
      readIccBE32(raw_profile + offsetof(ICCHeader, signature)) != kACSP_Signature) {
    return UHDR_CG_UNSPECIFIED;
  }

  const size_t max_tags = (profile_size - sizeof(ICCHeader)) / kICCTagTableEntrySize;
  const size_t tag_count = readIccBE32(raw_profile + offsetof(ICCHeader, tag_count));
  if (tag_count > max_tags) {
    ALOGE("Tag table size exceeds buffer size during icc parsing. tag count %zu, max tags %zu",
          tag_count, max_tags);
    return UHDR_CG_UNSPECIFIED;
  }

  // Use 0 to indicate not found, since offsets are always relative to start
  // of ICC data and therefore a tag offset of zero would never be valid.
  size_t red_primary_offset = 0, green_primary_offset = 0, blue_primary_offset = 0;
  size_t red_primary_size = 0, green_primary_size = 0, blue_primary_size = 0;
  size_t cicp_size = 0, cicp_offset = 0;
  for (size_t tag_idx = 0; tag_idx < tag_count; ++tag_idx) {
    const uint8_t* tag_entry = raw_profile + sizeof(ICCHeader) + tag_idx * kICCTagTableEntrySize;
    const uint32_t sig = readIccBE32(tag_entry);
    const size_t off = readIccBE32(tag_entry + 4);
    const size_t sz = readIccBE32(tag_entry + 8);
    if (red_primary_offset == 0 && sig == kTAG_rXYZ) {
      red_primary_offset = off;
      red_primary_size = sz;
    } else if (green_primary_offset == 0 && sig == kTAG_gXYZ) {
      green_primary_offset = off;
      green_primary_size = sz;
    } else if (blue_primary_offset == 0 && sig == kTAG_bXYZ) {
      blue_primary_offset = off;
      blue_primary_size = sz;
    } else if (cicp_offset == 0 && sig == kTAG_cicp) {
      cicp_offset = off;
      cicp_size = sz;
    }
  }

  if (cicp_offset != 0 && cicp_size == kCicpTagSize && cicp_offset <= profile_size &&
      cicp_size <= profile_size - cicp_offset) {
    const uint8_t* cicp = raw_profile + cicp_offset;
    uint8_t primaries = cicp[8];
    uhdr_color_gamut_t gamut = UHDR_CG_UNSPECIFIED;
    if (primaries == kCICPPrimariesSRGB) {
      gamut = UHDR_CG_BT_709;
    } else if (primaries == kCICPPrimariesP3) {
      gamut = UHDR_CG_DISPLAY_P3;
    } else if (primaries == kCICPPrimariesRec2020) {
      gamut = UHDR_CG_BT_2100;
    }
    if (gamut != UHDR_CG_UNSPECIFIED) {
      return gamut;
    }
  }

  if (red_primary_offset == 0 || red_primary_size != kColorantTagSize ||
      red_primary_offset > profile_size || red_primary_size > profile_size - red_primary_offset ||
      green_primary_offset == 0 || green_primary_size != kColorantTagSize ||
      green_primary_offset > profile_size ||
      green_primary_size > profile_size - green_primary_offset || blue_primary_offset == 0 ||
      blue_primary_size != kColorantTagSize || blue_primary_offset > profile_size ||
      blue_primary_size > profile_size - blue_primary_offset) {
    return UHDR_CG_UNSPECIFIED;
  }

  const uint8_t* red_tag = raw_profile + red_primary_offset;
  const uint8_t* green_tag = raw_profile + green_primary_offset;
  const uint8_t* blue_tag = raw_profile + blue_primary_offset;

  // Serialize tags as we do on encode and compare what we find to that to
  // determine the gamut (since we don't have a need yet for full deserialize).
  if (tagsEqualToMatrix(kSRGB, red_tag, green_tag, blue_tag)) {
    return UHDR_CG_BT_709;
  }
  if (tagsEqualToMatrix(kDisplayP3, red_tag, green_tag, blue_tag)) {
    return UHDR_CG_DISPLAY_P3;
  }
  if (tagsEqualToMatrix(kRec2020, red_tag, green_tag, blue_tag)) {
    return UHDR_CG_BT_2100;
  }
  // Didn't find a match to one of the profiles we write; indicate the gamut
  // is unspecified since we don't understand it.
  return UHDR_CG_UNSPECIFIED;
}

std::shared_ptr<DataStruct> IccHelper::injectHagcIntoIccProfile(const void* icc_data,
                                                                size_t icc_size,
                                                                const void* hagc_data,
                                                                size_t hagc_size) {
  std::shared_ptr<DataStruct> out;
  if (!Serializer::injectHagc(icc_data, icc_size, hagc_data, hagc_size,
                              /*force_raw_output=*/false, [&out](size_t total_size) -> uint8_t* {
                                out = std::make_shared<DataStruct>(total_size);
                                return static_cast<uint8_t*>(out->getData());
                              })) {
    return nullptr;
  }
  return out;
}

bool detail::writeRawIccProfile(uhdr_color_transfer_t tf, uhdr_color_gamut_t gamut,
                                const void* hagc_data, size_t hagc_size,
                                std::vector<uint8_t>& out_raw_icc) {
  const bool aliases = bufferAliasesVector(out_raw_icc, hagc_data);
  std::vector<uint8_t> scratch;
  if (!IccHelper::Serializer::serializeProfile(
          tf, gamut, hagc_data, hagc_size, /*include_jpeg_identifier=*/false,
          [&](size_t total_size) -> uint8_t* {
            std::vector<uint8_t>& target = aliases ? scratch : out_raw_icc;
            target.resize(total_size);
            return target.data();
          })) {
    return false;
  }
  if (aliases) {
    out_raw_icc = std::move(scratch);
  }
  return true;
}

bool detail::injectHagcIntoRawIccProfile(const void* base_icc_data, size_t base_icc_size,
                                         const void* hagc_data, size_t hagc_size,
                                         std::vector<uint8_t>& out_raw_icc) {
  const bool aliases = bufferAliasesVector(out_raw_icc, base_icc_data) ||
                       bufferAliasesVector(out_raw_icc, hagc_data);
  std::vector<uint8_t> scratch;
  if (!IccHelper::Serializer::injectHagc(
          base_icc_data, base_icc_size, hagc_data, hagc_size,
          /*force_raw_output=*/true, [&](size_t total_size) -> uint8_t* {
            std::vector<uint8_t>& target = aliases ? scratch : out_raw_icc;
            target.resize(total_size);
            return target.data();
          })) {
    return false;
  }
  if (aliases) {
    out_raw_icc = std::move(scratch);
  }
  return true;
}

bool IccHelper::readIccHagc(const void* icc_data, size_t icc_size, std::vector<uint8_t>& out_hagc) {
  out_hagc.clear();
  const uint8_t* profile = nullptr;
  size_t profile_buf_size = 0;
  bool has_jpeg_id = false;
  if (!unwrapIccProfile(icc_data, icc_size, profile, profile_buf_size, has_jpeg_id)) {
    return false;
  }

  const size_t encoded_size = readIccBE32(profile);
  if (encoded_size < sizeof(ICCHeader) || encoded_size > profile_buf_size) {
    return false;
  }
  if (readIccBE32(profile + offsetof(ICCHeader, signature)) != kACSP_Signature) {
    return false;
  }

  const size_t tag_count = readIccBE32(profile + offsetof(ICCHeader, tag_count));
  const size_t max_tags = (encoded_size - sizeof(ICCHeader)) / kICCTagTableEntrySize;
  if (tag_count > max_tags) {
    return false;
  }

  const size_t table_end = sizeof(ICCHeader) + tag_count * kICCTagTableEntrySize;
  const uint8_t* hagc_payload = nullptr;
  size_t hagc_payload_sz = 0;
  for (size_t i = 0; i < tag_count; ++i) {
    const uint8_t* entry = profile + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    const uint32_t sig = readIccBE32(entry);
    const size_t tag_off = readIccBE32(entry + 4);
    const size_t tag_sz = readIccBE32(entry + 8);
    if (tag_off < table_end || tag_off > encoded_size || tag_sz > encoded_size - tag_off) {
      return false;
    }
    if (sig != kTAG_HAGC) {
      continue;
    }
    if (hagc_payload != nullptr || tag_sz < kHagcTagHeaderSize) {
      return false;
    }
    const uint8_t* tag_ptr = profile + tag_off;
    const uint32_t tag_type = readIccBE32(tag_ptr);
    const uint32_t reserved = readIccBE32(tag_ptr + 4);
    const size_t payload_sz = readIccBE32(tag_ptr + 8);
    if (tag_type != kTAG_HAGCType || reserved != 0 || payload_sz == 0 ||
        payload_sz > tag_sz - kHagcTagHeaderSize) {
      return false;
    }
    hagc_payload = tag_ptr + kHagcTagHeaderSize;
    hagc_payload_sz = payload_sz;
  }
  if (hagc_payload == nullptr) {
    return false;
  }
  out_hagc.assign(hagc_payload, hagc_payload + hagc_payload_sz);
  return true;
}

uhdr_color_transfer_t readIccColorTransfer(const void* icc_data, size_t icc_size) {
  const uint8_t* profile = nullptr;
  size_t profile_buf_size = 0;
  bool has_jpeg_id = false;
  if (!unwrapIccProfile(icc_data, icc_size, profile, profile_buf_size, has_jpeg_id)) {
    return UHDR_CT_UNSPECIFIED;
  }

  const size_t encoded_size = readIccBE32(profile);
  if (encoded_size < sizeof(ICCHeader) || encoded_size > profile_buf_size ||
      readIccBE32(profile + offsetof(ICCHeader, signature)) != kACSP_Signature) {
    return UHDR_CT_UNSPECIFIED;
  }

  const size_t tag_count = readIccBE32(profile + offsetof(ICCHeader, tag_count));
  const size_t max_tags = (encoded_size - sizeof(ICCHeader)) / kICCTagTableEntrySize;
  if (tag_count > max_tags) {
    return UHDR_CT_UNSPECIFIED;
  }

  const size_t table_end = sizeof(ICCHeader) + tag_count * kICCTagTableEntrySize;
  for (size_t i = 0; i < tag_count; ++i) {
    const uint8_t* entry = profile + sizeof(ICCHeader) + i * kICCTagTableEntrySize;
    if (readIccBE32(entry) != kTAG_cicp) {
      continue;
    }
    const size_t tag_off = readIccBE32(entry + 4);
    const size_t tag_sz = readIccBE32(entry + 8);
    if (tag_off < table_end || tag_off > encoded_size || tag_sz != kCicpTagSize ||
        tag_sz > encoded_size - tag_off) {
      return UHDR_CT_UNSPECIFIED;
    }
    const uint8_t* cicp = profile + tag_off;
    if (readIccBE32(cicp) != kTAG_cicp || readIccBE32(cicp + 4) != 0) {
      return UHDR_CT_UNSPECIFIED;
    }
    switch (cicp[9]) {
      case kCICPTrfnSRGB:
      case 6:
      case 13:
        return UHDR_CT_SRGB;
      case kCICPTrfnLinear:
        return UHDR_CT_LINEAR;
      case kCICPTrfnPQ:
        return UHDR_CT_PQ;
      case kCICPTrfnHLG:
        return UHDR_CT_HLG;
      default:
        return UHDR_CT_UNSPECIFIED;
    }
  }
  return UHDR_CT_UNSPECIFIED;
}

}  // namespace ultrahdr
