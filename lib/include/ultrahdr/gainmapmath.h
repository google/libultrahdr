/*
 * Copyright 2022 The Android Open Source Project
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

#ifndef ULTRAHDR_GAINMAPMATH_H
#define ULTRAHDR_GAINMAPMATH_H

#include <array>
#include <cmath>
#include <cstring>

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/ultrahdr.h"
#include "ultrahdr/jpegr.h"

#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
#include <arm_neon.h>
#endif

#define CLIP3(x, min, max) ((x) < (min)) ? (min) : ((x) > (max)) ? (max) : (x)

namespace ultrahdr {

////////////////////////////////////////////////////////////////////////////////
// Framework

// This aligns with the suggested default reference diffuse white from
// ISO/TS 22028-5
const float kSdrWhiteNits = 203.0f;
const float kHlgMaxNits = 1000.0f;
const float kPqMaxNits = 10000.0f;

static const float kMaxPixelFloat = 1.0f;

// Describes the tone-mapping operation & gain-map encoding parameters.
const float kHlgHeadroom = 1000.0f / 203.0f;

struct Color {
  union {
    struct {
      float r;
      float g;
      float b;
    };
    struct {
      float y;
      float u;
      float v;
    };
  };
};

typedef Color (*ColorTransformFn)(Color);
typedef float (*ColorCalculationFn)(Color);

static inline float clampPixelFloat(float value) {
  return (value < 0.0f) ? 0.0f : (value > kMaxPixelFloat) ? kMaxPixelFloat : value;
}
static inline Color clampPixelFloat(Color e) {
  return {{{clampPixelFloat(e.r), clampPixelFloat(e.g), clampPixelFloat(e.b)}}};
}

// A transfer function mapping encoded values to linear values,
// represented by this 7-parameter piecewise function:
//
//   linear = sign(encoded) *  (c*|encoded| + f)       , 0 <= |encoded| < d
//          = sign(encoded) * ((a*|encoded| + b)^g + e), d <= |encoded|
//
// (A simple gamma transfer function sets g to gamma and a to 1.)
typedef struct TransferFunction {
  float g, a, b, c, d, e, f;
} TransferFunction;

static constexpr TransferFunction kSRGB_TransFun = {
    2.4f, (float)(1 / 1.055), (float)(0.055 / 1.055), (float)(1 / 12.92), 0.04045f, 0.0f, 0.0f};

static constexpr TransferFunction kLinear_TransFun = {1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};

inline Color operator+=(Color& lhs, const Color& rhs) {
  lhs.r += rhs.r;
  lhs.g += rhs.g;
  lhs.b += rhs.b;
  return lhs;
}
inline Color operator-=(Color& lhs, const Color& rhs) {
  lhs.r -= rhs.r;
  lhs.g -= rhs.g;
  lhs.b -= rhs.b;
  return lhs;
}

inline Color operator+(const Color& lhs, const Color& rhs) {
  Color temp = lhs;
  return temp += rhs;
}
inline Color operator-(const Color& lhs, const Color& rhs) {
  Color temp = lhs;
  return temp -= rhs;
}

inline Color operator+=(Color& lhs, const float rhs) {
  lhs.r += rhs;
  lhs.g += rhs;
  lhs.b += rhs;
  return lhs;
}
inline Color operator-=(Color& lhs, const float rhs) {
  lhs.r -= rhs;
  lhs.g -= rhs;
  lhs.b -= rhs;
  return lhs;
}
inline Color operator*=(Color& lhs, const float rhs) {
  lhs.r *= rhs;
  lhs.g *= rhs;
  lhs.b *= rhs;
  return lhs;
}
inline Color operator/=(Color& lhs, const float rhs) {
  lhs.r /= rhs;
  lhs.g /= rhs;
  lhs.b /= rhs;
  return lhs;
}

inline Color operator+(const Color& lhs, const float rhs) {
  Color temp = lhs;
  return temp += rhs;
}
inline Color operator-(const Color& lhs, const float rhs) {
  Color temp = lhs;
  return temp -= rhs;
}
inline Color operator*(const Color& lhs, const float rhs) {
  Color temp = lhs;
  return temp *= rhs;
}
inline Color operator/(const Color& lhs, const float rhs) {
  Color temp = lhs;
  return temp /= rhs;
}

union FloatUIntUnion {
  uint32_t fUInt;
  float fFloat;
};

inline uint16_t floatToHalf(float f) {
  FloatUIntUnion floatUnion;
  floatUnion.fFloat = f;
  // round-to-nearest-even: add last bit after truncated mantissa
  const uint32_t b = floatUnion.fUInt + 0x00001000;

  const int32_t e = (b & 0x7F800000) >> 23;  // exponent
  const uint32_t m = b & 0x007FFFFF;         // mantissa

  // sign : normalized : denormalized : saturate
  return (b & 0x80000000) >> 16 | (e > 112) * ((((e - 112) << 10) & 0x7C00) | m >> 13) |
         ((e < 113) & (e > 101)) * ((((0x007FF000 + m) >> (125 - e)) + 1) >> 1) |
         (e > 143) * 0x7FFF;
}

constexpr int32_t kGainFactorPrecision = 10;
constexpr int32_t kGainFactorNumEntries = 1 << kGainFactorPrecision;
struct GainLUT {
  GainLUT(ultrahdr_metadata_ptr metadata) {
    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
      float logBoost = log2(metadata->minContentBoost) * (1.0f - value) +
                       log2(metadata->maxContentBoost) * value;
      mGainTable[idx] = exp2(logBoost);
    }
  }

  GainLUT(ultrahdr_metadata_ptr metadata, float displayBoost) {
    float boostFactor = displayBoost > 0 ? displayBoost / metadata->maxContentBoost : 1.0f;
    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
      float logBoost = log2(metadata->minContentBoost) * (1.0f - value) +
                       log2(metadata->maxContentBoost) * value;
      mGainTable[idx] = exp2(logBoost * boostFactor);
    }
  }

  ~GainLUT() {}

  float getGainFactor(float gain) {
    int32_t idx = static_cast<int32_t>(gain * (kGainFactorNumEntries - 1) + 0.5);
    // TODO() : Remove once conversion modules have appropriate clamping in place
    idx = CLIP3(idx, 0, kGainFactorNumEntries - 1);
    return mGainTable[idx];
  }

 private:
  float mGainTable[kGainFactorNumEntries];
};

struct ShepardsIDW {
  ShepardsIDW(int mapScaleFactor) : mMapScaleFactor{mapScaleFactor} {
    const int size = mMapScaleFactor * mMapScaleFactor * 4;
    mWeights = new float[size];
    mWeightsNR = new float[size];
    mWeightsNB = new float[size];
    mWeightsC = new float[size];
    fillShepardsIDW(mWeights, 1, 1);
    fillShepardsIDW(mWeightsNR, 0, 1);
    fillShepardsIDW(mWeightsNB, 1, 0);
    fillShepardsIDW(mWeightsC, 0, 0);
  }
  ~ShepardsIDW() {
    delete[] mWeights;
    delete[] mWeightsNR;
    delete[] mWeightsNB;
    delete[] mWeightsC;
  }

  int mMapScaleFactor;
  // Image :-
  // p00 p01 p02 p03 p04 p05 p06 p07
  // p10 p11 p12 p13 p14 p15 p16 p17
  // p20 p21 p22 p23 p24 p25 p26 p27
  // p30 p31 p32 p33 p34 p35 p36 p37
  // p40 p41 p42 p43 p44 p45 p46 p47
  // p50 p51 p52 p53 p54 p55 p56 p57
  // p60 p61 p62 p63 p64 p65 p66 p67
  // p70 p71 p72 p73 p74 p75 p76 p77

  // Gain Map (for 4 scale factor) :-
  // m00 p01
  // m10 m11

  // Gain sample of curr 4x4, right 4x4, bottom 4x4, bottom right 4x4 are used during
  // reconstruction. hence table weight size is 4.
  float* mWeights;
  // TODO: check if its ok to mWeights at places
  float* mWeightsNR;  // no right
  float* mWeightsNB;  // no bottom
  float* mWeightsC;   // no right & bottom

  float euclideanDistance(float x1, float x2, float y1, float y2);
  void fillShepardsIDW(float* weights, int incR, int incB);
};

////////////////////////////////////////////////////////////////////////////////
// sRGB transformations
// NOTE: sRGB has the same color primaries as BT.709, but different transfer
// function. For this reason, all sRGB transformations here apply to BT.709,
// except for those concerning transfer functions.

/*
 * Calculate the luminance of a linear RGB sRGB pixel, according to
 * IEC 61966-2-1/Amd 1:2003.
 *
 * [0.0, 1.0] range in and out.
 */
float srgbLuminance(Color e);

/*
 * Convert from OETF'd srgb RGB to YUV, according to ITU-R BT.709-6.
 *
 * BT.709 YUV<->RGB matrix is used to match expectations for DataSpace.
 */
Color srgbRgbToYuv(Color e_gamma);

/*
 * Convert from OETF'd srgb YUV to RGB, according to ITU-R BT.709-6.
 *
 * BT.709 YUV<->RGB matrix is used to match expectations for DataSpace.
 */
Color srgbYuvToRgb(Color e_gamma);

/*
 * Convert from srgb to linear, according to IEC 61966-2-1/Amd 1:2003.
 *
 * [0.0, 1.0] range in and out.
 */
float srgbInvOetf(float e_gamma);
Color srgbInvOetf(Color e_gamma);
float srgbInvOetfLUT(float e_gamma);
Color srgbInvOetfLUT(Color e_gamma);

/*
 * Convert from linear to srgb, according to IEC 61966-2-1/Amd 1:2003.
 *
 * [0.0, 1.0] range in and out.
 */
float srgbOetf(float e);
Color srgbOetf(Color e);

constexpr int32_t kSrgbInvOETFPrecision = 10;
constexpr int32_t kSrgbInvOETFNumEntries = 1 << kSrgbInvOETFPrecision;

////////////////////////////////////////////////////////////////////////////////
// Display-P3 transformations

/*
 * Calculated the luminance of a linear RGB P3 pixel, according to SMPTE EG 432-1.
 *
 * [0.0, 1.0] range in and out.
 */
float p3Luminance(Color e);

/*
 * Convert from OETF'd P3 RGB to YUV, according to ITU-R BT.601-7.
 *
 * BT.601 YUV<->RGB matrix is used to match expectations for DataSpace.
 */
Color p3RgbToYuv(Color e_gamma);

/*
 * Convert from OETF'd P3 YUV to RGB, according to ITU-R BT.601-7.
 *
 * BT.601 YUV<->RGB matrix is used to match expectations for DataSpace.
 */
Color p3YuvToRgb(Color e_gamma);

////////////////////////////////////////////////////////////////////////////////
// BT.2100 transformations - according to ITU-R BT.2100-2

/*
 * Calculate the luminance of a linear RGB BT.2100 pixel.
 *
 * [0.0, 1.0] range in and out.
 */
float bt2100Luminance(Color e);

/*
 * Convert from OETF'd BT.2100 RGB to YUV, according to ITU-R BT.2100-2.
 *
 * BT.2100 YUV<->RGB matrix is used to match expectations for DataSpace.
 */
Color bt2100RgbToYuv(Color e_gamma);

/*
 * Convert from OETF'd BT.2100 YUV to RGB, according to ITU-R BT.2100-2.
 *
 * BT.2100 YUV<->RGB matrix is used to match expectations for DataSpace.
 */
Color bt2100YuvToRgb(Color e_gamma);

/*
 * Convert from scene luminance to HLG.
 *
 * [0.0, 1.0] range in and out.
 */
float hlgOetf(float e);
Color hlgOetf(Color e);
float hlgOetfLUT(float e);
Color hlgOetfLUT(Color e);

constexpr int32_t kHlgOETFPrecision = 16;
constexpr int32_t kHlgOETFNumEntries = 1 << kHlgOETFPrecision;

/*
 * Convert from HLG to scene luminance.
 *
 * [0.0, 1.0] range in and out.
 */
float hlgInvOetf(float e_gamma);
Color hlgInvOetf(Color e_gamma);
float hlgInvOetfLUT(float e_gamma);
Color hlgInvOetfLUT(Color e_gamma);

constexpr int32_t kHlgInvOETFPrecision = 12;
constexpr int32_t kHlgInvOETFNumEntries = 1 << kHlgInvOETFPrecision;

/*
 * Convert from scene luminance to PQ.
 *
 * [0.0, 1.0] range in and out.
 */
float pqOetf(float e);
Color pqOetf(Color e);
float pqOetfLUT(float e);
Color pqOetfLUT(Color e);

constexpr int32_t kPqOETFPrecision = 16;
constexpr int32_t kPqOETFNumEntries = 1 << kPqOETFPrecision;

/*
 * Convert from PQ to scene luminance in nits.
 *
 * [0.0, 1.0] range in and out.
 */
float pqInvOetf(float e_gamma);
Color pqInvOetf(Color e_gamma);
float pqInvOetfLUT(float e_gamma);
Color pqInvOetfLUT(Color e_gamma);

constexpr int32_t kPqInvOETFPrecision = 12;
constexpr int32_t kPqInvOETFNumEntries = 1 << kPqInvOETFPrecision;

////////////////////////////////////////////////////////////////////////////////
// Color space conversions

/*
 * Convert between color spaces with linear RGB data, according to ITU-R BT.2407 and EG 432-1.
 *
 * All conversions are derived from multiplying the matrix for XYZ to output RGB color gamut by the
 * matrix for input RGB color gamut to XYZ. The matrix for converting from XYZ to an RGB gamut is
 * always the inverse of the RGB gamut to XYZ matrix.
 */
Color bt709ToP3(Color e);
Color bt709ToBt2100(Color e);
Color p3ToBt709(Color e);
Color p3ToBt2100(Color e);
Color bt2100ToBt709(Color e);
Color bt2100ToP3(Color e);

/*
 * Identity conversion.
 */
inline Color identityConversion(Color e) { return e; }

/*
 * Get the conversion to apply to the HDR image for gain map generation
 */
ColorTransformFn getHdrConversionFn(ultrahdr_color_gamut sdr_gamut, ultrahdr_color_gamut hdr_gamut);

/*
 * Convert between YUV encodings, according to ITU-R BT.709-6, ITU-R BT.601-7, and ITU-R BT.2100-2.
 *
 * Bt.709 and Bt.2100 have well-defined YUV encodings; Display-P3's is less well defined, but is
 * treated as Bt.601 by DataSpace, hence we do the same.
 */
extern const std::array<float, 9> kYuvBt709ToBt601;
extern const std::array<float, 9> kYuvBt709ToBt2100;
extern const std::array<float, 9> kYuvBt601ToBt709;
extern const std::array<float, 9> kYuvBt601ToBt2100;
extern const std::array<float, 9> kYuvBt2100ToBt709;
extern const std::array<float, 9> kYuvBt2100ToBt601;

Color yuvColorGamutConversion(Color e_gamma, const std::array<float, 9>& coeffs);

#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))

extern const int16_t kYuv709To601_coeffs_neon[8];
extern const int16_t kYuv709To2100_coeffs_neon[8];
extern const int16_t kYuv601To709_coeffs_neon[8];
extern const int16_t kYuv601To2100_coeffs_neon[8];
extern const int16_t kYuv2100To709_coeffs_neon[8];
extern const int16_t kYuv2100To601_coeffs_neon[8];

/*
 * The Y values are provided at half the width of U & V values to allow use of the widening
 * arithmetic instructions.
 */
int16x8x3_t yuvConversion_neon(uint8x8_t y, int16x8_t u, int16x8_t v, int16x8_t coeffs);

void transformYuv420_neon(jr_uncompressed_ptr image, const int16_t* coeffs_ptr);

status_t convertYuv_neon(jr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
                         ultrahdr_color_gamut dst_encoding);
#endif

/*
 * Performs a color gamut transformation on an entire YUV420 image.
 *
 * Apply the transformation by determining transformed YUV for each of the 4 Y + 1 UV; each Y gets
 * this result, and UV gets the averaged result.
 *
 * The chroma channels should be less than or equal to half the image's width and height
 * respectively, since input is 4:2:0 subsampled.
 */
void transformYuv420(jr_uncompressed_ptr image, const std::array<float, 9>& coeffs);

////////////////////////////////////////////////////////////////////////////////
// Gain map calculations

/*
 * Calculate the 8-bit unsigned integer gain value for the given SDR and HDR
 * luminances in linear space, and the hdr ratio to encode against.
 *
 * Note: since this library always uses gamma of 1.0, offsetSdr of 0.0, and
 * offsetHdr of 0.0, this function doesn't handle different metadata values for
 * these fields.
 */
uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata);
uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata,
                   float log2MinContentBoost, float log2MaxContentBoost);

/*
 * Calculates the linear luminance in nits after applying the given gain
 * value, with the given hdr ratio, to the given sdr input in the range [0, 1].
 *
 * Note: similar to encodeGain(), this function only supports gamma 1.0,
 * offsetSdr 0.0, offsetHdr 0.0, hdrCapacityMin 1.0, and hdrCapacityMax equal to
 * gainMapMax, as this library encodes.
 */
Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata);
Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata, float displayBoost);
Color applyGainLUT(Color e, float gain, GainLUT& gainLUT);

/*
 * Helper for sampling from YUV 420 images.
 */
Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y);

/*
 * Helper for sampling from P010 images.
 *
 * Expect narrow-range image data for P010.
 */
Color getP010Pixel(jr_uncompressed_ptr image, size_t x, size_t y);

/*
 * Sample the image at the provided location, with a weighting based on nearby
 * pixels and the map scale factor.
 */
Color sampleYuv420(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);

/*
 * Sample the image at the provided location, with a weighting based on nearby
 * pixels and the map scale factor.
 *
 * Expect narrow-range image data for P010.
 */
Color sampleP010(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);

/*
 * Sample the gain value for the map from a given x,y coordinate on a scale
 * that is map scale factor larger than the map size.
 */
float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y);
float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
                ShepardsIDW& weightTables);

/*
 * Convert from Color to RGBA1010102.
 *
 * Alpha always set to 1.0.
 */
uint32_t colorToRgba1010102(Color e_gamma);

/*
 * Convert from Color to F16.
 *
 * Alpha always set to 1.0.
 */
uint64_t colorToRgbaF16(Color e_gamma);

/*
 * Helper for preparing encoder raw inputs for encoding
 */
std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_t* src);

}  // namespace ultrahdr

#endif  // ULTRAHDR_GAINMAPMATH_H
