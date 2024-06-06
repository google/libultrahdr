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

#include <cmath>
#include "ultrahdr/gainmapmath.h"

namespace ultrahdr {

static const std::vector<float> kPqOETF = [] {
  std::vector<float> result;
  for (size_t idx = 0; idx < kPqOETFNumEntries; idx++) {
    float value = static_cast<float>(idx) / static_cast<float>(kPqOETFNumEntries - 1);
    result.push_back(pqOetf(value));
  }
  return result;
}();

static const std::vector<float> kPqInvOETF = [] {
  std::vector<float> result;
  for (size_t idx = 0; idx < kPqInvOETFNumEntries; idx++) {
    float value = static_cast<float>(idx) / static_cast<float>(kPqInvOETFNumEntries - 1);
    result.push_back(pqInvOetf(value));
  }
  return result;
}();

static const std::vector<float> kHlgOETF = [] {
  std::vector<float> result;
  for (size_t idx = 0; idx < kHlgOETFNumEntries; idx++) {
    float value = static_cast<float>(idx) / static_cast<float>(kHlgOETFNumEntries - 1);
    result.push_back(hlgOetf(value));
  }
  return result;
}();

static const std::vector<float> kHlgInvOETF = [] {
  std::vector<float> result;
  for (size_t idx = 0; idx < kHlgInvOETFNumEntries; idx++) {
    float value = static_cast<float>(idx) / static_cast<float>(kHlgInvOETFNumEntries - 1);
    result.push_back(hlgInvOetf(value));
  }
  return result;
}();

static const std::vector<float> kSrgbInvOETF = [] {
  std::vector<float> result;
  for (size_t idx = 0; idx < kSrgbInvOETFNumEntries; idx++) {
    float value = static_cast<float>(idx) / static_cast<float>(kSrgbInvOETFNumEntries - 1);
    result.push_back(srgbInvOetf(value));
  }
  return result;
}();

// Use Shepard's method for inverse distance weighting. For more information:
// en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method

float ShepardsIDW::euclideanDistance(float x1, float x2, float y1, float y2) {
  return sqrt(((y2 - y1) * (y2 - y1)) + (x2 - x1) * (x2 - x1));
}

void ShepardsIDW::fillShepardsIDW(float* weights, int incR, int incB) {
  for (int y = 0; y < mMapScaleFactor; y++) {
    for (int x = 0; x < mMapScaleFactor; x++) {
      float pos_x = ((float)x) / mMapScaleFactor;
      float pos_y = ((float)y) / mMapScaleFactor;
      int curr_x = floor(pos_x);
      int curr_y = floor(pos_y);
      int next_x = curr_x + incR;
      int next_y = curr_y + incB;
      float e1_distance = euclideanDistance(pos_x, curr_x, pos_y, curr_y);
      int index = y * mMapScaleFactor * 4 + x * 4;
      if (e1_distance == 0) {
        weights[index++] = 1.f;
        weights[index++] = 0.f;
        weights[index++] = 0.f;
        weights[index++] = 0.f;
      } else {
        float e1_weight = 1.f / e1_distance;

        float e2_distance = euclideanDistance(pos_x, curr_x, pos_y, next_y);
        float e2_weight = 1.f / e2_distance;

        float e3_distance = euclideanDistance(pos_x, next_x, pos_y, curr_y);
        float e3_weight = 1.f / e3_distance;

        float e4_distance = euclideanDistance(pos_x, next_x, pos_y, next_y);
        float e4_weight = 1.f / e4_distance;

        float total_weight = e1_weight + e2_weight + e3_weight + e4_weight;

        weights[index++] = e1_weight / total_weight;
        weights[index++] = e2_weight / total_weight;
        weights[index++] = e3_weight / total_weight;
        weights[index++] = e4_weight / total_weight;
      }
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// sRGB transformations

// See IEC 61966-2-1/Amd 1:2003, Equation F.7.
static const float kSrgbR = 0.2126f, kSrgbG = 0.7152f, kSrgbB = 0.0722f;

float srgbLuminance(Color e) { return kSrgbR * e.r + kSrgbG * e.g + kSrgbB * e.b; }

// See ITU-R BT.709-6, Section 3.
// Uses the same coefficients for deriving luma signal as
// IEC 61966-2-1/Amd 1:2003 states for luminance, so we reuse the luminance
// function above.
static const float kSrgbCb = 1.8556f, kSrgbCr = 1.5748f;

Color srgbRgbToYuv(Color e_gamma) {
  float y_gamma = srgbLuminance(e_gamma);
  return {{{y_gamma, (e_gamma.b - y_gamma) / kSrgbCb, (e_gamma.r - y_gamma) / kSrgbCr}}};
}

// See ITU-R BT.709-6, Section 3.
// Same derivation to BT.2100's YUV->RGB, below. Similar to srgbRgbToYuv, we
// can reuse the luminance coefficients since they are the same.
static const float kSrgbGCb = kSrgbB * kSrgbCb / kSrgbG;
static const float kSrgbGCr = kSrgbR * kSrgbCr / kSrgbG;

Color srgbYuvToRgb(Color e_gamma) {
  return {{{clampPixelFloat(e_gamma.y + kSrgbCr * e_gamma.v),
            clampPixelFloat(e_gamma.y - kSrgbGCb * e_gamma.u - kSrgbGCr * e_gamma.v),
            clampPixelFloat(e_gamma.y + kSrgbCb * e_gamma.u)}}};
}

// See IEC 61966-2-1/Amd 1:2003, Equations F.5 and F.6.
float srgbInvOetf(float e_gamma) {
  if (e_gamma <= 0.04045f) {
    return e_gamma / 12.92f;
  } else {
    return pow((e_gamma + 0.055f) / 1.055f, 2.4);
  }
}

Color srgbInvOetf(Color e_gamma) {
  return {{{srgbInvOetf(e_gamma.r), srgbInvOetf(e_gamma.g), srgbInvOetf(e_gamma.b)}}};
}

// See IEC 61966-2-1, Equations F.5 and F.6.
float srgbInvOetfLUT(float e_gamma) {
  int32_t value = static_cast<int32_t>(e_gamma * (kSrgbInvOETFNumEntries - 1) + 0.5);
  // TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kSrgbInvOETFNumEntries - 1);
  return kSrgbInvOETF[value];
}

Color srgbInvOetfLUT(Color e_gamma) {
  return {{{srgbInvOetfLUT(e_gamma.r), srgbInvOetfLUT(e_gamma.g), srgbInvOetfLUT(e_gamma.b)}}};
}

float srgbOetf(float e) {
  constexpr float kThreshold = 0.00304;
  constexpr float kLowSlope = 12.92;
  constexpr float kHighOffset = 0.055;
  constexpr float kPowerExponent = 1.0 / 2.4;
  if (e < kThreshold) {
    return kLowSlope * e;
  }
  return (1.0 + kHighOffset) * std::pow(e, kPowerExponent) - kHighOffset;
}

Color srgbOetf(Color e) { return {{{srgbOetf(e.r), srgbOetf(e.g), srgbOetf(e.b)}}}; }

////////////////////////////////////////////////////////////////////////////////
// Display-P3 transformations

// See SMPTE EG 432-1, Equation 7-8.
static const float kP3R = 0.20949f, kP3G = 0.72160f, kP3B = 0.06891f;

float p3Luminance(Color e) { return kP3R * e.r + kP3G * e.g + kP3B * e.b; }

// See ITU-R BT.601-7, Sections 2.5.1 and 2.5.2.
// Unfortunately, calculation of luma signal differs from calculation of
// luminance for Display-P3, so we can't reuse p3Luminance here.
static const float kP3YR = 0.299f, kP3YG = 0.587f, kP3YB = 0.114f;
static const float kP3Cb = 1.772f, kP3Cr = 1.402f;

Color p3RgbToYuv(Color e_gamma) {
  float y_gamma = kP3YR * e_gamma.r + kP3YG * e_gamma.g + kP3YB * e_gamma.b;
  return {{{y_gamma, (e_gamma.b - y_gamma) / kP3Cb, (e_gamma.r - y_gamma) / kP3Cr}}};
}

// See ITU-R BT.601-7, Sections 2.5.1 and 2.5.2.
// Same derivation to BT.2100's YUV->RGB, below. Similar to p3RgbToYuv, we must
// use luma signal coefficients rather than the luminance coefficients.
static const float kP3GCb = kP3YB * kP3Cb / kP3YG;
static const float kP3GCr = kP3YR * kP3Cr / kP3YG;

Color p3YuvToRgb(Color e_gamma) {
  return {{{clampPixelFloat(e_gamma.y + kP3Cr * e_gamma.v),
            clampPixelFloat(e_gamma.y - kP3GCb * e_gamma.u - kP3GCr * e_gamma.v),
            clampPixelFloat(e_gamma.y + kP3Cb * e_gamma.u)}}};
}

////////////////////////////////////////////////////////////////////////////////
// BT.2100 transformations - according to ITU-R BT.2100-2

// See ITU-R BT.2100-2, Table 5, HLG Reference OOTF
static const float kBt2100R = 0.2627f, kBt2100G = 0.6780f, kBt2100B = 0.0593f;

float bt2100Luminance(Color e) { return kBt2100R * e.r + kBt2100G * e.g + kBt2100B * e.b; }

// See ITU-R BT.2100-2, Table 6, Derivation of colour difference signals.
// BT.2100 uses the same coefficients for calculating luma signal and luminance,
// so we reuse the luminance function here.
static const float kBt2100Cb = 1.8814f, kBt2100Cr = 1.4746f;

Color bt2100RgbToYuv(Color e_gamma) {
  float y_gamma = bt2100Luminance(e_gamma);
  return {{{y_gamma, (e_gamma.b - y_gamma) / kBt2100Cb, (e_gamma.r - y_gamma) / kBt2100Cr}}};
}

// See ITU-R BT.2100-2, Table 6, Derivation of colour difference signals.
//
// Similar to bt2100RgbToYuv above, we can reuse the luminance coefficients.
//
// Derived by inversing bt2100RgbToYuv. The derivation for R and B are  pretty
// straight forward; we just invert the formulas for U and V above. But deriving
// the formula for G is a bit more complicated:
//
// Start with equation for luminance:
//   Y = kBt2100R * R + kBt2100G * G + kBt2100B * B
// Solve for G:
//   G = (Y - kBt2100R * R - kBt2100B * B) / kBt2100B
// Substitute equations for R and B in terms YUV:
//   G = (Y - kBt2100R * (Y + kBt2100Cr * V) - kBt2100B * (Y + kBt2100Cb * U)) / kBt2100B
// Simplify:
//   G = Y * ((1 - kBt2100R - kBt2100B) / kBt2100G)
//     + U * (kBt2100B * kBt2100Cb / kBt2100G)
//     + V * (kBt2100R * kBt2100Cr / kBt2100G)
//
// We then get the following coeficients for calculating G from YUV:
//
// Coef for Y = (1 - kBt2100R - kBt2100B) / kBt2100G = 1
// Coef for U = kBt2100B * kBt2100Cb / kBt2100G = kBt2100GCb = ~0.1645
// Coef for V = kBt2100R * kBt2100Cr / kBt2100G = kBt2100GCr = ~0.5713

static const float kBt2100GCb = kBt2100B * kBt2100Cb / kBt2100G;
static const float kBt2100GCr = kBt2100R * kBt2100Cr / kBt2100G;

Color bt2100YuvToRgb(Color e_gamma) {
  return {{{clampPixelFloat(e_gamma.y + kBt2100Cr * e_gamma.v),
            clampPixelFloat(e_gamma.y - kBt2100GCb * e_gamma.u - kBt2100GCr * e_gamma.v),
            clampPixelFloat(e_gamma.y + kBt2100Cb * e_gamma.u)}}};
}

// See ITU-R BT.2100-2, Table 5, HLG Reference OETF.
static const float kHlgA = 0.17883277f, kHlgB = 0.28466892f, kHlgC = 0.55991073;

float hlgOetf(float e) {
  if (e <= 1.0f / 12.0f) {
    return sqrt(3.0f * e);
  } else {
    return kHlgA * log(12.0f * e - kHlgB) + kHlgC;
  }
}

Color hlgOetf(Color e) { return {{{hlgOetf(e.r), hlgOetf(e.g), hlgOetf(e.b)}}}; }

float hlgOetfLUT(float e) {
  int32_t value = static_cast<int32_t>(e * (kHlgOETFNumEntries - 1) + 0.5);
  // TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kHlgOETFNumEntries - 1);

  return kHlgOETF[value];
}

Color hlgOetfLUT(Color e) { return {{{hlgOetfLUT(e.r), hlgOetfLUT(e.g), hlgOetfLUT(e.b)}}}; }

// See ITU-R BT.2100-2, Table 5, HLG Reference EOTF.
float hlgInvOetf(float e_gamma) {
  if (e_gamma <= 0.5f) {
    return pow(e_gamma, 2.0f) / 3.0f;
  } else {
    return (exp((e_gamma - kHlgC) / kHlgA) + kHlgB) / 12.0f;
  }
}

Color hlgInvOetf(Color e_gamma) {
  return {{{hlgInvOetf(e_gamma.r), hlgInvOetf(e_gamma.g), hlgInvOetf(e_gamma.b)}}};
}

float hlgInvOetfLUT(float e_gamma) {
  int32_t value = static_cast<int32_t>(e_gamma * (kHlgInvOETFNumEntries - 1) + 0.5);
  // TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kHlgInvOETFNumEntries - 1);

  return kHlgInvOETF[value];
}

Color hlgInvOetfLUT(Color e_gamma) {
  return {{{hlgInvOetfLUT(e_gamma.r), hlgInvOetfLUT(e_gamma.g), hlgInvOetfLUT(e_gamma.b)}}};
}

// See ITU-R BT.2100-2, Table 4, Reference PQ OETF.
static const float kPqM1 = 2610.0f / 16384.0f, kPqM2 = 2523.0f / 4096.0f * 128.0f;
static const float kPqC1 = 3424.0f / 4096.0f, kPqC2 = 2413.0f / 4096.0f * 32.0f,
                   kPqC3 = 2392.0f / 4096.0f * 32.0f;

float pqOetf(float e) {
  if (e <= 0.0f) return 0.0f;
  return pow((kPqC1 + kPqC2 * pow(e, kPqM1)) / (1 + kPqC3 * pow(e, kPqM1)), kPqM2);
}

Color pqOetf(Color e) { return {{{pqOetf(e.r), pqOetf(e.g), pqOetf(e.b)}}}; }

float pqOetfLUT(float e) {
  int32_t value = static_cast<int32_t>(e * (kPqOETFNumEntries - 1) + 0.5);
  // TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kPqOETFNumEntries - 1);

  return kPqOETF[value];
}

Color pqOetfLUT(Color e) { return {{{pqOetfLUT(e.r), pqOetfLUT(e.g), pqOetfLUT(e.b)}}}; }

// Derived from the inverse of the Reference PQ OETF.
static const float kPqInvA = 128.0f, kPqInvB = 107.0f, kPqInvC = 2413.0f, kPqInvD = 2392.0f,
                   kPqInvE = 6.2773946361f, kPqInvF = 0.0126833f;

float pqInvOetf(float e_gamma) {
  // This equation blows up if e_gamma is 0.0, and checking on <= 0.0 doesn't
  // always catch 0.0. So, check on 0.0001, since anything this small will
  // effectively be crushed to zero anyways.
  if (e_gamma <= 0.0001f) return 0.0f;
  return pow(
      (kPqInvA * pow(e_gamma, kPqInvF) - kPqInvB) / (kPqInvC - kPqInvD * pow(e_gamma, kPqInvF)),
      kPqInvE);
}

Color pqInvOetf(Color e_gamma) {
  return {{{pqInvOetf(e_gamma.r), pqInvOetf(e_gamma.g), pqInvOetf(e_gamma.b)}}};
}

float pqInvOetfLUT(float e_gamma) {
  int32_t value = static_cast<int32_t>(e_gamma * (kPqInvOETFNumEntries - 1) + 0.5);
  // TODO() : Remove once conversion modules have appropriate clamping in place
  value = CLIP3(value, 0, kPqInvOETFNumEntries - 1);

  return kPqInvOETF[value];
}

Color pqInvOetfLUT(Color e_gamma) {
  return {{{pqInvOetfLUT(e_gamma.r), pqInvOetfLUT(e_gamma.g), pqInvOetfLUT(e_gamma.b)}}};
}

////////////////////////////////////////////////////////////////////////////////
// Color conversions

Color bt709ToP3(Color e) {
  return {{{0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b,
            0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b,
            0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b}}};
}

Color bt709ToBt2100(Color e) {
  return {{{0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b,
            0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b,
            0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b}}};
}

Color p3ToBt709(Color e) {
  return {{{1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b,
            -0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b,
            -0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b}}};
}

Color p3ToBt2100(Color e) {
  return {{{0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b,
            0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b,
            -0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b}}};
}

Color bt2100ToBt709(Color e) {
  return {{{1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b,
            -0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b,
            -0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b}}};
}

Color bt2100ToP3(Color e) {
  return {{{1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b,
            -0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b,
            0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b}}};
}

// TODO: confirm we always want to convert like this before calculating
// luminance.
ColorTransformFn getHdrConversionFn(ultrahdr_color_gamut sdr_gamut,
                                    ultrahdr_color_gamut hdr_gamut) {
  switch (sdr_gamut) {
    case ULTRAHDR_COLORGAMUT_BT709:
      switch (hdr_gamut) {
        case ULTRAHDR_COLORGAMUT_BT709:
          return identityConversion;
        case ULTRAHDR_COLORGAMUT_P3:
          return p3ToBt709;
        case ULTRAHDR_COLORGAMUT_BT2100:
          return bt2100ToBt709;
        case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
          return nullptr;
      }
      break;
    case ULTRAHDR_COLORGAMUT_P3:
      switch (hdr_gamut) {
        case ULTRAHDR_COLORGAMUT_BT709:
          return bt709ToP3;
        case ULTRAHDR_COLORGAMUT_P3:
          return identityConversion;
        case ULTRAHDR_COLORGAMUT_BT2100:
          return bt2100ToP3;
        case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
          return nullptr;
      }
      break;
    case ULTRAHDR_COLORGAMUT_BT2100:
      switch (hdr_gamut) {
        case ULTRAHDR_COLORGAMUT_BT709:
          return bt709ToBt2100;
        case ULTRAHDR_COLORGAMUT_P3:
          return p3ToBt2100;
        case ULTRAHDR_COLORGAMUT_BT2100:
          return identityConversion;
        case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
          return nullptr;
      }
      break;
    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
      return nullptr;
  }
  return nullptr;
}

// All of these conversions are derived from the respective input YUV->RGB conversion followed by
// the RGB->YUV for the receiving encoding. They are consistent with the RGB<->YUV functions in
// gainmapmath.cpp, given that we use BT.709 encoding for sRGB and BT.601 encoding for Display-P3,
// to match DataSpace.

// Yuv Bt709 -> Yuv Bt601
// Y' = (1.0 * Y) + ( 0.101579 * U) + ( 0.196076 * V)
// U' = (0.0 * Y) + ( 0.989854 * U) + (-0.110653 * V)
// V' = (0.0 * Y) + (-0.072453 * U) + ( 0.983398 * V)
const std::array<float, 9> kYuvBt709ToBt601 = {
    1.0f, 0.101579f, 0.196076f, 0.0f, 0.989854f, -0.110653f, 0.0f, -0.072453f, 0.983398f};

// Yuv Bt709 -> Yuv Bt2100
// Y' = (1.0 * Y) + (-0.016969 * U) + ( 0.096312 * V)
// U' = (0.0 * Y) + ( 0.995306 * U) + (-0.051192 * V)
// V' = (0.0 * Y) + ( 0.011507 * U) + ( 1.002637 * V)
const std::array<float, 9> kYuvBt709ToBt2100 = {
    1.0f, -0.016969f, 0.096312f, 0.0f, 0.995306f, -0.051192f, 0.0f, 0.011507f, 1.002637f};

// Yuv Bt601 -> Yuv Bt709
// Y' = (1.0 * Y) + (-0.118188 * U) + (-0.212685 * V)
// U' = (0.0 * Y) + ( 1.018640 * U) + ( 0.114618 * V)
// V' = (0.0 * Y) + ( 0.075049 * U) + ( 1.025327 * V)
const std::array<float, 9> kYuvBt601ToBt709 = {
    1.0f, -0.118188f, -0.212685f, 0.0f, 1.018640f, 0.114618f, 0.0f, 0.075049f, 1.025327f};

// Yuv Bt601 -> Yuv Bt2100
// Y' = (1.0 * Y) + (-0.128245 * U) + (-0.115879 * V)
// U' = (0.0 * Y) + ( 1.010016 * U) + ( 0.061592 * V)
// V' = (0.0 * Y) + ( 0.086969 * U) + ( 1.029350 * V)
const std::array<float, 9> kYuvBt601ToBt2100 = {
    1.0f, -0.128245f, -0.115879, 0.0f, 1.010016f, 0.061592f, 0.0f, 0.086969f, 1.029350f};

// Yuv Bt2100 -> Yuv Bt709
// Y' = (1.0 * Y) + ( 0.018149 * U) + (-0.095132 * V)
// U' = (0.0 * Y) + ( 1.004123 * U) + ( 0.051267 * V)
// V' = (0.0 * Y) + (-0.011524 * U) + ( 0.996782 * V)
const std::array<float, 9> kYuvBt2100ToBt709 = {
    1.0f, 0.018149f, -0.095132f, 0.0f, 1.004123f, 0.051267f, 0.0f, -0.011524f, 0.996782f};

// Yuv Bt2100 -> Yuv Bt601
// Y' = (1.0 * Y) + ( 0.117887 * U) + ( 0.105521 * V)
// U' = (0.0 * Y) + ( 0.995211 * U) + (-0.059549 * V)
// V' = (0.0 * Y) + (-0.084085 * U) + ( 0.976518 * V)
const std::array<float, 9> kYuvBt2100ToBt601 = {
    1.0f, 0.117887f, 0.105521f, 0.0f, 0.995211f, -0.059549f, 0.0f, -0.084085f, 0.976518f};

Color yuvColorGamutConversion(Color e_gamma, const std::array<float, 9>& coeffs) {
  const float y = e_gamma.y * std::get<0>(coeffs) + e_gamma.u * std::get<1>(coeffs) +
                  e_gamma.v * std::get<2>(coeffs);
  const float u = e_gamma.y * std::get<3>(coeffs) + e_gamma.u * std::get<4>(coeffs) +
                  e_gamma.v * std::get<5>(coeffs);
  const float v = e_gamma.y * std::get<6>(coeffs) + e_gamma.u * std::get<7>(coeffs) +
                  e_gamma.v * std::get<8>(coeffs);
  return {{{y, u, v}}};
}

void transformYuv420(jr_uncompressed_ptr image, const std::array<float, 9>& coeffs) {
  for (size_t y = 0; y < image->height / 2; ++y) {
    for (size_t x = 0; x < image->width / 2; ++x) {
      Color yuv1 = getYuv420Pixel(image, x * 2, y * 2);
      Color yuv2 = getYuv420Pixel(image, x * 2 + 1, y * 2);
      Color yuv3 = getYuv420Pixel(image, x * 2, y * 2 + 1);
      Color yuv4 = getYuv420Pixel(image, x * 2 + 1, y * 2 + 1);

      yuv1 = yuvColorGamutConversion(yuv1, coeffs);
      yuv2 = yuvColorGamutConversion(yuv2, coeffs);
      yuv3 = yuvColorGamutConversion(yuv3, coeffs);
      yuv4 = yuvColorGamutConversion(yuv4, coeffs);

      Color new_uv = (yuv1 + yuv2 + yuv3 + yuv4) / 4.0f;

      size_t pixel_y1_idx = x * 2 + y * 2 * image->luma_stride;
      size_t pixel_y2_idx = (x * 2 + 1) + y * 2 * image->luma_stride;
      size_t pixel_y3_idx = x * 2 + (y * 2 + 1) * image->luma_stride;
      size_t pixel_y4_idx = (x * 2 + 1) + (y * 2 + 1) * image->luma_stride;

      uint8_t& y1_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y1_idx];
      uint8_t& y2_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y2_idx];
      uint8_t& y3_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y3_idx];
      uint8_t& y4_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y4_idx];

      size_t pixel_count = image->chroma_stride * image->height / 2;
      size_t pixel_uv_idx = x + y * (image->chroma_stride);

      uint8_t& u_uint = reinterpret_cast<uint8_t*>(image->chroma_data)[pixel_uv_idx];
      uint8_t& v_uint = reinterpret_cast<uint8_t*>(image->chroma_data)[pixel_count + pixel_uv_idx];

      y1_uint = static_cast<uint8_t>(CLIP3((yuv1.y * 255.0f + 0.5f), 0, 255));
      y2_uint = static_cast<uint8_t>(CLIP3((yuv2.y * 255.0f + 0.5f), 0, 255));
      y3_uint = static_cast<uint8_t>(CLIP3((yuv3.y * 255.0f + 0.5f), 0, 255));
      y4_uint = static_cast<uint8_t>(CLIP3((yuv4.y * 255.0f + 0.5f), 0, 255));

      u_uint = static_cast<uint8_t>(CLIP3((new_uv.u * 255.0f + 128.0f + 0.5f), 0, 255));
      v_uint = static_cast<uint8_t>(CLIP3((new_uv.v * 255.0f + 128.0f + 0.5f), 0, 255));
    }
  }
}

////////////////////////////////////////////////////////////////////////////////
// Gain map calculations
uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata) {
  return encodeGain(y_sdr, y_hdr, metadata, log2(metadata->minContentBoost),
                    log2(metadata->maxContentBoost));
}

uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata,
                   float log2MinContentBoost, float log2MaxContentBoost) {
  float gain = 1.0f;
  if (y_sdr > 0.0f) {
    gain = y_hdr / y_sdr;
  }

  if (gain < metadata->minContentBoost) gain = metadata->minContentBoost;
  if (gain > metadata->maxContentBoost) gain = metadata->maxContentBoost;

  return static_cast<uint8_t>((log2(gain) - log2MinContentBoost) /
                              (log2MaxContentBoost - log2MinContentBoost) * 255.0f);
}

Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata) {
  float logBoost =
      log2(metadata->minContentBoost) * (1.0f - gain) + log2(metadata->maxContentBoost) * gain;
  float gainFactor = exp2(logBoost);
  return e * gainFactor;
}

Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata, float displayBoost) {
  float logBoost =
      log2(metadata->minContentBoost) * (1.0f - gain) + log2(metadata->maxContentBoost) * gain;
  float gainFactor = exp2(logBoost * displayBoost / metadata->maxContentBoost);
  return e * gainFactor;
}

Color applyGainLUT(Color e, float gain, GainLUT& gainLUT) {
  float gainFactor = gainLUT.getGainFactor(gain);
  return e * gainFactor;
}

Color applyGain(Color e, Color gain, ultrahdr_metadata_ptr metadata) {
  float logBoostR =
      log2(metadata->minContentBoost) * (1.0f - gain.r) + log2(metadata->maxContentBoost) * gain.r;
  float logBoostG =
      log2(metadata->minContentBoost) * (1.0f - gain.g) + log2(metadata->maxContentBoost) * gain.g;
  float logBoostB =
      log2(metadata->minContentBoost) * (1.0f - gain.b) + log2(metadata->maxContentBoost) * gain.b;
  float gainFactorR = exp2(logBoostR);
  float gainFactorG = exp2(logBoostG);
  float gainFactorB = exp2(logBoostB);
  return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
}

Color applyGain(Color e, Color gain, ultrahdr_metadata_ptr metadata, float displayBoost) {
  float logBoostR =
      log2(metadata->minContentBoost) * (1.0f - gain.r) + log2(metadata->maxContentBoost) * gain.r;
  float logBoostG =
      log2(metadata->minContentBoost) * (1.0f - gain.g) + log2(metadata->maxContentBoost) * gain.g;
  float logBoostB =
      log2(metadata->minContentBoost) * (1.0f - gain.b) + log2(metadata->maxContentBoost) * gain.b;
  float gainFactorR = exp2(logBoostR * displayBoost / metadata->maxContentBoost);
  float gainFactorG = exp2(logBoostG * displayBoost / metadata->maxContentBoost);
  float gainFactorB = exp2(logBoostB * displayBoost / metadata->maxContentBoost);
  return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
}

Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT) {
  float gainFactorR = gainLUT.getGainFactor(gain.r);
  float gainFactorG = gainLUT.getGainFactor(gain.g);
  float gainFactorB = gainLUT.getGainFactor(gain.b);
  return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
}

Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->data);
  size_t luma_stride = image->luma_stride;
  uint8_t* chroma_data = reinterpret_cast<uint8_t*>(image->chroma_data);
  size_t chroma_stride = image->chroma_stride;

  size_t offset_cr = chroma_stride * (image->height / 2);
  size_t pixel_y_idx = x + y * luma_stride;
  size_t pixel_chroma_idx = x / 2 + (y / 2) * chroma_stride;

  uint8_t y_uint = luma_data[pixel_y_idx];
  uint8_t u_uint = chroma_data[pixel_chroma_idx];
  uint8_t v_uint = chroma_data[offset_cr + pixel_chroma_idx];

  // 128 bias for UV given we are using jpeglib; see:
  // https://github.com/kornelski/libjpeg/blob/master/structure.doc
  return {
      {{static_cast<float>(y_uint) * (1 / 255.0f), static_cast<float>(u_uint - 128) * (1 / 255.0f),
        static_cast<float>(v_uint - 128) * (1 / 255.0f)}}};
}

Color getP010Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->data);
  size_t luma_stride = image->luma_stride == 0 ? image->width : image->luma_stride;
  uint16_t* chroma_data = reinterpret_cast<uint16_t*>(image->chroma_data);
  size_t chroma_stride = image->chroma_stride;

  size_t pixel_y_idx = y * luma_stride + x;
  size_t pixel_u_idx = (y >> 1) * chroma_stride + (x & ~0x1);
  size_t pixel_v_idx = pixel_u_idx + 1;

  uint16_t y_uint = luma_data[pixel_y_idx] >> 6;
  uint16_t u_uint = chroma_data[pixel_u_idx] >> 6;
  uint16_t v_uint = chroma_data[pixel_v_idx] >> 6;

  if (image->colorRange == UHDR_CR_FULL_RANGE) {
    return {{{static_cast<float>(y_uint) / 1023.0f,
              static_cast<float>(u_uint) / 1023.0f - 0.5f,
              static_cast<float>(v_uint) / 1023.0f - 0.5f }}};
  }

  // Conversions include taking narrow-range into account.
  return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
            static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
            static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
}

typedef Color (*getPixelFn)(jr_uncompressed_ptr, size_t, size_t);

static Color samplePixels(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y,
                          getPixelFn get_pixel_fn) {
  Color e = {{{0.0f, 0.0f, 0.0f}}};
  for (size_t dy = 0; dy < map_scale_factor; ++dy) {
    for (size_t dx = 0; dx < map_scale_factor; ++dx) {
      e += get_pixel_fn(image, x * map_scale_factor + dx, y * map_scale_factor + dy);
    }
  }

  return e / static_cast<float>(map_scale_factor * map_scale_factor);
}

Color sampleYuv420(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
  return samplePixels(image, map_scale_factor, x, y, getYuv420Pixel);
}

Color sampleP010(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
  return samplePixels(image, map_scale_factor, x, y, getP010Pixel);
}

// TODO: do we need something more clever for filtering either the map or images
// to generate the map?

static size_t clamp(const size_t& val, const size_t& low, const size_t& high) {
  return val < low ? low : (high < val ? high : val);
}

static float mapUintToFloat(uint8_t map_uint) { return static_cast<float>(map_uint) / 255.0f; }

static float pythDistance(float x_diff, float y_diff) {
  return sqrt(pow(x_diff, 2.0f) + pow(y_diff, 2.0f));
}

// TODO: If map_scale_factor is guaranteed to be an integer, then remove the following.
float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y) {
  float x_map = static_cast<float>(x) / map_scale_factor;
  float y_map = static_cast<float>(y) / map_scale_factor;

  size_t x_lower = static_cast<size_t>(floor(x_map));
  size_t x_upper = x_lower + 1;
  size_t y_lower = static_cast<size_t>(floor(y_map));
  size_t y_upper = y_lower + 1;

  x_lower = clamp(x_lower, 0, map->width - 1);
  x_upper = clamp(x_upper, 0, map->width - 1);
  y_lower = clamp(y_lower, 0, map->height - 1);
  y_upper = clamp(y_upper, 0, map->height - 1);

  // Use Shepard's method for inverse distance weighting. For more information:
  // en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method

  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
  float e1_dist =
      pythDistance(x_map - static_cast<float>(x_lower), y_map - static_cast<float>(y_lower));
  if (e1_dist == 0.0f) return e1;

  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
  float e2_dist =
      pythDistance(x_map - static_cast<float>(x_lower), y_map - static_cast<float>(y_upper));
  if (e2_dist == 0.0f) return e2;

  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
  float e3_dist =
      pythDistance(x_map - static_cast<float>(x_upper), y_map - static_cast<float>(y_lower));
  if (e3_dist == 0.0f) return e3;

  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);
  float e4_dist =
      pythDistance(x_map - static_cast<float>(x_upper), y_map - static_cast<float>(y_upper));
  if (e4_dist == 0.0f) return e2;

  float e1_weight = 1.0f / e1_dist;
  float e2_weight = 1.0f / e2_dist;
  float e3_weight = 1.0f / e3_dist;
  float e4_weight = 1.0f / e4_dist;
  float total_weight = e1_weight + e2_weight + e3_weight + e4_weight;

  return e1 * (e1_weight / total_weight) + e2 * (e2_weight / total_weight) +
         e3 * (e3_weight / total_weight) + e4 * (e4_weight / total_weight);
}

float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
                ShepardsIDW& weightTables) {
  // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
  // following by computing log2(map_scale_factor) once and then using >> log2(map_scale_factor)
  size_t x_lower = x / map_scale_factor;
  size_t x_upper = x_lower + 1;
  size_t y_lower = y / map_scale_factor;
  size_t y_upper = y_lower + 1;

  x_lower = std::min(x_lower, map->width - 1);
  x_upper = std::min(x_upper, map->width - 1);
  y_lower = std::min(y_lower, map->height - 1);
  y_upper = std::min(y_upper, map->height - 1);

  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);

  // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
  // following by using & (map_scale_factor - 1)
  int offset_x = x % map_scale_factor;
  int offset_y = y % map_scale_factor;

  float* weights = weightTables.mWeights;
  if (x_lower == x_upper && y_lower == y_upper)
    weights = weightTables.mWeightsC;
  else if (x_lower == x_upper)
    weights = weightTables.mWeightsNR;
  else if (y_lower == y_upper)
    weights = weightTables.mWeightsNB;
  weights += offset_y * map_scale_factor * 4 + offset_x * 4;

  return e1 * weights[0] + e2 * weights[1] + e3 * weights[2] + e4 * weights[3];
}

Color sampleMap3Channel(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y,
                        bool has_alpha) {
  float x_map = static_cast<float>(x) / map_scale_factor;
  float y_map = static_cast<float>(y) / map_scale_factor;

  size_t x_lower = static_cast<size_t>(floor(x_map));
  size_t x_upper = x_lower + 1;
  size_t y_lower = static_cast<size_t>(floor(y_map));
  size_t y_upper = y_lower + 1;

  x_lower = std::min(x_lower, map->width - 1);
  x_upper = std::min(x_upper, map->width - 1);
  y_lower = std::min(y_lower, map->height - 1);
  y_upper = std::min(y_upper, map->height - 1);

  int factor = has_alpha ? 4 : 3;

  float r1 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor]);
  float r2 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor]);
  float r3 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor]);
  float r4 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor]);

  float g1 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 1]);
  float g2 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 1]);
  float g3 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 1]);
  float g4 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 1]);

  float b1 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 2]);
  float b2 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 2]);
  float b3 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 2]);
  float b4 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 2]);

  Color rgb1 = {{{r1, g1, b1}}};
  Color rgb2 = {{{r2, g2, b2}}};
  Color rgb3 = {{{r3, g3, b3}}};
  Color rgb4 = {{{r4, g4, b4}}};

  // Use Shepard's method for inverse distance weighting. For more information:
  // en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method
  float e1_dist =
      pythDistance(x_map - static_cast<float>(x_lower), y_map - static_cast<float>(y_lower));
  if (e1_dist == 0.0f) return rgb1;

  float e2_dist =
      pythDistance(x_map - static_cast<float>(x_lower), y_map - static_cast<float>(y_upper));
  if (e2_dist == 0.0f) return rgb2;

  float e3_dist =
      pythDistance(x_map - static_cast<float>(x_upper), y_map - static_cast<float>(y_lower));
  if (e3_dist == 0.0f) return rgb3;

  float e4_dist =
      pythDistance(x_map - static_cast<float>(x_upper), y_map - static_cast<float>(y_upper));
  if (e4_dist == 0.0f) return rgb4;

  float e1_weight = 1.0f / e1_dist;
  float e2_weight = 1.0f / e2_dist;
  float e3_weight = 1.0f / e3_dist;
  float e4_weight = 1.0f / e4_dist;
  float total_weight = e1_weight + e2_weight + e3_weight + e4_weight;

  return rgb1 * (e1_weight / total_weight) + rgb2 * (e2_weight / total_weight) +
         rgb3 * (e3_weight / total_weight) + rgb4 * (e4_weight / total_weight);
}

Color sampleMap3Channel(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
                        ShepardsIDW& weightTables, bool has_alpha) {
  // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
  // following by computing log2(map_scale_factor) once and then using >> log2(map_scale_factor)
  size_t x_lower = x / map_scale_factor;
  size_t x_upper = x_lower + 1;
  size_t y_lower = y / map_scale_factor;
  size_t y_upper = y_lower + 1;

  x_lower = std::min(x_lower, map->width - 1);
  x_upper = std::min(x_upper, map->width - 1);
  y_lower = std::min(y_lower, map->height - 1);
  y_upper = std::min(y_upper, map->height - 1);

  int factor = has_alpha ? 4 : 3;

  float r1 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor]);
  float r2 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor]);
  float r3 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor]);
  float r4 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor]);

  float g1 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 1]);
  float g2 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 1]);
  float g3 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 1]);
  float g4 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 1]);

  float b1 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 2]);
  float b2 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 2]);
  float b3 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 2]);
  float b4 = mapUintToFloat(
      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 2]);

  Color rgb1 = {{{r1, g1, b1}}};
  Color rgb2 = {{{r2, g2, b2}}};
  Color rgb3 = {{{r3, g3, b3}}};
  Color rgb4 = {{{r4, g4, b4}}};

  // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
  // following by using & (map_scale_factor - 1)
  int offset_x = x % map_scale_factor;
  int offset_y = y % map_scale_factor;

  float* weights = weightTables.mWeights;
  if (x_lower == x_upper && y_lower == y_upper)
    weights = weightTables.mWeightsC;
  else if (x_lower == x_upper)
    weights = weightTables.mWeightsNR;
  else if (y_lower == y_upper)
    weights = weightTables.mWeightsNB;
  weights += offset_y * map_scale_factor * 4 + offset_x * 4;

  return rgb1 * weights[0] + rgb2 * weights[1] + rgb3 * weights[2] + rgb4 * weights[3];
}

uint32_t colorToRgba1010102(Color e_gamma) {
  return (0x3ff & static_cast<uint32_t>(e_gamma.r * 1023.0f)) |
         ((0x3ff & static_cast<uint32_t>(e_gamma.g * 1023.0f)) << 10) |
         ((0x3ff & static_cast<uint32_t>(e_gamma.b * 1023.0f)) << 20) |
         (0x3 << 30);  // Set alpha to 1.0
}

uint64_t colorToRgbaF16(Color e_gamma) {
  return (uint64_t)floatToHalf(e_gamma.r) | (((uint64_t)floatToHalf(e_gamma.g)) << 16) |
         (((uint64_t)floatToHalf(e_gamma.b)) << 32) | (((uint64_t)floatToHalf(1.0f)) << 48);
}

std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_t* src) {
  std::unique_ptr<uhdr_raw_image_ext_t> dst = nullptr;
  Color (*rgbToyuv)(Color) = nullptr;

  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    if (src->cg == UHDR_CG_BT_709) {
      rgbToyuv = srgbRgbToYuv;
    } else if (src->cg == UHDR_CG_BT_2100) {
      rgbToyuv = bt2100RgbToYuv;
    } else if (src->cg == UHDR_CG_DISPLAY_P3) {
      rgbToyuv = p3RgbToYuv;
    } else {
      return dst;
    }
  }

  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppYCbCrP010, src->cg, src->ct,
                                                 UHDR_CR_LIMITED_RANGE, src->w, src->h, 64);

    uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    unsigned int srcStride = src->stride[UHDR_PLANE_PACKED];

    uint16_t* yData = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
    uint16_t* uData = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_UV]);
    uint16_t* vData = uData + 1;

    for (size_t i = 0; i < dst->h; i += 2) {
      for (size_t j = 0; j < dst->w; j += 2) {
        Color pixel[4];

        pixel[0].r = float(rgbData[srcStride * i + j] & 0x3ff);
        pixel[0].g = float((rgbData[srcStride * i + j] >> 10) & 0x3ff);
        pixel[0].b = float((rgbData[srcStride * i + j] >> 20) & 0x3ff);

        pixel[1].r = float(rgbData[srcStride * i + j + 1] & 0x3ff);
        pixel[1].g = float((rgbData[srcStride * i + j + 1] >> 10) & 0x3ff);
        pixel[1].b = float((rgbData[srcStride * i + j + 1] >> 20) & 0x3ff);

        pixel[2].r = float(rgbData[srcStride * (i + 1) + j] & 0x3ff);
        pixel[2].g = float((rgbData[srcStride * (i + 1) + j] >> 10) & 0x3ff);
        pixel[2].b = float((rgbData[srcStride * (i + 1) + j] >> 20) & 0x3ff);

        pixel[3].r = float(rgbData[srcStride * (i + 1) + j + 1] & 0x3ff);
        pixel[3].g = float((rgbData[srcStride * (i + 1) + j + 1] >> 10) & 0x3ff);
        pixel[3].b = float((rgbData[srcStride * (i + 1) + j + 1] >> 20) & 0x3ff);

        for (int k = 0; k < 4; k++) {
          pixel[k] /= 1023.0f;
          pixel[k] = (*rgbToyuv)(pixel[k]);

          pixel[k].y = (pixel[k].y * 876.0f) + 64.0f + 0.5f;
          pixel[k].y = CLIP3(pixel[k].y, 64.0f, 940.0f);
        }

        yData[dst->stride[UHDR_PLANE_Y] * i + j] = uint16_t(pixel[0].y) << 6;
        yData[dst->stride[UHDR_PLANE_Y] * i + j + 1] = uint16_t(pixel[1].y) << 6;
        yData[dst->stride[UHDR_PLANE_Y] * (i + 1) + j] = uint16_t(pixel[2].y) << 6;
        yData[dst->stride[UHDR_PLANE_Y] * (i + 1) + j + 1] = uint16_t(pixel[3].y) << 6;

        pixel[0].u = (pixel[0].u + pixel[1].u + pixel[2].u + pixel[3].u) / 4;
        pixel[0].v = (pixel[0].v + pixel[1].v + pixel[2].v + pixel[3].v) / 4;

        pixel[0].u = (pixel[0].u * 896.0f) + 512.0f + 0.5f;
        pixel[0].v = (pixel[0].v * 896.0f) + 512.0f + 0.5f;

        pixel[0].u = CLIP3(pixel[0].u, 64.0f, 960.0f);
        pixel[0].v = CLIP3(pixel[0].v, 64.0f, 960.0f);

        uData[dst->stride[UHDR_PLANE_UV] * (i / 2) + j] = uint16_t(pixel[0].u) << 6;
        vData[dst->stride[UHDR_PLANE_UV] * (i / 2) + j] = uint16_t(pixel[0].v) << 6;
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_12bppYCbCr420, src->cg, src->ct,
                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
    uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
    unsigned int srcStride = src->stride[UHDR_PLANE_PACKED];

    uint8_t* yData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    uint8_t* uData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
    uint8_t* vData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);
    for (size_t i = 0; i < dst->h; i += 2) {
      for (size_t j = 0; j < dst->w; j += 2) {
        Color pixel[4];

        pixel[0].r = float(rgbData[srcStride * i + j] & 0xff);
        pixel[0].g = float((rgbData[srcStride * i + j] >> 8) & 0xff);
        pixel[0].b = float((rgbData[srcStride * i + j] >> 16) & 0xff);

        pixel[1].r = float(rgbData[srcStride * i + (j + 1)] & 0xff);
        pixel[1].g = float((rgbData[srcStride * i + (j + 1)] >> 8) & 0xff);
        pixel[1].b = float((rgbData[srcStride * i + (j + 1)] >> 16) & 0xff);

        pixel[2].r = float(rgbData[srcStride * (i + 1) + j] & 0xff);
        pixel[2].g = float((rgbData[srcStride * (i + 1) + j] >> 8) & 0xff);
        pixel[2].b = float((rgbData[srcStride * (i + 1) + j] >> 16) & 0xff);

        pixel[3].r = float(rgbData[srcStride * (i + 1) + (j + 1)] & 0xff);
        pixel[3].g = float((rgbData[srcStride * (i + 1) + (j + 1)] >> 8) & 0xff);
        pixel[3].b = float((rgbData[srcStride * (i + 1) + (j + 1)] >> 16) & 0xff);

        for (int k = 0; k < 4; k++) {
          pixel[k] /= 255.0f;
          pixel[k] = (*rgbToyuv)(pixel[k]);

          pixel[k].y = pixel[k].y * 255.0f + 0.5f;
          pixel[k].y = CLIP3(pixel[k].y, 0.0f, 255.0f);
        }
        yData[dst->stride[UHDR_PLANE_Y] * i + j] = uint8_t(pixel[0].y);
        yData[dst->stride[UHDR_PLANE_Y] * i + j + 1] = uint8_t(pixel[1].y);
        yData[dst->stride[UHDR_PLANE_Y] * (i + 1) + j] = uint8_t(pixel[2].y);
        yData[dst->stride[UHDR_PLANE_Y] * (i + 1) + j + 1] = uint8_t(pixel[3].y);

        pixel[0].u = (pixel[0].u + pixel[1].u + pixel[2].u + pixel[3].u) / 4;
        pixel[0].v = (pixel[0].v + pixel[1].v + pixel[2].v + pixel[3].v) / 4;

        pixel[0].u = pixel[0].u * 255.0f + 0.5 + 128.0f;
        pixel[0].v = pixel[0].v * 255.0f + 0.5 + 128.0f;

        pixel[0].u = CLIP3(pixel[0].u, 0.0f, 255.0f);
        pixel[0].v = CLIP3(pixel[0].v, 0.0f, 255.0f);

        uData[dst->stride[UHDR_PLANE_U] * (i / 2) + (j / 2)] = uint8_t(pixel[0].u);
        vData[dst->stride[UHDR_PLANE_V] * (i / 2) + (j / 2)] = uint8_t(pixel[0].v);
      }
    }
  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    dst = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range,
                                                           src->w, src->h, 64);

    uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* u_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
    uint8_t* u_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_U]);
    uint8_t* v_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);
    uint8_t* v_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_V]);

    // copy y
    for (size_t i = 0; i < src->h; i++) {
      memcpy(y_dst, y_src, src->w);
      y_dst += dst->stride[UHDR_PLANE_Y];
      y_src += src->stride[UHDR_PLANE_Y];
    }
    // copy cb & cr
    for (size_t i = 0; i < src->h / 2; i++) {
      memcpy(u_dst, u_src, src->w / 2);
      memcpy(v_dst, v_src, src->w / 2);
      u_dst += dst->stride[UHDR_PLANE_U];
      v_dst += dst->stride[UHDR_PLANE_V];
      u_src += src->stride[UHDR_PLANE_U];
      v_src += src->stride[UHDR_PLANE_V];
    }
  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    dst = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range,
                                                           src->w, src->h, 64);

    int bpp = 2;
    uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
    uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
    uint8_t* uv_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_UV]);
    uint8_t* uv_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_UV]);

    // copy y
    for (size_t i = 0; i < src->h; i++) {
      memcpy(y_dst, y_src, src->w * bpp);
      y_dst += (dst->stride[UHDR_PLANE_Y] * bpp);
      y_src += (src->stride[UHDR_PLANE_Y] * bpp);
    }
    // copy cbcr
    for (size_t i = 0; i < src->h / 2; i++) {
      memcpy(uv_dst, uv_src, src->w * bpp);
      uv_dst += (dst->stride[UHDR_PLANE_UV] * bpp);
      uv_src += (src->stride[UHDR_PLANE_UV] * bpp);
    }
  }
  return dst;
}
// Use double type for intermediate results for better precision.
static bool floatToUnsignedFractionImpl(float v, uint32_t maxNumerator, uint32_t* numerator,
                                        uint32_t* denominator) {
  if (std::isnan(v) || v < 0 || v > maxNumerator) {
    return false;
  }

  // Maximum denominator: makes sure that the numerator is <= maxNumerator and the denominator
  // is <= UINT32_MAX.
  const uint64_t maxD = (v <= 1) ? UINT32_MAX : (uint64_t)floor(maxNumerator / v);

  // Find the best approximation of v as a fraction using continued fractions, see
  // https://en.wikipedia.org/wiki/Continued_fraction
  *denominator = 1;
  uint32_t previousD = 0;
  double currentV = (double)v - floor(v);
  int iter = 0;
  // Set a maximum number of iterations to be safe. Most numbers should
  // converge in less than ~20 iterations.
  // The golden ratio is the worst case and takes 39 iterations.
  const int maxIter = 39;
  while (iter < maxIter) {
    const double numeratorDouble = (double)(*denominator) * v;
    if (numeratorDouble > maxNumerator) {
      return false;
    }
    *numerator = (uint32_t)round(numeratorDouble);
    if (fabs(numeratorDouble - (*numerator)) == 0.0) {
      return true;
    }
    currentV = 1.0 / currentV;
    const double newD = previousD + floor(currentV) * (*denominator);
    if (newD > maxD) {
      // This is the best we can do with a denominator <= max_d.
      return true;
    }
    previousD = *denominator;
    if (newD > (double)UINT32_MAX) {
      return false;
    }
    *denominator = (uint32_t)newD;
    currentV -= floor(currentV);
    ++iter;
  }
  // Maximum number of iterations reached, return what we've found.
  // For max_iter >= 39 we shouldn't get here. max_iter can be set
  // to a lower value to speed up the algorithm if needed.
  *numerator = (uint32_t)round((double)(*denominator) * v);
  return true;
}

bool floatToSignedFraction(float v, int32_t* numerator, uint32_t* denominator) {
  uint32_t positive_numerator;
  if (!floatToUnsignedFractionImpl(fabs(v), INT32_MAX, &positive_numerator, denominator)) {
    return false;
  }
  *numerator = (int32_t)positive_numerator;
  if (v < 0) {
    *numerator *= -1;
  }
  return true;
}

bool floatToUnsignedFraction(float v, uint32_t* numerator, uint32_t* denominator) {
  return floatToUnsignedFractionImpl(v, UINT32_MAX, numerator, denominator);
}

}  // namespace ultrahdr
