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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <ultrahdr/gainmapmath.h>

namespace android::ultrahdr {

class GainMapMathTest : public testing::Test {
public:
  GainMapMathTest();
  ~GainMapMathTest();

  float ComparisonEpsilon() { return 1e-4f; }
  float LuminanceEpsilon() { return 1e-2f; }
  float YuvConversionEpsilon() { return 1.0f / (255.0f * 2.0f); }

  Color Yuv420(uint8_t y, uint8_t u, uint8_t v) {
      return {{{ static_cast<float>(y) / 255.0f,
                 (static_cast<float>(u) - 128.0f) / 255.0f,
                 (static_cast<float>(v) - 128.0f) / 255.0f }}};
  }

  Color P010(uint16_t y, uint16_t u, uint16_t v) {
      return {{{ (static_cast<float>(y) - 64.0f) / 876.0f,
                 (static_cast<float>(u) - 64.0f) / 896.0f - 0.5f,
                 (static_cast<float>(v) - 64.0f) / 896.0f - 0.5f }}};
  }

  float Map(uint8_t e) {
    return static_cast<float>(e) / 255.0f;
  }

  Color ColorMin(Color e1, Color e2) {
    return {{{ fmin(e1.r, e2.r), fmin(e1.g, e2.g), fmin(e1.b, e2.b) }}};
  }

  Color ColorMax(Color e1, Color e2) {
    return {{{ fmax(e1.r, e2.r), fmax(e1.g, e2.g), fmax(e1.b, e2.b) }}};
  }

  Color RgbBlack() { return {{{ 0.0f, 0.0f, 0.0f }}}; }
  Color RgbWhite() { return {{{ 1.0f, 1.0f, 1.0f }}}; }

  Color RgbRed() { return {{{ 1.0f, 0.0f, 0.0f }}}; }
  Color RgbGreen() { return {{{ 0.0f, 1.0f, 0.0f }}}; }
  Color RgbBlue() { return {{{ 0.0f, 0.0f, 1.0f }}}; }

  Color YuvBlack() { return {{{ 0.0f, 0.0f, 0.0f }}}; }
  Color YuvWhite() { return {{{ 1.0f, 0.0f, 0.0f }}}; }

  Color SrgbYuvRed() { return {{{ 0.2126f, -0.11457f, 0.5f }}}; }
  Color SrgbYuvGreen() { return {{{ 0.7152f, -0.38543f, -0.45415f }}}; }
  Color SrgbYuvBlue() { return {{{ 0.0722f, 0.5f, -0.04585f }}}; }

  Color P3YuvRed() { return {{{ 0.299f, -0.16874f, 0.5f }}}; }
  Color P3YuvGreen() { return {{{ 0.587f, -0.33126f, -0.41869f }}}; }
  Color P3YuvBlue() { return {{{ 0.114f, 0.5f, -0.08131f }}}; }

  Color Bt2100YuvRed() { return {{{ 0.2627f, -0.13963f, 0.5f }}}; }
  Color Bt2100YuvGreen() { return {{{ 0.6780f, -0.36037f, -0.45979f }}}; }
  Color Bt2100YuvBlue() { return {{{ 0.0593f, 0.5f, -0.04021f }}}; }

  float SrgbYuvToLuminance(Color yuv_gamma, ColorCalculationFn luminanceFn) {
    Color rgb_gamma = srgbYuvToRgb(yuv_gamma);
    Color rgb = srgbInvOetf(rgb_gamma);
    float luminance_scaled = luminanceFn(rgb);
    return luminance_scaled * kSdrWhiteNits;
  }

  float P3YuvToLuminance(Color yuv_gamma, ColorCalculationFn luminanceFn) {
    Color rgb_gamma = p3YuvToRgb(yuv_gamma);
    Color rgb = srgbInvOetf(rgb_gamma);
    float luminance_scaled = luminanceFn(rgb);
    return luminance_scaled * kSdrWhiteNits;
  }

  float Bt2100YuvToLuminance(Color yuv_gamma, ColorTransformFn hdrInvOetf,
                             ColorTransformFn gamutConversionFn, ColorCalculationFn luminanceFn,
                             float scale_factor) {
    Color rgb_gamma = bt2100YuvToRgb(yuv_gamma);
    Color rgb = hdrInvOetf(rgb_gamma);
    rgb = gamutConversionFn(rgb);
    float luminance_scaled = luminanceFn(rgb);
    return luminance_scaled * scale_factor;
  }

  Color Recover(Color yuv_gamma, float gain, ultrahdr_metadata_ptr metadata) {
    Color rgb_gamma = srgbYuvToRgb(yuv_gamma);
    Color rgb = srgbInvOetf(rgb_gamma);
    return applyGain(rgb, gain, metadata);
  }

  jpegr_uncompressed_struct Yuv420Image() {
    static uint8_t pixels[] = {
      // Y
      0x00, 0x10, 0x20, 0x30,
      0x01, 0x11, 0x21, 0x31,
      0x02, 0x12, 0x22, 0x32,
      0x03, 0x13, 0x23, 0x33,
      // U
      0xA0, 0xA1,
      0xA2, 0xA3,
      // V
      0xB0, 0xB1,
      0xB2, 0xB3,
    };
    return { pixels, 4, 4, ULTRAHDR_COLORGAMUT_BT709 };
  }

  Color (*Yuv420Colors())[4] {
    static Color colors[4][4] = {
      {
        Yuv420(0x00, 0xA0, 0xB0), Yuv420(0x10, 0xA0, 0xB0),
        Yuv420(0x20, 0xA1, 0xB1), Yuv420(0x30, 0xA1, 0xB1),
      }, {
        Yuv420(0x01, 0xA0, 0xB0), Yuv420(0x11, 0xA0, 0xB0),
        Yuv420(0x21, 0xA1, 0xB1), Yuv420(0x31, 0xA1, 0xB1),
      }, {
        Yuv420(0x02, 0xA2, 0xB2), Yuv420(0x12, 0xA2, 0xB2),
        Yuv420(0x22, 0xA3, 0xB3), Yuv420(0x32, 0xA3, 0xB3),
      }, {
        Yuv420(0x03, 0xA2, 0xB2), Yuv420(0x13, 0xA2, 0xB2),
        Yuv420(0x23, 0xA3, 0xB3), Yuv420(0x33, 0xA3, 0xB3),
      },
    };
    return colors;
  }

  jpegr_uncompressed_struct P010Image() {
    static uint16_t pixels[] = {
      // Y
      0x00 << 6, 0x10 << 6, 0x20 << 6, 0x30 << 6,
      0x01 << 6, 0x11 << 6, 0x21 << 6, 0x31 << 6,
      0x02 << 6, 0x12 << 6, 0x22 << 6, 0x32 << 6,
      0x03 << 6, 0x13 << 6, 0x23 << 6, 0x33 << 6,
      // UV
      0xA0 << 6, 0xB0 << 6, 0xA1 << 6, 0xB1 << 6,
      0xA2 << 6, 0xB2 << 6, 0xA3 << 6, 0xB3 << 6,
    };
    return { pixels, 4, 4, ULTRAHDR_COLORGAMUT_BT709 };
  }

  Color (*P010Colors())[4] {
    static Color colors[4][4] = {
      {
        P010(0x00, 0xA0, 0xB0), P010(0x10, 0xA0, 0xB0),
        P010(0x20, 0xA1, 0xB1), P010(0x30, 0xA1, 0xB1),
      }, {
        P010(0x01, 0xA0, 0xB0), P010(0x11, 0xA0, 0xB0),
        P010(0x21, 0xA1, 0xB1), P010(0x31, 0xA1, 0xB1),
      }, {
        P010(0x02, 0xA2, 0xB2), P010(0x12, 0xA2, 0xB2),
        P010(0x22, 0xA3, 0xB3), P010(0x32, 0xA3, 0xB3),
      }, {
        P010(0x03, 0xA2, 0xB2), P010(0x13, 0xA2, 0xB2),
        P010(0x23, 0xA3, 0xB3), P010(0x33, 0xA3, 0xB3),
      },
    };
    return colors;
  }

  jpegr_uncompressed_struct MapImage() {
    static uint8_t pixels[] = {
      0x00, 0x10, 0x20, 0x30,
      0x01, 0x11, 0x21, 0x31,
      0x02, 0x12, 0x22, 0x32,
      0x03, 0x13, 0x23, 0x33,
    };
    return { pixels, 4, 4, ULTRAHDR_COLORGAMUT_UNSPECIFIED };
  }

  float (*MapValues())[4] {
    static float values[4][4] = {
      {
        Map(0x00), Map(0x10), Map(0x20), Map(0x30),
      }, {
        Map(0x01), Map(0x11), Map(0x21), Map(0x31),
      }, {
        Map(0x02), Map(0x12), Map(0x22), Map(0x32),
      }, {
        Map(0x03), Map(0x13), Map(0x23), Map(0x33),
      },
    };
    return values;
  }

protected:
  virtual void SetUp();
  virtual void TearDown();
};

GainMapMathTest::GainMapMathTest() {}
GainMapMathTest::~GainMapMathTest() {}

void GainMapMathTest::SetUp() {}
void GainMapMathTest::TearDown() {}

#define EXPECT_RGB_EQ(e1, e2)       \
  EXPECT_FLOAT_EQ((e1).r, (e2).r);  \
  EXPECT_FLOAT_EQ((e1).g, (e2).g);  \
  EXPECT_FLOAT_EQ((e1).b, (e2).b)

#define EXPECT_RGB_NEAR(e1, e2)                     \
  EXPECT_NEAR((e1).r, (e2).r, ComparisonEpsilon()); \
  EXPECT_NEAR((e1).g, (e2).g, ComparisonEpsilon()); \
  EXPECT_NEAR((e1).b, (e2).b, ComparisonEpsilon())

#define EXPECT_RGB_CLOSE(e1, e2)                            \
  EXPECT_NEAR((e1).r, (e2).r, ComparisonEpsilon() * 10.0f); \
  EXPECT_NEAR((e1).g, (e2).g, ComparisonEpsilon() * 10.0f); \
  EXPECT_NEAR((e1).b, (e2).b, ComparisonEpsilon() * 10.0f)

#define EXPECT_YUV_EQ(e1, e2)       \
  EXPECT_FLOAT_EQ((e1).y, (e2).y);  \
  EXPECT_FLOAT_EQ((e1).u, (e2).u);  \
  EXPECT_FLOAT_EQ((e1).v, (e2).v)

#define EXPECT_YUV_NEAR(e1, e2)                     \
  EXPECT_NEAR((e1).y, (e2).y, ComparisonEpsilon()); \
  EXPECT_NEAR((e1).u, (e2).u, ComparisonEpsilon()); \
  EXPECT_NEAR((e1).v, (e2).v, ComparisonEpsilon())

#define EXPECT_YUV_BETWEEN(e, min, max)                                           \
  EXPECT_THAT((e).y, testing::AllOf(testing::Ge((min).y), testing::Le((max).y))); \
  EXPECT_THAT((e).u, testing::AllOf(testing::Ge((min).u), testing::Le((max).u))); \
  EXPECT_THAT((e).v, testing::AllOf(testing::Ge((min).v), testing::Le((max).v)))

// TODO: a bunch of these tests can be parameterized.

TEST_F(GainMapMathTest, ColorConstruct) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  EXPECT_FLOAT_EQ(e1.r, 0.1f);
  EXPECT_FLOAT_EQ(e1.g, 0.2f);
  EXPECT_FLOAT_EQ(e1.b, 0.3f);

  EXPECT_FLOAT_EQ(e1.y, 0.1f);
  EXPECT_FLOAT_EQ(e1.u, 0.2f);
  EXPECT_FLOAT_EQ(e1.v, 0.3f);
}

TEST_F(GainMapMathTest, ColorAddColor) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  Color e2 = e1 + e1;
  EXPECT_FLOAT_EQ(e2.r, e1.r * 2.0f);
  EXPECT_FLOAT_EQ(e2.g, e1.g * 2.0f);
  EXPECT_FLOAT_EQ(e2.b, e1.b * 2.0f);

  e2 += e1;
  EXPECT_FLOAT_EQ(e2.r, e1.r * 3.0f);
  EXPECT_FLOAT_EQ(e2.g, e1.g * 3.0f);
  EXPECT_FLOAT_EQ(e2.b, e1.b * 3.0f);
}

TEST_F(GainMapMathTest, ColorAddFloat) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  Color e2 = e1 + 0.1f;
  EXPECT_FLOAT_EQ(e2.r, e1.r + 0.1f);
  EXPECT_FLOAT_EQ(e2.g, e1.g + 0.1f);
  EXPECT_FLOAT_EQ(e2.b, e1.b + 0.1f);

  e2 += 0.1f;
  EXPECT_FLOAT_EQ(e2.r, e1.r + 0.2f);
  EXPECT_FLOAT_EQ(e2.g, e1.g + 0.2f);
  EXPECT_FLOAT_EQ(e2.b, e1.b + 0.2f);
}

TEST_F(GainMapMathTest, ColorSubtractColor) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  Color e2 = e1 - e1;
  EXPECT_FLOAT_EQ(e2.r, 0.0f);
  EXPECT_FLOAT_EQ(e2.g, 0.0f);
  EXPECT_FLOAT_EQ(e2.b, 0.0f);

  e2 -= e1;
  EXPECT_FLOAT_EQ(e2.r, -e1.r);
  EXPECT_FLOAT_EQ(e2.g, -e1.g);
  EXPECT_FLOAT_EQ(e2.b, -e1.b);
}

TEST_F(GainMapMathTest, ColorSubtractFloat) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  Color e2 = e1 - 0.1f;
  EXPECT_FLOAT_EQ(e2.r, e1.r - 0.1f);
  EXPECT_FLOAT_EQ(e2.g, e1.g - 0.1f);
  EXPECT_FLOAT_EQ(e2.b, e1.b - 0.1f);

  e2 -= 0.1f;
  EXPECT_FLOAT_EQ(e2.r, e1.r - 0.2f);
  EXPECT_FLOAT_EQ(e2.g, e1.g - 0.2f);
  EXPECT_FLOAT_EQ(e2.b, e1.b - 0.2f);
}

TEST_F(GainMapMathTest, ColorMultiplyFloat) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  Color e2 = e1 * 2.0f;
  EXPECT_FLOAT_EQ(e2.r, e1.r * 2.0f);
  EXPECT_FLOAT_EQ(e2.g, e1.g * 2.0f);
  EXPECT_FLOAT_EQ(e2.b, e1.b * 2.0f);

  e2 *= 2.0f;
  EXPECT_FLOAT_EQ(e2.r, e1.r * 4.0f);
  EXPECT_FLOAT_EQ(e2.g, e1.g * 4.0f);
  EXPECT_FLOAT_EQ(e2.b, e1.b * 4.0f);
}

TEST_F(GainMapMathTest, ColorDivideFloat) {
  Color e1 = {{{ 0.1f, 0.2f, 0.3f }}};

  Color e2 = e1 / 2.0f;
  EXPECT_FLOAT_EQ(e2.r, e1.r / 2.0f);
  EXPECT_FLOAT_EQ(e2.g, e1.g / 2.0f);
  EXPECT_FLOAT_EQ(e2.b, e1.b / 2.0f);

  e2 /= 2.0f;
  EXPECT_FLOAT_EQ(e2.r, e1.r / 4.0f);
  EXPECT_FLOAT_EQ(e2.g, e1.g / 4.0f);
  EXPECT_FLOAT_EQ(e2.b, e1.b / 4.0f);
}

TEST_F(GainMapMathTest, SrgbLuminance) {
  EXPECT_FLOAT_EQ(srgbLuminance(RgbBlack()), 0.0f);
  EXPECT_FLOAT_EQ(srgbLuminance(RgbWhite()), 1.0f);
  EXPECT_FLOAT_EQ(srgbLuminance(RgbRed()), 0.2126f);
  EXPECT_FLOAT_EQ(srgbLuminance(RgbGreen()), 0.7152f);
  EXPECT_FLOAT_EQ(srgbLuminance(RgbBlue()), 0.0722f);
}

TEST_F(GainMapMathTest, SrgbYuvToRgb) {
  Color rgb_black = srgbYuvToRgb(YuvBlack());
  EXPECT_RGB_NEAR(rgb_black, RgbBlack());

  Color rgb_white = srgbYuvToRgb(YuvWhite());
  EXPECT_RGB_NEAR(rgb_white, RgbWhite());

  Color rgb_r = srgbYuvToRgb(SrgbYuvRed());
  EXPECT_RGB_NEAR(rgb_r, RgbRed());

  Color rgb_g = srgbYuvToRgb(SrgbYuvGreen());
  EXPECT_RGB_NEAR(rgb_g, RgbGreen());

  Color rgb_b = srgbYuvToRgb(SrgbYuvBlue());
  EXPECT_RGB_NEAR(rgb_b, RgbBlue());
}

TEST_F(GainMapMathTest, SrgbRgbToYuv) {
  Color yuv_black = srgbRgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv_black, YuvBlack());

  Color yuv_white = srgbRgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv_white, YuvWhite());

  Color yuv_r = srgbRgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv_r, SrgbYuvRed());

  Color yuv_g = srgbRgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv_g, SrgbYuvGreen());

  Color yuv_b = srgbRgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv_b, SrgbYuvBlue());
}

TEST_F(GainMapMathTest, SrgbRgbYuvRoundtrip) {
  Color rgb_black = srgbYuvToRgb(srgbRgbToYuv(RgbBlack()));
  EXPECT_RGB_NEAR(rgb_black, RgbBlack());

  Color rgb_white = srgbYuvToRgb(srgbRgbToYuv(RgbWhite()));
  EXPECT_RGB_NEAR(rgb_white, RgbWhite());

  Color rgb_r = srgbYuvToRgb(srgbRgbToYuv(RgbRed()));
  EXPECT_RGB_NEAR(rgb_r, RgbRed());

  Color rgb_g = srgbYuvToRgb(srgbRgbToYuv(RgbGreen()));
  EXPECT_RGB_NEAR(rgb_g, RgbGreen());

  Color rgb_b = srgbYuvToRgb(srgbRgbToYuv(RgbBlue()));
  EXPECT_RGB_NEAR(rgb_b, RgbBlue());
}

TEST_F(GainMapMathTest, SrgbTransferFunction) {
  EXPECT_FLOAT_EQ(srgbInvOetf(0.0f), 0.0f);
  EXPECT_NEAR(srgbInvOetf(0.02f), 0.00154f, ComparisonEpsilon());
  EXPECT_NEAR(srgbInvOetf(0.04045f), 0.00313f, ComparisonEpsilon());
  EXPECT_NEAR(srgbInvOetf(0.5f), 0.21404f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(srgbInvOetf(1.0f), 1.0f);
}

TEST_F(GainMapMathTest, P3Luminance) {
  EXPECT_FLOAT_EQ(p3Luminance(RgbBlack()), 0.0f);
  EXPECT_FLOAT_EQ(p3Luminance(RgbWhite()), 1.0f);
  EXPECT_FLOAT_EQ(p3Luminance(RgbRed()), 0.20949f);
  EXPECT_FLOAT_EQ(p3Luminance(RgbGreen()), 0.72160f);
  EXPECT_FLOAT_EQ(p3Luminance(RgbBlue()), 0.06891f);
}

TEST_F(GainMapMathTest, P3YuvToRgb) {
  Color rgb_black = p3YuvToRgb(YuvBlack());
  EXPECT_RGB_NEAR(rgb_black, RgbBlack());

  Color rgb_white = p3YuvToRgb(YuvWhite());
  EXPECT_RGB_NEAR(rgb_white, RgbWhite());

  Color rgb_r = p3YuvToRgb(P3YuvRed());
  EXPECT_RGB_NEAR(rgb_r, RgbRed());

  Color rgb_g = p3YuvToRgb(P3YuvGreen());
  EXPECT_RGB_NEAR(rgb_g, RgbGreen());

  Color rgb_b = p3YuvToRgb(P3YuvBlue());
  EXPECT_RGB_NEAR(rgb_b, RgbBlue());
}

TEST_F(GainMapMathTest, P3RgbToYuv) {
  Color yuv_black = p3RgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv_black, YuvBlack());

  Color yuv_white = p3RgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv_white, YuvWhite());

  Color yuv_r = p3RgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv_r, P3YuvRed());

  Color yuv_g = p3RgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv_g, P3YuvGreen());

  Color yuv_b = p3RgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv_b, P3YuvBlue());
}

TEST_F(GainMapMathTest, P3RgbYuvRoundtrip) {
  Color rgb_black = p3YuvToRgb(p3RgbToYuv(RgbBlack()));
  EXPECT_RGB_NEAR(rgb_black, RgbBlack());

  Color rgb_white = p3YuvToRgb(p3RgbToYuv(RgbWhite()));
  EXPECT_RGB_NEAR(rgb_white, RgbWhite());

  Color rgb_r = p3YuvToRgb(p3RgbToYuv(RgbRed()));
  EXPECT_RGB_NEAR(rgb_r, RgbRed());

  Color rgb_g = p3YuvToRgb(p3RgbToYuv(RgbGreen()));
  EXPECT_RGB_NEAR(rgb_g, RgbGreen());

  Color rgb_b = p3YuvToRgb(p3RgbToYuv(RgbBlue()));
  EXPECT_RGB_NEAR(rgb_b, RgbBlue());
}
TEST_F(GainMapMathTest, Bt2100Luminance) {
  EXPECT_FLOAT_EQ(bt2100Luminance(RgbBlack()), 0.0f);
  EXPECT_FLOAT_EQ(bt2100Luminance(RgbWhite()), 1.0f);
  EXPECT_FLOAT_EQ(bt2100Luminance(RgbRed()), 0.2627f);
  EXPECT_FLOAT_EQ(bt2100Luminance(RgbGreen()), 0.6780f);
  EXPECT_FLOAT_EQ(bt2100Luminance(RgbBlue()), 0.0593f);
}

TEST_F(GainMapMathTest, Bt2100YuvToRgb) {
  Color rgb_black = bt2100YuvToRgb(YuvBlack());
  EXPECT_RGB_NEAR(rgb_black, RgbBlack());

  Color rgb_white = bt2100YuvToRgb(YuvWhite());
  EXPECT_RGB_NEAR(rgb_white, RgbWhite());

  Color rgb_r = bt2100YuvToRgb(Bt2100YuvRed());
  EXPECT_RGB_NEAR(rgb_r, RgbRed());

  Color rgb_g = bt2100YuvToRgb(Bt2100YuvGreen());
  EXPECT_RGB_NEAR(rgb_g, RgbGreen());

  Color rgb_b = bt2100YuvToRgb(Bt2100YuvBlue());
  EXPECT_RGB_NEAR(rgb_b, RgbBlue());
}

TEST_F(GainMapMathTest, Bt2100RgbToYuv) {
  Color yuv_black = bt2100RgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv_black, YuvBlack());

  Color yuv_white = bt2100RgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv_white, YuvWhite());

  Color yuv_r = bt2100RgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv_r, Bt2100YuvRed());

  Color yuv_g = bt2100RgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv_g, Bt2100YuvGreen());

  Color yuv_b = bt2100RgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv_b, Bt2100YuvBlue());
}

TEST_F(GainMapMathTest, Bt2100RgbYuvRoundtrip) {
  Color rgb_black = bt2100YuvToRgb(bt2100RgbToYuv(RgbBlack()));
  EXPECT_RGB_NEAR(rgb_black, RgbBlack());

  Color rgb_white = bt2100YuvToRgb(bt2100RgbToYuv(RgbWhite()));
  EXPECT_RGB_NEAR(rgb_white, RgbWhite());

  Color rgb_r = bt2100YuvToRgb(bt2100RgbToYuv(RgbRed()));
  EXPECT_RGB_NEAR(rgb_r, RgbRed());

  Color rgb_g = bt2100YuvToRgb(bt2100RgbToYuv(RgbGreen()));
  EXPECT_RGB_NEAR(rgb_g, RgbGreen());

  Color rgb_b = bt2100YuvToRgb(bt2100RgbToYuv(RgbBlue()));
  EXPECT_RGB_NEAR(rgb_b, RgbBlue());
}

TEST_F(GainMapMathTest, Bt709ToBt601YuvConversion) {
  Color yuv_black = srgbRgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv709To601(yuv_black), YuvBlack());

  Color yuv_white = srgbRgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv709To601(yuv_white), YuvWhite());

  Color yuv_r = srgbRgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv709To601(yuv_r), P3YuvRed());

  Color yuv_g = srgbRgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv709To601(yuv_g), P3YuvGreen());

  Color yuv_b = srgbRgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv709To601(yuv_b), P3YuvBlue());
}

TEST_F(GainMapMathTest, Bt709ToBt2100YuvConversion) {
  Color yuv_black = srgbRgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv709To2100(yuv_black), YuvBlack());

  Color yuv_white = srgbRgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv709To2100(yuv_white), YuvWhite());

  Color yuv_r = srgbRgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv709To2100(yuv_r), Bt2100YuvRed());

  Color yuv_g = srgbRgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv709To2100(yuv_g), Bt2100YuvGreen());

  Color yuv_b = srgbRgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv709To2100(yuv_b), Bt2100YuvBlue());
}

TEST_F(GainMapMathTest, Bt601ToBt709YuvConversion) {
  Color yuv_black = p3RgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv601To709(yuv_black), YuvBlack());

  Color yuv_white = p3RgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv601To709(yuv_white), YuvWhite());

  Color yuv_r = p3RgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv601To709(yuv_r), SrgbYuvRed());

  Color yuv_g = p3RgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv601To709(yuv_g), SrgbYuvGreen());

  Color yuv_b = p3RgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv601To709(yuv_b), SrgbYuvBlue());
}

TEST_F(GainMapMathTest, Bt601ToBt2100YuvConversion) {
  Color yuv_black = p3RgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv601To2100(yuv_black), YuvBlack());

  Color yuv_white = p3RgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv601To2100(yuv_white), YuvWhite());

  Color yuv_r = p3RgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv601To2100(yuv_r), Bt2100YuvRed());

  Color yuv_g = p3RgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv601To2100(yuv_g), Bt2100YuvGreen());

  Color yuv_b = p3RgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv601To2100(yuv_b), Bt2100YuvBlue());
}

TEST_F(GainMapMathTest, Bt2100ToBt709YuvConversion) {
  Color yuv_black = bt2100RgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv2100To709(yuv_black), YuvBlack());

  Color yuv_white = bt2100RgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv2100To709(yuv_white), YuvWhite());

  Color yuv_r = bt2100RgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv2100To709(yuv_r), SrgbYuvRed());

  Color yuv_g = bt2100RgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv2100To709(yuv_g), SrgbYuvGreen());

  Color yuv_b = bt2100RgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv2100To709(yuv_b), SrgbYuvBlue());
}

TEST_F(GainMapMathTest, Bt2100ToBt601YuvConversion) {
  Color yuv_black = bt2100RgbToYuv(RgbBlack());
  EXPECT_YUV_NEAR(yuv2100To601(yuv_black), YuvBlack());

  Color yuv_white = bt2100RgbToYuv(RgbWhite());
  EXPECT_YUV_NEAR(yuv2100To601(yuv_white), YuvWhite());

  Color yuv_r = bt2100RgbToYuv(RgbRed());
  EXPECT_YUV_NEAR(yuv2100To601(yuv_r), P3YuvRed());

  Color yuv_g = bt2100RgbToYuv(RgbGreen());
  EXPECT_YUV_NEAR(yuv2100To601(yuv_g), P3YuvGreen());

  Color yuv_b = bt2100RgbToYuv(RgbBlue());
  EXPECT_YUV_NEAR(yuv2100To601(yuv_b), P3YuvBlue());
}

TEST_F(GainMapMathTest, TransformYuv420) {
  ColorTransformFn transforms[] = { yuv709To601, yuv709To2100, yuv601To709, yuv601To2100,
                                    yuv2100To709, yuv2100To601 };
  for (const ColorTransformFn& transform : transforms) {
    jpegr_uncompressed_struct input = Yuv420Image();

    size_t out_buf_size = input.width * input.height * 3 / 2;
    std::unique_ptr<uint8_t[]> out_buf = std::make_unique<uint8_t[]>(out_buf_size);
    memcpy(out_buf.get(), input.data, out_buf_size);
    jpegr_uncompressed_struct output = Yuv420Image();
    output.data = out_buf.get();

    transformYuv420(&output, 1, 1, transform);

    for (size_t y = 0; y < 4; ++y) {
      for (size_t x = 0; x < 4; ++x) {
        // Skip the last chroma sample, which we modified above
        if (x >= 2 && y >= 2) {
          continue;
        }

        // All other pixels should remain unchanged
        EXPECT_YUV_EQ(getYuv420Pixel(&input, x, y), getYuv420Pixel(&output, x, y));
      }
    }

    // modified pixels should be updated as intended by the transformYuv420 algorithm
    Color in1 = getYuv420Pixel(&input,   2, 2);
    Color in2 = getYuv420Pixel(&input,   3, 2);
    Color in3 = getYuv420Pixel(&input,   2, 3);
    Color in4 = getYuv420Pixel(&input,   3, 3);
    Color out1 = getYuv420Pixel(&output, 2, 2);
    Color out2 = getYuv420Pixel(&output, 3, 2);
    Color out3 = getYuv420Pixel(&output, 2, 3);
    Color out4 = getYuv420Pixel(&output, 3, 3);

    EXPECT_NEAR(transform(in1).y, out1.y, YuvConversionEpsilon());
    EXPECT_NEAR(transform(in2).y, out2.y, YuvConversionEpsilon());
    EXPECT_NEAR(transform(in3).y, out3.y, YuvConversionEpsilon());
    EXPECT_NEAR(transform(in4).y, out4.y, YuvConversionEpsilon());

    Color expect_uv = (transform(in1) + transform(in2) + transform(in3) + transform(in4)) / 4.0f;

    EXPECT_NEAR(expect_uv.u, out1.u, YuvConversionEpsilon());
    EXPECT_NEAR(expect_uv.u, out2.u, YuvConversionEpsilon());
    EXPECT_NEAR(expect_uv.u, out3.u, YuvConversionEpsilon());
    EXPECT_NEAR(expect_uv.u, out4.u, YuvConversionEpsilon());

    EXPECT_NEAR(expect_uv.v, out1.v, YuvConversionEpsilon());
    EXPECT_NEAR(expect_uv.v, out2.v, YuvConversionEpsilon());
    EXPECT_NEAR(expect_uv.v, out3.v, YuvConversionEpsilon());
    EXPECT_NEAR(expect_uv.v, out4.v, YuvConversionEpsilon());
  }
}

TEST_F(GainMapMathTest, HlgOetf) {
  EXPECT_FLOAT_EQ(hlgOetf(0.0f), 0.0f);
  EXPECT_NEAR(hlgOetf(0.04167f), 0.35357f, ComparisonEpsilon());
  EXPECT_NEAR(hlgOetf(0.08333f), 0.5f, ComparisonEpsilon());
  EXPECT_NEAR(hlgOetf(0.5f), 0.87164f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(hlgOetf(1.0f), 1.0f);

  Color e = {{{ 0.04167f, 0.08333f, 0.5f }}};
  Color e_gamma = {{{ 0.35357f, 0.5f, 0.87164f }}};
  EXPECT_RGB_NEAR(hlgOetf(e), e_gamma);
}

TEST_F(GainMapMathTest, HlgInvOetf) {
  EXPECT_FLOAT_EQ(hlgInvOetf(0.0f), 0.0f);
  EXPECT_NEAR(hlgInvOetf(0.25f), 0.02083f, ComparisonEpsilon());
  EXPECT_NEAR(hlgInvOetf(0.5f), 0.08333f, ComparisonEpsilon());
  EXPECT_NEAR(hlgInvOetf(0.75f), 0.26496f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(hlgInvOetf(1.0f), 1.0f);

  Color e_gamma = {{{ 0.25f, 0.5f, 0.75f }}};
  Color e = {{{ 0.02083f, 0.08333f, 0.26496f }}};
  EXPECT_RGB_NEAR(hlgInvOetf(e_gamma), e);
}

TEST_F(GainMapMathTest, HlgTransferFunctionRoundtrip) {
  EXPECT_FLOAT_EQ(hlgInvOetf(hlgOetf(0.0f)), 0.0f);
  EXPECT_NEAR(hlgInvOetf(hlgOetf(0.04167f)), 0.04167f, ComparisonEpsilon());
  EXPECT_NEAR(hlgInvOetf(hlgOetf(0.08333f)), 0.08333f, ComparisonEpsilon());
  EXPECT_NEAR(hlgInvOetf(hlgOetf(0.5f)), 0.5f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(hlgInvOetf(hlgOetf(1.0f)), 1.0f);
}

TEST_F(GainMapMathTest, PqOetf) {
  EXPECT_FLOAT_EQ(pqOetf(0.0f), 0.0f);
  EXPECT_NEAR(pqOetf(0.01f), 0.50808f, ComparisonEpsilon());
  EXPECT_NEAR(pqOetf(0.5f), 0.92655f, ComparisonEpsilon());
  EXPECT_NEAR(pqOetf(0.99f), 0.99895f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(pqOetf(1.0f), 1.0f);

  Color e = {{{ 0.01f, 0.5f, 0.99f }}};
  Color e_gamma = {{{ 0.50808f, 0.92655f, 0.99895f }}};
  EXPECT_RGB_NEAR(pqOetf(e), e_gamma);
}

TEST_F(GainMapMathTest, PqInvOetf) {
  EXPECT_FLOAT_EQ(pqInvOetf(0.0f), 0.0f);
  EXPECT_NEAR(pqInvOetf(0.01f), 2.31017e-7f, ComparisonEpsilon());
  EXPECT_NEAR(pqInvOetf(0.5f), 0.00922f, ComparisonEpsilon());
  EXPECT_NEAR(pqInvOetf(0.99f), 0.90903f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(pqInvOetf(1.0f), 1.0f);

  Color e_gamma = {{{ 0.01f, 0.5f, 0.99f }}};
  Color e = {{{ 2.31017e-7f, 0.00922f, 0.90903f }}};
  EXPECT_RGB_NEAR(pqInvOetf(e_gamma), e);
}

TEST_F(GainMapMathTest, PqInvOetfLUT) {
    for (int idx = 0; idx < kPqInvOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kPqInvOETFNumEntries - 1);
      EXPECT_FLOAT_EQ(pqInvOetf(value), pqInvOetfLUT(value));
    }
}

TEST_F(GainMapMathTest, HlgInvOetfLUT) {
    for (int idx = 0; idx < kHlgInvOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kHlgInvOETFNumEntries - 1);
      EXPECT_FLOAT_EQ(hlgInvOetf(value), hlgInvOetfLUT(value));
    }
}

TEST_F(GainMapMathTest, pqOetfLUT) {
    for (int idx = 0; idx < kPqOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kPqOETFNumEntries - 1);
      EXPECT_FLOAT_EQ(pqOetf(value), pqOetfLUT(value));
    }
}

TEST_F(GainMapMathTest, hlgOetfLUT) {
    for (int idx = 0; idx < kHlgOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kHlgOETFNumEntries - 1);
      EXPECT_FLOAT_EQ(hlgOetf(value), hlgOetfLUT(value));
    }
}

TEST_F(GainMapMathTest, srgbInvOetfLUT) {
    for (int idx = 0; idx < kSrgbInvOETFNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kSrgbInvOETFNumEntries - 1);
      EXPECT_FLOAT_EQ(srgbInvOetf(value), srgbInvOetfLUT(value));
    }
}

TEST_F(GainMapMathTest, applyGainLUT) {
  for (int boost = 1; boost <= 10; boost++) {
    ultrahdr_metadata_struct metadata = { .maxContentBoost = static_cast<float>(boost),
                                       .minContentBoost = 1.0f / static_cast<float>(boost) };
    GainLUT gainLUT(&metadata);
    GainLUT gainLUTWithBoost(&metadata, metadata.maxContentBoost);
    for (int idx = 0; idx < kGainFactorNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
      EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
                      applyGainLUT(RgbBlack(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata),
                      applyGainLUT(RgbWhite(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata),
                      applyGainLUT(RgbRed(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata),
                      applyGainLUT(RgbGreen(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata),
                      applyGainLUT(RgbBlue(), value, gainLUT));
      EXPECT_RGB_EQ(applyGainLUT(RgbBlack(), value, gainLUT),
                    applyGainLUT(RgbBlack(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbWhite(), value, gainLUT),
                    applyGainLUT(RgbWhite(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbRed(), value, gainLUT),
                    applyGainLUT(RgbRed(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbGreen(), value, gainLUT),
                    applyGainLUT(RgbGreen(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbBlue(), value, gainLUT),
                    applyGainLUT(RgbBlue(), value, gainLUTWithBoost));
    }
  }

  for (int boost = 1; boost <= 10; boost++) {
    ultrahdr_metadata_struct metadata = { .maxContentBoost = static_cast<float>(boost),
                                       .minContentBoost = 1.0f };
    GainLUT gainLUT(&metadata);
    GainLUT gainLUTWithBoost(&metadata, metadata.maxContentBoost);
    for (int idx = 0; idx < kGainFactorNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
      EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
                      applyGainLUT(RgbBlack(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata),
                      applyGainLUT(RgbWhite(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata),
                      applyGainLUT(RgbRed(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata),
                      applyGainLUT(RgbGreen(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata),
                      applyGainLUT(RgbBlue(), value, gainLUT));
      EXPECT_RGB_EQ(applyGainLUT(RgbBlack(), value, gainLUT),
                    applyGainLUT(RgbBlack(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbWhite(), value, gainLUT),
                    applyGainLUT(RgbWhite(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbRed(), value, gainLUT),
                    applyGainLUT(RgbRed(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbGreen(), value, gainLUT),
                    applyGainLUT(RgbGreen(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbBlue(), value, gainLUT),
                    applyGainLUT(RgbBlue(), value, gainLUTWithBoost));
    }
  }

  for (int boost = 1; boost <= 10; boost++) {
    ultrahdr_metadata_struct metadata = { .maxContentBoost = static_cast<float>(boost),
                                       .minContentBoost = 1.0f / pow(static_cast<float>(boost),
                                                              1.0f / 3.0f) };
    GainLUT gainLUT(&metadata);
    GainLUT gainLUTWithBoost(&metadata, metadata.maxContentBoost);
    for (int idx = 0; idx < kGainFactorNumEntries; idx++) {
      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
      EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
                      applyGainLUT(RgbBlack(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata),
                      applyGainLUT(RgbWhite(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata),
                      applyGainLUT(RgbRed(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata),
                      applyGainLUT(RgbGreen(), value, gainLUT));
      EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata),
                      applyGainLUT(RgbBlue(), value, gainLUT));
      EXPECT_RGB_EQ(applyGainLUT(RgbBlack(), value, gainLUT),
                    applyGainLUT(RgbBlack(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbWhite(), value, gainLUT),
                    applyGainLUT(RgbWhite(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbRed(), value, gainLUT),
                    applyGainLUT(RgbRed(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbGreen(), value, gainLUT),
                    applyGainLUT(RgbGreen(), value, gainLUTWithBoost));
      EXPECT_RGB_EQ(applyGainLUT(RgbBlue(), value, gainLUT),
                    applyGainLUT(RgbBlue(), value, gainLUTWithBoost));
    }
  }
}

TEST_F(GainMapMathTest, PqTransferFunctionRoundtrip) {
  EXPECT_FLOAT_EQ(pqInvOetf(pqOetf(0.0f)), 0.0f);
  EXPECT_NEAR(pqInvOetf(pqOetf(0.01f)), 0.01f, ComparisonEpsilon());
  EXPECT_NEAR(pqInvOetf(pqOetf(0.5f)), 0.5f, ComparisonEpsilon());
  EXPECT_NEAR(pqInvOetf(pqOetf(0.99f)), 0.99f, ComparisonEpsilon());
  EXPECT_FLOAT_EQ(pqInvOetf(pqOetf(1.0f)), 1.0f);
}

TEST_F(GainMapMathTest, ColorConversionLookup) {
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
            nullptr);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_BT709),
            identityConversion);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3),
            p3ToBt709);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_BT2100),
            bt2100ToBt709);

  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
            nullptr);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT709),
            bt709ToP3);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_P3),
            identityConversion);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100),
            bt2100ToP3);

  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
            nullptr);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_BT709),
            bt709ToBt2100);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_P3),
            p3ToBt2100);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_BT2100),
            identityConversion);

  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
            nullptr);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_BT709),
            nullptr);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_P3),
            nullptr);
  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_BT2100),
            nullptr);
}

TEST_F(GainMapMathTest, EncodeGain) {
  ultrahdr_metadata_struct metadata = { .maxContentBoost = 4.0f,
                                        .minContentBoost = 1.0f / 4.0f };

  EXPECT_EQ(encodeGain(0.0f, 0.0f, &metadata), 127);
  EXPECT_EQ(encodeGain(0.0f, 1.0f, &metadata), 127);
  EXPECT_EQ(encodeGain(1.0f, 0.0f, &metadata), 0);
  EXPECT_EQ(encodeGain(0.5f, 0.0f, &metadata), 0);

  EXPECT_EQ(encodeGain(1.0f, 1.0f, &metadata), 127);
  EXPECT_EQ(encodeGain(1.0f, 4.0f, &metadata), 255);
  EXPECT_EQ(encodeGain(1.0f, 5.0f, &metadata), 255);
  EXPECT_EQ(encodeGain(4.0f, 1.0f, &metadata), 0);
  EXPECT_EQ(encodeGain(4.0f, 0.5f, &metadata), 0);
  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 191);
  EXPECT_EQ(encodeGain(2.0f, 1.0f, &metadata), 63);

  metadata.maxContentBoost = 2.0f;
  metadata.minContentBoost = 1.0f / 2.0f;

  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 255);
  EXPECT_EQ(encodeGain(2.0f, 1.0f, &metadata), 0);
  EXPECT_EQ(encodeGain(1.0f, 1.41421f, &metadata), 191);
  EXPECT_EQ(encodeGain(1.41421f, 1.0f, &metadata), 63);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 1.0f / 8.0f;

  EXPECT_EQ(encodeGain(1.0f, 8.0f, &metadata), 255);
  EXPECT_EQ(encodeGain(8.0f, 1.0f, &metadata), 0);
  EXPECT_EQ(encodeGain(1.0f, 2.82843f, &metadata), 191);
  EXPECT_EQ(encodeGain(2.82843f, 1.0f, &metadata), 63);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 1.0f;

  EXPECT_EQ(encodeGain(0.0f, 0.0f, &metadata), 0);
  EXPECT_EQ(encodeGain(1.0f, 0.0f, &metadata), 0);

  EXPECT_EQ(encodeGain(1.0f, 1.0f, &metadata), 0);
  EXPECT_EQ(encodeGain(1.0f, 8.0f, &metadata), 255);
  EXPECT_EQ(encodeGain(1.0f, 4.0f, &metadata), 170);
  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 85);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 0.5f;

  EXPECT_EQ(encodeGain(0.0f, 0.0f, &metadata), 63);
  EXPECT_EQ(encodeGain(1.0f, 0.0f, &metadata), 0);

  EXPECT_EQ(encodeGain(1.0f, 1.0f, &metadata), 63);
  EXPECT_EQ(encodeGain(1.0f, 8.0f, &metadata), 255);
  EXPECT_EQ(encodeGain(1.0f, 4.0f, &metadata), 191);
  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 127);
  EXPECT_EQ(encodeGain(1.0f, 0.7071f, &metadata), 31);
  EXPECT_EQ(encodeGain(1.0f, 0.5f, &metadata), 0);
}

TEST_F(GainMapMathTest, ApplyGain) {
  ultrahdr_metadata_struct metadata = { .maxContentBoost = 4.0f,
                                        .minContentBoost = 1.0f / 4.0f };
  float displayBoost = metadata.maxContentBoost;

  EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.0f, &metadata), RgbBlack());
  EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.5f, &metadata), RgbBlack());
  EXPECT_RGB_NEAR(applyGain(RgbBlack(), 1.0f, &metadata), RgbBlack());

  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 4.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 2.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.5f, &metadata), RgbWhite());
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 2.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 4.0f);

  metadata.maxContentBoost = 2.0f;
  metadata.minContentBoost = 1.0f / 2.0f;

  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 2.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 1.41421f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.5f, &metadata), RgbWhite());
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 1.41421f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 2.0f);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 1.0f / 8.0f;

  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 8.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 2.82843f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.5f, &metadata), RgbWhite());
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 2.82843f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 1.0f;

  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite());
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f / 3.0f, &metadata), RgbWhite() * 2.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 2.0f / 3.0f, &metadata), RgbWhite() * 4.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 0.5f;

  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 2.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite());
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.5f, &metadata), RgbWhite() * 2.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 4.0f);
  EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);

  Color e = {{{ 0.0f, 0.5f, 1.0f }}};
  metadata.maxContentBoost = 4.0f;
  metadata.minContentBoost = 1.0f / 4.0f;

  EXPECT_RGB_NEAR(applyGain(e, 0.0f, &metadata), e / 4.0f);
  EXPECT_RGB_NEAR(applyGain(e, 0.25f, &metadata), e / 2.0f);
  EXPECT_RGB_NEAR(applyGain(e, 0.5f, &metadata), e);
  EXPECT_RGB_NEAR(applyGain(e, 0.75f, &metadata), e * 2.0f);
  EXPECT_RGB_NEAR(applyGain(e, 1.0f, &metadata), e * 4.0f);

  EXPECT_RGB_EQ(applyGain(RgbBlack(), 1.0f, &metadata),
                applyGain(RgbBlack(), 1.0f, &metadata, displayBoost));
  EXPECT_RGB_EQ(applyGain(RgbWhite(), 1.0f, &metadata),
                applyGain(RgbWhite(), 1.0f, &metadata, displayBoost));
  EXPECT_RGB_EQ(applyGain(RgbRed(), 1.0f, &metadata),
                applyGain(RgbRed(), 1.0f, &metadata, displayBoost));
  EXPECT_RGB_EQ(applyGain(RgbGreen(), 1.0f, &metadata),
                applyGain(RgbGreen(), 1.0f, &metadata, displayBoost));
  EXPECT_RGB_EQ(applyGain(RgbBlue(), 1.0f, &metadata),
                applyGain(RgbBlue(), 1.0f, &metadata, displayBoost));
  EXPECT_RGB_EQ(applyGain(e, 1.0f, &metadata),
                applyGain(e, 1.0f, &metadata, displayBoost));
}

TEST_F(GainMapMathTest, GetYuv420Pixel) {
  jpegr_uncompressed_struct image = Yuv420Image();
  Color (*colors)[4] = Yuv420Colors();

  for (size_t y = 0; y < 4; ++y) {
    for (size_t x = 0; x < 4; ++x) {
      EXPECT_YUV_NEAR(getYuv420Pixel(&image, x, y), colors[y][x]);
    }
  }
}

TEST_F(GainMapMathTest, GetP010Pixel) {
  jpegr_uncompressed_struct image = P010Image();
  Color (*colors)[4] = P010Colors();

  for (size_t y = 0; y < 4; ++y) {
    for (size_t x = 0; x < 4; ++x) {
      EXPECT_YUV_NEAR(getP010Pixel(&image, x, y), colors[y][x]);
    }
  }
}

TEST_F(GainMapMathTest, SampleYuv420) {
  jpegr_uncompressed_struct image = Yuv420Image();
  Color (*colors)[4] = Yuv420Colors();

  static const size_t kMapScaleFactor = 2;
  for (size_t y = 0; y < 4 / kMapScaleFactor; ++y) {
    for (size_t x = 0; x < 4 / kMapScaleFactor; ++x) {
      Color min = {{{ 1.0f, 1.0f, 1.0f }}};
      Color max = {{{ -1.0f, -1.0f, -1.0f }}};

      for (size_t dy = 0; dy < kMapScaleFactor; ++dy) {
        for (size_t dx = 0; dx < kMapScaleFactor; ++dx) {
          Color e = colors[y * kMapScaleFactor + dy][x * kMapScaleFactor + dx];
          min = ColorMin(min, e);
          max = ColorMax(max, e);
        }
      }

      // Instead of reimplementing the sampling algorithm, confirm that the
      // sample output is within the range of the min and max of the nearest
      // points.
      EXPECT_YUV_BETWEEN(sampleYuv420(&image, kMapScaleFactor, x, y), min, max);
    }
  }
}

TEST_F(GainMapMathTest, SampleP010) {
  jpegr_uncompressed_struct image = P010Image();
  Color (*colors)[4] = P010Colors();

  static const size_t kMapScaleFactor = 2;
  for (size_t y = 0; y < 4 / kMapScaleFactor; ++y) {
    for (size_t x = 0; x < 4 / kMapScaleFactor; ++x) {
      Color min = {{{ 1.0f, 1.0f, 1.0f }}};
      Color max = {{{ -1.0f, -1.0f, -1.0f }}};

      for (size_t dy = 0; dy < kMapScaleFactor; ++dy) {
        for (size_t dx = 0; dx < kMapScaleFactor; ++dx) {
          Color e = colors[y * kMapScaleFactor + dy][x * kMapScaleFactor + dx];
          min = ColorMin(min, e);
          max = ColorMax(max, e);
        }
      }

      // Instead of reimplementing the sampling algorithm, confirm that the
      // sample output is within the range of the min and max of the nearest
      // points.
      EXPECT_YUV_BETWEEN(sampleP010(&image, kMapScaleFactor, x, y), min, max);
    }
  }
}

TEST_F(GainMapMathTest, SampleMap) {
  jpegr_uncompressed_struct image = MapImage();
  float (*values)[4] = MapValues();

  static const size_t kMapScaleFactor = 2;
  ShepardsIDW idwTable(kMapScaleFactor);
  for (size_t y = 0; y < 4 * kMapScaleFactor; ++y) {
    for (size_t x = 0; x < 4 * kMapScaleFactor; ++x) {
      size_t x_base = x / kMapScaleFactor;
      size_t y_base = y / kMapScaleFactor;

      float min = 1.0f;
      float max = -1.0f;

      min = fmin(min, values[y_base][x_base]);
      max = fmax(max, values[y_base][x_base]);
      if (y_base + 1 < 4) {
        min = fmin(min, values[y_base + 1][x_base]);
        max = fmax(max, values[y_base + 1][x_base]);
      }
      if (x_base + 1 < 4) {
        min = fmin(min, values[y_base][x_base + 1]);
        max = fmax(max, values[y_base][x_base + 1]);
      }
      if (y_base + 1 < 4 && x_base + 1 < 4) {
        min = fmin(min, values[y_base + 1][x_base + 1]);
        max = fmax(max, values[y_base + 1][x_base + 1]);
      }

      // Instead of reimplementing the sampling algorithm, confirm that the
      // sample output is within the range of the min and max of the nearest
      // points.
      EXPECT_THAT(sampleMap(&image, kMapScaleFactor, x, y),
                  testing::AllOf(testing::Ge(min), testing::Le(max)));
      EXPECT_EQ(sampleMap(&image, kMapScaleFactor, x, y, idwTable),
                sampleMap(&image, kMapScaleFactor, x, y));
    }
  }
}

TEST_F(GainMapMathTest, ColorToRgba1010102) {
  EXPECT_EQ(colorToRgba1010102(RgbBlack()), 0x3 << 30);
  EXPECT_EQ(colorToRgba1010102(RgbWhite()), 0xFFFFFFFF);
  EXPECT_EQ(colorToRgba1010102(RgbRed()), 0x3 << 30 | 0x3ff);
  EXPECT_EQ(colorToRgba1010102(RgbGreen()), 0x3 << 30 | 0x3ff << 10);
  EXPECT_EQ(colorToRgba1010102(RgbBlue()), 0x3 << 30 | 0x3ff << 20);

  Color e_gamma = {{{ 0.1f, 0.2f, 0.3f }}};
  EXPECT_EQ(colorToRgba1010102(e_gamma),
            0x3 << 30
          | static_cast<uint32_t>(0.1f * static_cast<float>(0x3ff))
          | static_cast<uint32_t>(0.2f * static_cast<float>(0x3ff)) << 10
          | static_cast<uint32_t>(0.3f * static_cast<float>(0x3ff)) << 20);
}

TEST_F(GainMapMathTest, ColorToRgbaF16) {
  EXPECT_EQ(colorToRgbaF16(RgbBlack()), ((uint64_t) 0x3C00) << 48);
  EXPECT_EQ(colorToRgbaF16(RgbWhite()), 0x3C003C003C003C00);
  EXPECT_EQ(colorToRgbaF16(RgbRed()),   (((uint64_t) 0x3C00) << 48) | ((uint64_t) 0x3C00));
  EXPECT_EQ(colorToRgbaF16(RgbGreen()), (((uint64_t) 0x3C00) << 48) | (((uint64_t) 0x3C00) << 16));
  EXPECT_EQ(colorToRgbaF16(RgbBlue()),  (((uint64_t) 0x3C00) << 48) | (((uint64_t) 0x3C00) << 32));

  Color e_gamma = {{{ 0.1f, 0.2f, 0.3f }}};
  EXPECT_EQ(colorToRgbaF16(e_gamma), 0x3C0034CD32662E66);
}

TEST_F(GainMapMathTest, Float32ToFloat16) {
  EXPECT_EQ(floatToHalf(0.1f), 0x2E66);
  EXPECT_EQ(floatToHalf(0.0f), 0x0);
  EXPECT_EQ(floatToHalf(1.0f), 0x3C00);
  EXPECT_EQ(floatToHalf(-1.0f), 0xBC00);
  EXPECT_EQ(floatToHalf(0x1.fffffep127f), 0x7FFF);  // float max
  EXPECT_EQ(floatToHalf(-0x1.fffffep127f), 0xFFFF);  // float min
  EXPECT_EQ(floatToHalf(0x1.0p-126f), 0x0);  // float zero
}

TEST_F(GainMapMathTest, GenerateMapLuminanceSrgb) {
  EXPECT_FLOAT_EQ(SrgbYuvToLuminance(YuvBlack(), srgbLuminance),
                  0.0f);
  EXPECT_FLOAT_EQ(SrgbYuvToLuminance(YuvWhite(), srgbLuminance),
                  kSdrWhiteNits);
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvRed(), srgbLuminance),
              srgbLuminance(RgbRed()) * kSdrWhiteNits, LuminanceEpsilon());
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvGreen(), srgbLuminance),
              srgbLuminance(RgbGreen()) * kSdrWhiteNits, LuminanceEpsilon());
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvBlue(), srgbLuminance),
              srgbLuminance(RgbBlue()) * kSdrWhiteNits, LuminanceEpsilon());
}

TEST_F(GainMapMathTest, GenerateMapLuminanceSrgbP3) {
  EXPECT_FLOAT_EQ(SrgbYuvToLuminance(YuvBlack(), p3Luminance),
                  0.0f);
  EXPECT_FLOAT_EQ(SrgbYuvToLuminance(YuvWhite(), p3Luminance),
                  kSdrWhiteNits);
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvRed(), p3Luminance),
              p3Luminance(RgbRed()) * kSdrWhiteNits, LuminanceEpsilon());
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvGreen(), p3Luminance),
              p3Luminance(RgbGreen()) * kSdrWhiteNits, LuminanceEpsilon());
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvBlue(), p3Luminance),
              p3Luminance(RgbBlue()) * kSdrWhiteNits, LuminanceEpsilon());
}

TEST_F(GainMapMathTest, GenerateMapLuminanceSrgbBt2100) {
  EXPECT_FLOAT_EQ(SrgbYuvToLuminance(YuvBlack(), bt2100Luminance),
                  0.0f);
  EXPECT_FLOAT_EQ(SrgbYuvToLuminance(YuvWhite(), bt2100Luminance),
                  kSdrWhiteNits);
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvRed(), bt2100Luminance),
              bt2100Luminance(RgbRed()) * kSdrWhiteNits, LuminanceEpsilon());
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvGreen(), bt2100Luminance),
              bt2100Luminance(RgbGreen()) * kSdrWhiteNits, LuminanceEpsilon());
  EXPECT_NEAR(SrgbYuvToLuminance(SrgbYuvBlue(), bt2100Luminance),
              bt2100Luminance(RgbBlue()) * kSdrWhiteNits, LuminanceEpsilon());
}

TEST_F(GainMapMathTest, GenerateMapLuminanceHlg) {
  EXPECT_FLOAT_EQ(Bt2100YuvToLuminance(YuvBlack(), hlgInvOetf, identityConversion,
                                       bt2100Luminance, kHlgMaxNits),
                  0.0f);
  EXPECT_FLOAT_EQ(Bt2100YuvToLuminance(YuvWhite(), hlgInvOetf, identityConversion,
                                       bt2100Luminance, kHlgMaxNits),
                  kHlgMaxNits);
  EXPECT_NEAR(Bt2100YuvToLuminance(Bt2100YuvRed(), hlgInvOetf, identityConversion,
                                   bt2100Luminance, kHlgMaxNits),
              bt2100Luminance(RgbRed()) * kHlgMaxNits, LuminanceEpsilon());
  EXPECT_NEAR(Bt2100YuvToLuminance(Bt2100YuvGreen(), hlgInvOetf, identityConversion,
                                   bt2100Luminance, kHlgMaxNits),
              bt2100Luminance(RgbGreen()) * kHlgMaxNits, LuminanceEpsilon());
  EXPECT_NEAR(Bt2100YuvToLuminance(Bt2100YuvBlue(), hlgInvOetf, identityConversion,
                                   bt2100Luminance, kHlgMaxNits),
              bt2100Luminance(RgbBlue()) * kHlgMaxNits, LuminanceEpsilon());
}

TEST_F(GainMapMathTest, GenerateMapLuminancePq) {
  EXPECT_FLOAT_EQ(Bt2100YuvToLuminance(YuvBlack(), pqInvOetf, identityConversion,
                                       bt2100Luminance, kPqMaxNits),
                  0.0f);
  EXPECT_FLOAT_EQ(Bt2100YuvToLuminance(YuvWhite(), pqInvOetf, identityConversion,
                                       bt2100Luminance, kPqMaxNits),
                  kPqMaxNits);
  EXPECT_NEAR(Bt2100YuvToLuminance(Bt2100YuvRed(), pqInvOetf, identityConversion,
                                       bt2100Luminance, kPqMaxNits),
              bt2100Luminance(RgbRed()) * kPqMaxNits, LuminanceEpsilon());
  EXPECT_NEAR(Bt2100YuvToLuminance(Bt2100YuvGreen(), pqInvOetf, identityConversion,
                                       bt2100Luminance, kPqMaxNits),
              bt2100Luminance(RgbGreen()) * kPqMaxNits, LuminanceEpsilon());
  EXPECT_NEAR(Bt2100YuvToLuminance(Bt2100YuvBlue(), pqInvOetf, identityConversion,
                                       bt2100Luminance, kPqMaxNits),
              bt2100Luminance(RgbBlue()) * kPqMaxNits, LuminanceEpsilon());
}

TEST_F(GainMapMathTest, ApplyMap) {
  ultrahdr_metadata_struct metadata = { .maxContentBoost = 8.0f,
                                     .minContentBoost = 1.0f / 8.0f };

  EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata),
                RgbWhite() * 8.0f);
  EXPECT_RGB_EQ(Recover(YuvBlack(), 1.0f, &metadata),
                RgbBlack());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvRed(), 1.0f, &metadata),
                  RgbRed() * 8.0f);
  EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 1.0f, &metadata),
                  RgbGreen() * 8.0f);
  EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 1.0f, &metadata),
                  RgbBlue() * 8.0f);

  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.75f, &metadata),
                RgbWhite() * sqrt(8.0f));
  EXPECT_RGB_EQ(Recover(YuvBlack(), 0.75f, &metadata),
                RgbBlack());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvRed(), 0.75f, &metadata),
                  RgbRed() * sqrt(8.0f));
  EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 0.75f, &metadata),
                  RgbGreen() * sqrt(8.0f));
  EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 0.75f, &metadata),
                  RgbBlue() * sqrt(8.0f));

  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.5f, &metadata),
                RgbWhite());
  EXPECT_RGB_EQ(Recover(YuvBlack(), 0.5f, &metadata),
                RgbBlack());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvRed(), 0.5f, &metadata),
                  RgbRed());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 0.5f, &metadata),
                  RgbGreen());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 0.5f, &metadata),
                  RgbBlue());

  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.25f, &metadata),
                RgbWhite() / sqrt(8.0f));
  EXPECT_RGB_EQ(Recover(YuvBlack(), 0.25f, &metadata),
                RgbBlack());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvRed(), 0.25f, &metadata),
                  RgbRed() / sqrt(8.0f));
  EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 0.25f, &metadata),
                  RgbGreen() / sqrt(8.0f));
  EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 0.25f, &metadata),
                  RgbBlue() / sqrt(8.0f));

  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.0f, &metadata),
                RgbWhite() / 8.0f);
  EXPECT_RGB_EQ(Recover(YuvBlack(), 0.0f, &metadata),
                RgbBlack());
  EXPECT_RGB_CLOSE(Recover(SrgbYuvRed(), 0.0f, &metadata),
                  RgbRed() / 8.0f);
  EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 0.0f, &metadata),
                  RgbGreen() / 8.0f);
  EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 0.0f, &metadata),
                  RgbBlue() / 8.0f);

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 1.0f;

  EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata),
                RgbWhite() * 8.0f);
  EXPECT_RGB_EQ(Recover(YuvWhite(), 2.0f / 3.0f, &metadata),
                RgbWhite() * 4.0f);
  EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f / 3.0f, &metadata),
                RgbWhite() * 2.0f);
  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.0f, &metadata),
                RgbWhite());

  metadata.maxContentBoost = 8.0f;
  metadata.minContentBoost = 0.5f;;

  EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata),
                RgbWhite() * 8.0f);
  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.75, &metadata),
                RgbWhite() * 4.0f);
  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.5f, &metadata),
                RgbWhite() * 2.0f);
  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.25f, &metadata),
                RgbWhite());
  EXPECT_RGB_EQ(Recover(YuvWhite(), 0.0f, &metadata),
                RgbWhite() / 2.0f);
}

} // namespace android::ultrahdr
