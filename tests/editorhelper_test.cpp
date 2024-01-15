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

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>

#include "ultrahdr/editorhelper.h"
#include "ultrahdr/jpegr.h"

//#define DUMP_OUTPUT

#ifdef DUMP_OUTPUT
static bool writeFile(const char* filename, void*& result, int length) {
  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    ofd.write(static_cast<char*>(result), length);
    return true;
  }
  std::cerr << "unable to write to file : " << filename << std::endl;
  return false;
}
#endif

namespace ultrahdr {

#ifdef __ANDROID__
#define YUV_IMAGE "/data/local/tmp/minnie-320x240.yu12"
#define GREY_IMAGE "/data/local/tmp/minnie-320x240.y"
#else
#define YUV_IMAGE "./data/minnie-320x240.yu12"
#define GREY_IMAGE "./data/minnie-320x240.y"
#endif
#define IMAGE_WIDTH 320
#define IMAGE_HEIGHT 240

class EditorHelperTest : public testing::Test {
 public:
  struct Image {
    std::unique_ptr<uint8_t[]> buffer;
    size_t size;
  };
  EditorHelperTest();
  ~EditorHelperTest();

 protected:
  virtual void SetUp();
  virtual void TearDown();

  Image mYuvImage, mGreyImage;
};

EditorHelperTest::EditorHelperTest() {}

EditorHelperTest::~EditorHelperTest() {}

static bool loadFile(const char filename[], EditorHelperTest::Image* result) {
  std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
  if (ifd.good()) {
    int size = ifd.tellg();
    ifd.seekg(0, std::ios::beg);
    result->buffer.reset(new uint8_t[size]);
    ifd.read(reinterpret_cast<char*>(result->buffer.get()), size);
    ifd.close();
    result->size = size;
    return true;
  }
  return false;
}

void EditorHelperTest::SetUp() {
  if (!loadFile(YUV_IMAGE, &mYuvImage)) {
    FAIL() << "Load file " << YUV_IMAGE << " failed";
  }
  if (!loadFile(GREY_IMAGE, &mGreyImage)) {
    FAIL() << "Load file " << GREY_IMAGE << " failed";
  }
}

void EditorHelperTest::TearDown() {}

TEST_F(EditorHelperTest, croppingYuvImage) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;
  const int left = 10;
  const int right = 99;
  const int top = 20;
  const int bottom = 199;
  int out_width = right - left + 1;
  int out_height = bottom - top + 1;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = out_width * out_height * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(crop(&in_img, left, right, top, bottom, &out_img) == UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = out_width);
  EXPECT_TRUE(out_img.height = out_height);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("cropped.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, croppingGreyImage) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;
  const int left = 10;
  const int right = 99;
  const int top = 20;
  const int bottom = 199;
  int out_width = right - left + 1;
  int out_height = bottom - top + 1;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = out_width * out_height;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(crop(&in_img, left, right, top, bottom, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = out_width);
  EXPECT_TRUE(out_img.height = out_height);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("cropped.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, mirroringYuvImageVertical) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(mirror(&in_img, ULTRAHDR_MIRROR_VERTICAL, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.height = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("mirrored_vertical.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, mirroringYuvImageHorizontal) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(mirror(&in_img, ULTRAHDR_MIRROR_HORIZONTAL, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.height = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("mirrored_horizontal.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, mirroringGreyImageVertical) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(mirror(&in_img, ULTRAHDR_MIRROR_VERTICAL, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.height = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("mirrored_vertical.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, mirroringGreyImageHorizontal) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(mirror(&in_img, ULTRAHDR_MIRROR_HORIZONTAL, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.height = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("mirrored_horizontal.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, rotatingYuvImage90) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(rotate(&in_img, 90, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.height = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("rotated_90.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, rotatingYuvImage180) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(rotate(&in_img, 180, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.height = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("rotated_180.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, rotatingYuvImage270) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(rotate(&in_img, 270, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.height = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("rotated_270.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, rotatingGreyImage90) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(rotate(&in_img, 90, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.height = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("rotated_90.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, rotatingGreyImage180) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(rotate(&in_img, 180, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.height = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("rotated_180.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, rotatingGreyImage270) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int outSize = IMAGE_WIDTH * IMAGE_HEIGHT;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(rotate(&in_img, 270, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = IMAGE_HEIGHT);
  EXPECT_TRUE(out_img.height = IMAGE_WIDTH);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("rotated_270.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, resizeYuvImageUp) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int out_width = IMAGE_WIDTH * 3 / 2;
  int out_height = IMAGE_HEIGHT * 3 / 2;
  int outSize = out_width * out_height * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(resize(&in_img, out_width, out_height, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = out_width);
  EXPECT_TRUE(out_img.height = out_height);
  EXPECT_TRUE(out_img.colorGamut == in_img.colorGamut);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("resize_up.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, resizeYuvImageDown) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mYuvImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_YUV420;

  std::unique_ptr<uint8_t[]> out_img_data;
  int out_width = IMAGE_WIDTH * 2 / 3;
  int out_height = IMAGE_HEIGHT * 2 / 3;
  int outSize = out_width * out_height * 3 / 2;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(resize(&in_img, out_width, out_height, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = out_width);
  EXPECT_TRUE(out_img.height = out_height);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("resize_down.yuv", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, resizeGreyImageUp) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int out_width = IMAGE_WIDTH * 3 / 2;
  int out_height = IMAGE_HEIGHT * 3 / 2;
  int outSize = out_width * out_height;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(resize(&in_img, out_width, out_height, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = out_width);
  EXPECT_TRUE(out_img.height = out_height);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("resize_up.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_F(EditorHelperTest, resizeGreyImageDown) {
  jpegr_uncompressed_struct in_img;
  jpegr_uncompressed_struct out_img;

  in_img.data = mGreyImage.buffer.get();
  in_img.width = IMAGE_WIDTH;
  in_img.height = IMAGE_HEIGHT;
  in_img.pixelFormat = ultrahdr_pixel_format::ULTRAHDR_PIX_FMT_MONOCHROME;

  std::unique_ptr<uint8_t[]> out_img_data;
  int out_width = IMAGE_WIDTH * 2 / 3;
  int out_height = IMAGE_HEIGHT * 2 / 3;
  int outSize = out_width * out_height;
  out_img_data.reset(new uint8_t[outSize]);
  out_img.data = out_img_data.get();
  EXPECT_TRUE(resize(&in_img, out_width, out_height, &out_img)== UHDR_NO_ERROR);
  EXPECT_TRUE(out_img.width = out_width);
  EXPECT_TRUE(out_img.height = out_height);
  EXPECT_TRUE(out_img.pixelFormat == in_img.pixelFormat);
#ifdef DUMP_OUTPUT
  if (!writeFile("resize_down.y", out_img.data, outSize)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}
}  // namespace ultrahdr
