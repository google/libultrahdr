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

#include <ultrahdr/jpegr.h>
#include <ultrahdr/jpegrutils.h>
#include <ultrahdr/gainmapmath.h>
#include <fcntl.h>
#include <fstream>
#include <gtest/gtest.h>
#include <sys/time.h>
#include <utils/Log.h>

#define RAW_P010_IMAGE "/sdcard/Documents/raw_p010_image.p010"
#define RAW_P010_IMAGE_WITH_STRIDE "/sdcard/Documents/raw_p010_image_with_stride.p010"
#define RAW_YUV420_IMAGE "/sdcard/Documents/raw_yuv420_image.yuv420"
#define JPEG_IMAGE "/sdcard/Documents/jpeg_image.jpg"
#define TEST_IMAGE_WIDTH 1280
#define TEST_IMAGE_HEIGHT 720
#define TEST_IMAGE_STRIDE 1288
#define DEFAULT_JPEG_QUALITY 90

#define SAVE_ENCODING_RESULT true
#define SAVE_DECODING_RESULT true
#define SAVE_INPUT_RGBA true

namespace android::ultrahdr {

struct Timer {
  struct timeval StartingTime;
  struct timeval EndingTime;
  struct timeval ElapsedMicroseconds;
};

void timerStart(Timer *t) {
  gettimeofday(&t->StartingTime, nullptr);
}

void timerStop(Timer *t) {
  gettimeofday(&t->EndingTime, nullptr);
}

int64_t elapsedTime(Timer *t) {
  t->ElapsedMicroseconds.tv_sec = t->EndingTime.tv_sec - t->StartingTime.tv_sec;
  t->ElapsedMicroseconds.tv_usec = t->EndingTime.tv_usec - t->StartingTime.tv_usec;
  return t->ElapsedMicroseconds.tv_sec * 1000000 + t->ElapsedMicroseconds.tv_usec;
}

static size_t getFileSize(int fd) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    ALOGW("%s : fstat failed", __func__);
    return 0;
  }
  return st.st_size; // bytes
}

static bool loadFile(const char filename[], void*& result, int* fileLength) {
  int fd = open(filename, O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  int length = getFileSize(fd);
  if (length == 0) {
    close(fd);
    return false;
  }
  if (fileLength != nullptr) {
    *fileLength = length;
  }
  result = malloc(length);
  if (read(fd, result, length) != static_cast<ssize_t>(length)) {
    close(fd);
    return false;
  }
  close(fd);
  return true;
}

static bool loadP010Image(const char *filename, jr_uncompressed_ptr img,
                          bool isUVContiguous) {
  int fd = open(filename, O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  const int bpp = 2;
  int lumaStride = img->luma_stride == 0 ? img->width : img->luma_stride;
  int lumaSize = bpp * lumaStride * img->height;
  int chromaSize = bpp * (img->height / 2) *
                   (isUVContiguous ? lumaStride : img->chroma_stride);
  img->data = malloc(lumaSize + (isUVContiguous ? chromaSize : 0));
  if (img->data == nullptr) {
    ALOGE("loadP010Image(): failed to allocate memory for luma data.");
    return false;
  }
  uint8_t *mem = static_cast<uint8_t *>(img->data);
  for (int i = 0; i < img->height; i++) {
    if (read(fd, mem, img->width * bpp) != img->width * bpp) {
      close(fd);
      return false;
    }
    mem += lumaStride * bpp;
  }
  int chromaStride = lumaStride;
  if (!isUVContiguous) {
    img->chroma_data = malloc(chromaSize);
    if (img->chroma_data == nullptr) {
      ALOGE("loadP010Image(): failed to allocate memory for chroma data.");
      return false;
    }
    mem = static_cast<uint8_t *>(img->chroma_data);
    chromaStride = img->chroma_stride;
  }
  for (int i = 0; i < img->height / 2; i++) {
    if (read(fd, mem, img->width * bpp) != img->width * bpp) {
      close(fd);
      return false;
    }
    mem += chromaStride * bpp;
  }
  close(fd);
  return true;
}

class JpegRTest : public testing::Test {
public:
  JpegRTest();
  ~JpegRTest();

protected:
  virtual void SetUp();
  virtual void TearDown();

  struct jpegr_uncompressed_struct mRawP010Image{};
  struct jpegr_uncompressed_struct mRawP010ImageWithStride{};
  struct jpegr_uncompressed_struct mRawP010ImageWithChromaData{};
  struct jpegr_uncompressed_struct mRawYuv420Image{};
  struct jpegr_compressed_struct mJpegImage{};
};

JpegRTest::JpegRTest() {}
JpegRTest::~JpegRTest() {}

void JpegRTest::SetUp() {}
void JpegRTest::TearDown() {
  free(mRawP010Image.data);
  free(mRawP010Image.chroma_data);
  free(mRawP010ImageWithStride.data);
  free(mRawP010ImageWithStride.chroma_data);
  free(mRawP010ImageWithChromaData.data);
  free(mRawP010ImageWithChromaData.chroma_data);
  free(mRawYuv420Image.data);
  free(mJpegImage.data);
}

class JpegRBenchmark : public JpegR {
public:
 void BenchmarkGenerateGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr p010Image,
                               ultrahdr_metadata_ptr metadata, jr_uncompressed_ptr map);
 void BenchmarkApplyGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr map,
                            ultrahdr_metadata_ptr metadata, jr_uncompressed_ptr dest);
private:
 const int kProfileCount = 10;
};

void JpegRBenchmark::BenchmarkGenerateGainMap(jr_uncompressed_ptr yuv420Image,
                                              jr_uncompressed_ptr p010Image,
                                              ultrahdr_metadata_ptr metadata,
                                              jr_uncompressed_ptr map) {
  ASSERT_EQ(yuv420Image->width, p010Image->width);
  ASSERT_EQ(yuv420Image->height, p010Image->height);

  Timer genRecMapTime;

  timerStart(&genRecMapTime);
  for (auto i = 0; i < kProfileCount; i++) {
      ASSERT_EQ(OK, generateGainMap(
          yuv420Image, p010Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, metadata, map));
      if (i != kProfileCount - 1) delete[] static_cast<uint8_t *>(map->data);
  }
  timerStop(&genRecMapTime);

  ALOGE("Generate Gain Map:- Res = %i x %i, time = %f ms",
        yuv420Image->width, yuv420Image->height,
        elapsedTime(&genRecMapTime) / (kProfileCount * 1000.f));

}

void JpegRBenchmark::BenchmarkApplyGainMap(jr_uncompressed_ptr yuv420Image,
                                           jr_uncompressed_ptr map,
                                           ultrahdr_metadata_ptr metadata,
                                           jr_uncompressed_ptr dest) {
  Timer applyRecMapTime;

  timerStart(&applyRecMapTime);
  for (auto i = 0; i < kProfileCount; i++) {
      ASSERT_EQ(OK, applyGainMap(yuv420Image, map, metadata, ULTRAHDR_OUTPUT_HDR_HLG,
                                 metadata->maxContentBoost /* displayBoost */, dest));
  }
  timerStop(&applyRecMapTime);

  ALOGE("Apply Gain Map:- Res = %i x %i, time = %f ms",
        yuv420Image->width, yuv420Image->height,
        elapsedTime(&applyRecMapTime) / (kProfileCount * 1000.f));
}

TEST_F(JpegRTest, build) {
  // Force all of the gain map lib to be linked by calling all public functions.
  JpegR jpegRCodec;
  jpegRCodec.encodeJPEGR(nullptr, static_cast<ultrahdr_transfer_function>(0), nullptr, 0, nullptr);
  jpegRCodec.encodeJPEGR(nullptr, nullptr, static_cast<ultrahdr_transfer_function>(0),
                         nullptr, 0, nullptr);
  jpegRCodec.encodeJPEGR(nullptr, nullptr, nullptr, static_cast<ultrahdr_transfer_function>(0),
                         nullptr);
  jpegRCodec.encodeJPEGR(nullptr, nullptr, static_cast<ultrahdr_transfer_function>(0), nullptr);
  jpegRCodec.decodeJPEGR(nullptr, nullptr);
}

/* Test Encode API-0 invalid arguments */
TEST_F(JpegRTest, encodeAPI0ForInvalidArgs) {
  int ret;

  // we are not really compressing anything so lets keep allocs to a minimum
  jpegr_compressed_struct jpegR;
  jpegR.maxLength = 16 * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);

  JpegR jpegRCodec;

  // we are not really compressing anything so lets keep allocs to a minimum
  mRawP010ImageWithStride.data = malloc(16);
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  // test quality factor
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      -1, nullptr)) << "fail, API allows bad jpeg quality factor";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      101, nullptr)) << "fail, API allows bad jpeg quality factor";

  // test hdr transfer function
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride,
      static_cast<ultrahdr_transfer_function>(ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride,
      static_cast<ultrahdr_transfer_function>(-10),
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad hdr transfer function";

  // test dest
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows nullptr dest";

  // test p010 input
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      nullptr, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows nullptr p010 image";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = static_cast<ultrahdr_color_gamut>(
      ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH - 1;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT - 1;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = 0;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = 0;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad luma stride";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.chroma_data = mRawP010ImageWithStride.data;
  mRawP010ImageWithStride.chroma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad chroma stride";

  mRawP010ImageWithStride.chroma_data = nullptr;

  free(jpegR.data);
}

/* Test Encode API-1 invalid arguments */
TEST_F(JpegRTest, encodeAPI1ForInvalidArgs) {
  int ret;

  // we are not really compressing anything so lets keep allocs to a minimum
  jpegr_compressed_struct jpegR;
  jpegR.maxLength = 16 * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);

  JpegR jpegRCodec;

  // we are not really compressing anything so lets keep allocs to a minimum
  mRawP010ImageWithStride.data = malloc(16);
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  // we are not really compressing anything so lets keep allocs to a minimum
  mRawYuv420Image.data = malloc(16);
  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  // test quality factor
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, -1, nullptr)) << "fail, API allows bad jpeg quality factor";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, 101, nullptr)) << "fail, API allows bad jpeg quality factor";

  // test hdr transfer function
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image,
      ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED, &jpegR, DEFAULT_JPEG_QUALITY,
      nullptr)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image,
      static_cast<ultrahdr_transfer_function>(ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image,
      static_cast<ultrahdr_transfer_function>(-10),
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad hdr transfer function";

  // test dest
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      nullptr, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows nullptr dest";

  // test p010 input
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      nullptr, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows nullptr p010 image";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = static_cast<ultrahdr_color_gamut>(
      ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH - 1;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT - 1;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = 0;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = 0;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad luma stride";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.chroma_data = mRawP010ImageWithStride.data;
  mRawP010ImageWithStride.chroma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad chroma stride";

  // test 420 input
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.chroma_data = nullptr;
  mRawP010ImageWithStride.chroma_stride = 0;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, nullptr, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows nullptr for 420 image";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad 420 image width";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH - 2;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad 420 image height";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.luma_stride = TEST_IMAGE_STRIDE;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad luma stride for 420";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.luma_stride = 0;
  mRawYuv420Image.chroma_data = mRawYuv420Image.data;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows chroma pointer for 420";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.luma_stride = 0;
  mRawYuv420Image.chroma_data = nullptr;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad 420 color gamut";

  mRawYuv420Image.colorGamut = static_cast<ultrahdr_color_gamut>(
      ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR, DEFAULT_JPEG_QUALITY, nullptr)) << "fail, API allows bad 420 color gamut";

  free(jpegR.data);
}

/* Test Encode API-2 invalid arguments */
TEST_F(JpegRTest, encodeAPI2ForInvalidArgs) {
  int ret;

  // we are not really compressing anything so lets keep allocs to a minimum
  jpegr_compressed_struct jpegR;
  jpegR.maxLength = 16 * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);

  JpegR jpegRCodec;

  // we are not really compressing anything so lets keep allocs to a minimum
  mRawP010ImageWithStride.data = malloc(16);
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  // we are not really compressing anything so lets keep allocs to a minimum
  mRawYuv420Image.data = malloc(16);
  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  // test hdr transfer function
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
      &jpegR)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      static_cast<ultrahdr_transfer_function>(ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
      &jpegR)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      static_cast<ultrahdr_transfer_function>(-10),
      &jpegR)) << "fail, API allows bad hdr transfer function";

  // test dest
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG, nullptr)) << "fail, API allows nullptr dest";

  // test p010 input
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      nullptr, &mRawYuv420Image, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows nullptr p010 image";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = static_cast<ultrahdr_color_gamut>(
      ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH - 1;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT - 1;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = 0;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = 0;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR)) << "fail, API allows bad luma stride";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.chroma_data = mRawP010ImageWithStride.data;
  mRawP010ImageWithStride.chroma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad chroma stride";

  // test 420 input
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.chroma_data = nullptr;
  mRawP010ImageWithStride.chroma_stride = 0;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, nullptr, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows nullptr for 420 image";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad 420 image width";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH - 2;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad 420 image height";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.luma_stride = TEST_IMAGE_STRIDE;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad luma stride for 420";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.luma_stride = 0;
  mRawYuv420Image.chroma_data = mRawYuv420Image.data;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows chroma pointer for 420";

  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.luma_stride = 0;
  mRawYuv420Image.chroma_data = nullptr;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad 420 color gamut";

  mRawYuv420Image.colorGamut = static_cast<ultrahdr_color_gamut>(
      ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, &jpegR,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad 420 color gamut";

  // bad compressed image
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &mRawYuv420Image, nullptr,
      ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad 420 color gamut";

  free(jpegR.data);
}

/* Test Encode API-3 invalid arguments */
TEST_F(JpegRTest, encodeAPI3ForInvalidArgs) {
  int ret;

  // we are not really compressing anything so lets keep allocs to a minimum
  jpegr_compressed_struct jpegR;
  jpegR.maxLength = 16 * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);

  JpegR jpegRCodec;

  // we are not really compressing anything so lets keep allocs to a minimum
  mRawP010ImageWithStride.data = malloc(16);
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  // test hdr transfer function
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_UNSPECIFIED,
      &jpegR)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR,
      static_cast<ultrahdr_transfer_function>(ultrahdr_transfer_function::ULTRAHDR_TF_MAX + 1),
      &jpegR)) << "fail, API allows bad hdr transfer function";

  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, static_cast<ultrahdr_transfer_function>(-10),
      &jpegR)) << "fail, API allows bad hdr transfer function";

  // test dest
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      nullptr)) << "fail, API allows nullptr dest";

  // test p010 input
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      nullptr, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows nullptr p010 image";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = static_cast<ultrahdr_color_gamut>(
      ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_MAX + 1);
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad p010 color gamut";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH - 1;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT - 1;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = 0;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad image width";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = 0;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad image height";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad luma stride";

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.chroma_data = mRawP010ImageWithStride.data;
  mRawP010ImageWithStride.chroma_stride = TEST_IMAGE_WIDTH - 2;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, &jpegR, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad chroma stride";
  mRawP010ImageWithStride.chroma_data = nullptr;

  // bad compressed image
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, nullptr, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR)) << "fail, API allows bad 420 color gamut";

  free(jpegR.data);
}

/* Test Encode API-4 invalid arguments */
TEST_F(JpegRTest, encodeAPI4ForInvalidArgs) {
  int ret;

  // we are not really compressing anything so lets keep allocs to a minimum
  jpegr_compressed_struct jpegR;
  jpegR.maxLength = 16 * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);

  JpegR jpegRCodec;

  // test dest
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, &jpegR, nullptr, nullptr)) << "fail, API allows nullptr dest";

  // test primary image
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      nullptr, &jpegR, nullptr, &jpegR)) << "fail, API allows nullptr primary image";

  // test gain map
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, nullptr, &jpegR)) << "fail, API allows nullptr gainmap image";

  // test metadata
  ultrahdr_metadata_struct good_metadata;
  good_metadata.version = "1.0";
  good_metadata.minContentBoost = 1.0f;
  good_metadata.maxContentBoost = 2.0f;
  good_metadata.gamma = 1.0f;
  good_metadata.offsetSdr = 0.0f;
  good_metadata.offsetHdr = 0.0f;
  good_metadata.hdrCapacityMin = 1.0f;
  good_metadata.hdrCapacityMax = 2.0f;

  ultrahdr_metadata_struct metadata = good_metadata;
  metadata.version = "1.1";
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata version";

  metadata = good_metadata;
  metadata.minContentBoost = 3.0f;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata content boost";

  metadata = good_metadata;
  metadata.gamma = -0.1f;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata gamma";

  metadata = good_metadata;
  metadata.offsetSdr = -0.1f;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata offset sdr";

  metadata = good_metadata;
  metadata.offsetHdr = -0.1f;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata offset hdr";

  metadata = good_metadata;
  metadata.hdrCapacityMax = 0.5f;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata hdr capacity max";

  metadata = good_metadata;
  metadata.hdrCapacityMin = 0.5f;
  EXPECT_NE(OK, jpegRCodec.encodeJPEGR(
      &jpegR, nullptr, &metadata, &jpegR)) << "fail, API allows bad metadata hdr capacity min";

  free(jpegR.data);
}

/* Test Decode API invalid arguments */
TEST_F(JpegRTest, decodeAPIForInvalidArgs) {
  int ret;

  // we are not really compressing anything so lets keep allocs to a minimum
  jpegr_compressed_struct jpegR;
  jpegR.maxLength = 16 * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);

  // we are not really decoding anything so lets keep allocs to a minimum
  mRawP010Image.data = malloc(16);

  JpegR jpegRCodec;

  // test jpegr image
  EXPECT_NE(OK, jpegRCodec.decodeJPEGR(
        nullptr, &mRawP010Image)) << "fail, API allows nullptr for jpegr img";

  // test dest image
  EXPECT_NE(OK, jpegRCodec.decodeJPEGR(
        &jpegR, nullptr)) << "fail, API allows nullptr for dest";

  // test max display boost
  EXPECT_NE(OK, jpegRCodec.decodeJPEGR(
        &jpegR, &mRawP010Image, 0.5)) << "fail, API allows invalid max display boost";

  // test output format
  EXPECT_NE(OK, jpegRCodec.decodeJPEGR(
        &jpegR, &mRawP010Image, 0.5, nullptr,
        static_cast<ultrahdr_output_format>(-1))) << "fail, API allows invalid output format";

  EXPECT_NE(OK, jpegRCodec.decodeJPEGR(
        &jpegR, &mRawP010Image, 0.5, nullptr,
        static_cast<ultrahdr_output_format>(ULTRAHDR_OUTPUT_MAX + 1)))
        << "fail, API allows invalid output format";

  free(jpegR.data);
}

TEST_F(JpegRTest, writeXmpThenRead) {
  ultrahdr_metadata_struct metadata_expected;
  metadata_expected.version = "1.0";
  metadata_expected.maxContentBoost = 1.25f;
  metadata_expected.minContentBoost = 0.75f;
  metadata_expected.gamma = 1.0f;
  metadata_expected.offsetSdr = 0.0f;
  metadata_expected.offsetHdr = 0.0f;
  metadata_expected.hdrCapacityMin = 1.0f;
  metadata_expected.hdrCapacityMax = metadata_expected.maxContentBoost;
  const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
  const int nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator

  std::string xmp = generateXmpForSecondaryImage(metadata_expected);

  std::vector<uint8_t> xmpData;
  xmpData.reserve(nameSpaceLength + xmp.size());
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(nameSpace.c_str()),
                  reinterpret_cast<const uint8_t*>(nameSpace.c_str()) + nameSpaceLength);
  xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(xmp.c_str()),
                  reinterpret_cast<const uint8_t*>(xmp.c_str()) + xmp.size());

  ultrahdr_metadata_struct metadata_read;
  EXPECT_TRUE(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read));
  EXPECT_FLOAT_EQ(metadata_expected.maxContentBoost, metadata_read.maxContentBoost);
  EXPECT_FLOAT_EQ(metadata_expected.minContentBoost, metadata_read.minContentBoost);
  EXPECT_FLOAT_EQ(metadata_expected.gamma, metadata_read.gamma);
  EXPECT_FLOAT_EQ(metadata_expected.offsetSdr, metadata_read.offsetSdr);
  EXPECT_FLOAT_EQ(metadata_expected.offsetHdr, metadata_read.offsetHdr);
  EXPECT_FLOAT_EQ(metadata_expected.hdrCapacityMin, metadata_read.hdrCapacityMin);
  EXPECT_FLOAT_EQ(metadata_expected.hdrCapacityMax, metadata_read.hdrCapacityMax);
}

/* Test Encode API-0 */
TEST_F(JpegRTest, encodeFromP010) {
  int ret;

  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  // Load input files.
  if (!loadP010Image(RAW_P010_IMAGE, &mRawP010Image, true)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR, DEFAULT_JPEG_QUALITY,
      nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }

  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_WIDTH + 128;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  // Load input files.
  if (!loadP010Image(RAW_P010_IMAGE, &mRawP010ImageWithStride, true)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }

  jpegr_compressed_struct jpegRWithStride;
  jpegRWithStride.maxLength = jpegR.length;
  jpegRWithStride.data = malloc(jpegRWithStride.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegRWithStride,
      DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  ASSERT_EQ(jpegR.length, jpegRWithStride.length)
      << "Same input is yielding different output";
  ASSERT_EQ(0, memcmp(jpegR.data, jpegRWithStride.data, jpegR.length))
      << "Same input is yielding different output";

  mRawP010ImageWithChromaData.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithChromaData.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithChromaData.luma_stride = TEST_IMAGE_WIDTH + 64;
  mRawP010ImageWithChromaData.chroma_stride = TEST_IMAGE_WIDTH + 256;
  mRawP010ImageWithChromaData.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;
  // Load input files.
  if (!loadP010Image(RAW_P010_IMAGE, &mRawP010ImageWithChromaData, false)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  jpegr_compressed_struct jpegRWithChromaData;
  jpegRWithChromaData.maxLength = jpegR.length;
  jpegRWithChromaData.data = malloc(jpegRWithChromaData.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithChromaData, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegRWithChromaData, DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  ASSERT_EQ(jpegR.length, jpegRWithChromaData.length)
      << "Same input is yielding different output";
  ASSERT_EQ(0, memcmp(jpegR.data, jpegRWithChromaData.data, jpegR.length))
      << "Same input is yielding different output";

  free(jpegR.data);
  free(jpegRWithStride.data);
  free(jpegRWithChromaData.data);
}

/* Test Encode API-0 and decode */
TEST_F(JpegRTest, encodeFromP010ThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR, DEFAULT_JPEG_QUALITY,
      nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-0 (with stride) and decode */
TEST_F(JpegRTest, encodeFromP010WithStrideThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE_WITH_STRIDE, mRawP010ImageWithStride.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE_WITH_STRIDE << " failed";
  }
  mRawP010ImageWithStride.width = TEST_IMAGE_WIDTH;
  mRawP010ImageWithStride.height = TEST_IMAGE_HEIGHT;
  mRawP010ImageWithStride.luma_stride = TEST_IMAGE_STRIDE;
  mRawP010ImageWithStride.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010ImageWithStride, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-1 and decode */
TEST_F(JpegRTest, encodeFromRawHdrAndSdrThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  if (!loadFile(RAW_YUV420_IMAGE, mRawYuv420Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, &mRawYuv420Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR,
      DEFAULT_JPEG_QUALITY, nullptr);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_yuv420p_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_yuv420p_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-2 and decode */
TEST_F(JpegRTest, encodeFromRawHdrAndSdrAndJpegThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  if (!loadFile(RAW_YUV420_IMAGE, mRawYuv420Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawYuv420Image.width = TEST_IMAGE_WIDTH;
  mRawYuv420Image.height = TEST_IMAGE_HEIGHT;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  if (!loadFile(JPEG_IMAGE, mJpegImage.data, &mJpegImage.length)) {
    FAIL() << "Load file " << JPEG_IMAGE << " failed";
  }
  mJpegImage.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, &mRawYuv420Image, &mJpegImage, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
      &jpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_yuv420p_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_yuv420p_jpeg_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

/* Test Encode API-3 and decode */
TEST_F(JpegRTest, encodeFromJpegThenDecode) {
  int ret;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = TEST_IMAGE_WIDTH;
  mRawP010Image.height = TEST_IMAGE_HEIGHT;
  mRawP010Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  if (SAVE_INPUT_RGBA) {
    size_t rgbaSize = mRawP010Image.width * mRawP010Image.height * sizeof(uint32_t);
    uint32_t *data = (uint32_t *)malloc(rgbaSize);

    for (size_t y = 0; y < mRawP010Image.height; ++y) {
      for (size_t x = 0; x < mRawP010Image.width; ++x) {
        Color hdr_yuv_gamma = getP010Pixel(&mRawP010Image, x, y);
        Color hdr_rgb_gamma = bt2100YuvToRgb(hdr_yuv_gamma);
        uint32_t rgba1010102 = colorToRgba1010102(hdr_rgb_gamma);
        size_t pixel_idx =  x + y * mRawP010Image.width;
        reinterpret_cast<uint32_t*>(data)[pixel_idx] = rgba1010102;
      }
    }

    // Output image data to file
    std::string filePath = "/sdcard/Documents/input_from_p010.rgb10";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)data, rgbaSize);
    free(data);
  }
  if (!loadFile(JPEG_IMAGE, mJpegImage.data, &mJpegImage.length)) {
    FAIL() << "Load file " << JPEG_IMAGE << " failed";
  }
  mJpegImage.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  JpegR jpegRCodec;

  jpegr_compressed_struct jpegR;
  jpegR.maxLength = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * sizeof(uint8_t);
  jpegR.data = malloc(jpegR.maxLength);
  ret = jpegRCodec.encodeJPEGR(
      &mRawP010Image, &mJpegImage, ultrahdr_transfer_function::ULTRAHDR_TF_HLG, &jpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_ENCODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/encoded_from_p010_jpeg_input.jpgr";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)jpegR.data, jpegR.length);
  }

  jpegr_uncompressed_struct decodedJpegR;
  int decodedJpegRSize = TEST_IMAGE_WIDTH * TEST_IMAGE_HEIGHT * 8;
  decodedJpegR.data = malloc(decodedJpegRSize);
  ret = jpegRCodec.decodeJPEGR(&jpegR, &decodedJpegR);
  if (ret != OK) {
    FAIL() << "Error code is " << ret;
  }
  if (SAVE_DECODING_RESULT) {
    // Output image data to file
    std::string filePath = "/sdcard/Documents/decoded_from_p010_jpeg_input.rgb";
    std::ofstream imageFile(filePath.c_str(), std::ofstream::binary);
    if (!imageFile.is_open()) {
      ALOGE("%s: Unable to create file %s", __FUNCTION__, filePath.c_str());
    }
    imageFile.write((const char*)decodedJpegR.data, decodedJpegRSize);
  }

  free(jpegR.data);
  free(decodedJpegR.data);
}

TEST_F(JpegRTest, ProfileGainMapFuncs) {
  const size_t kWidth = TEST_IMAGE_WIDTH;
  const size_t kHeight = TEST_IMAGE_HEIGHT;

  // Load input files.
  if (!loadFile(RAW_P010_IMAGE, mRawP010Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawP010Image.width = kWidth;
  mRawP010Image.height = kHeight;
  mRawP010Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT2100;

  if (!loadFile(RAW_YUV420_IMAGE, mRawYuv420Image.data, nullptr)) {
    FAIL() << "Load file " << RAW_P010_IMAGE << " failed";
  }
  mRawYuv420Image.width = kWidth;
  mRawYuv420Image.height = kHeight;
  mRawYuv420Image.colorGamut = ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709;

  JpegRBenchmark benchmark;

  ultrahdr_metadata_struct metadata = { .version = "1.0" };

  jpegr_uncompressed_struct map = { .data = NULL,
                                    .width = 0,
                                    .height = 0,
                                    .colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED };

  benchmark.BenchmarkGenerateGainMap(&mRawYuv420Image, &mRawP010Image, &metadata, &map);

  const int dstSize = mRawYuv420Image.width * mRawYuv420Image.height * 4;
  auto bufferDst = std::make_unique<uint8_t[]>(dstSize);
  jpegr_uncompressed_struct dest = { .data = bufferDst.get(),
                                     .width = 0,
                                     .height = 0,
                                     .colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED };

  benchmark.BenchmarkApplyGainMap(&mRawYuv420Image, &map, &metadata, &dest);
}

} // namespace android::ultrahdr
