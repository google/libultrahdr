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

// #define DUMP_OUTPUT

#define OUTPUT_P010_IMAGE "output.p010"
#define OUTPUT_YUV_IMAGE "output.yuv"
#define OUTPUT_RGBA_IMAGE "output.rgb"

#ifdef DUMP_OUTPUT
static bool writeFile(std::string prefixName, uhdr_raw_image_t* img) {
  char filename[50];

  if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    snprintf(filename, sizeof filename, "%s_%d_%s", prefixName.c_str(), img->fmt,
             OUTPUT_P010_IMAGE);
  } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420 || img->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    snprintf(filename, sizeof filename, "%s_%d_%s", prefixName.c_str(), img->fmt, OUTPUT_YUV_IMAGE);
  } else if (img->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || img->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
             img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    snprintf(filename, sizeof filename, "%s_%d_%s", prefixName.c_str(), img->fmt,
             OUTPUT_RGBA_IMAGE);
  } else {
    return false;
  }

  std::ofstream ofd(filename, std::ios::binary);
  if (ofd.is_open()) {
    int bpp = 1;

    if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      bpp = 2;
    } else if (img->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
               img->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
      bpp = 4;
    } else if (img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
      bpp = 8;
    }

    const char* data = static_cast<char*>(img->planes[UHDR_PLANE_Y]);
    size_t stride = img->stride[UHDR_PLANE_Y] * bpp;
    size_t length = img->w * bpp;
    for (int i = 0; i < img->h; i++, data += stride) {
      ofd.write(data, length);
    }

    if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      data = static_cast<char*>(img->planes[UHDR_PLANE_UV]);
      size_t stride = img->stride[UHDR_PLANE_UV] * bpp;
      size_t length = img->w * bpp;
      for (int i = 0; i < img->h / 2; i++, data += stride) {
        ofd.write(data, length);
      }
    } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      data = static_cast<char*>(img->planes[UHDR_PLANE_U]);
      size_t stride = img->stride[UHDR_PLANE_U] * bpp;
      size_t length = (img->w / 2) * bpp;
      for (int i = 0; i < img->h / 2; i++, data += stride) {
        ofd.write(data, length);
      }
      data = static_cast<char*>(img->planes[UHDR_PLANE_V]);
      size_t stride = img->stride[UHDR_PLANE_V] * bpp;
      size_t length = (img->w / 2) * bpp;
      for (int i = 0; i < img->h / 2; i++, data += stride) {
        ofd.write(data, length);
      }
    }
    return true;
  }
  std::cerr << "unable to write to file : " << filename << std::endl;
  return false;
}
#endif

namespace ultrahdr {

static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
  std::ifstream ifd(filename, std::ios::binary);
  if (ifd.good()) {
    if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      const int bpp = 2;
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_Y]), handle->w * handle->h * bpp);
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_UV]),
               (handle->w / 2) * (handle->h / 2) * bpp * 2);
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_Y]), handle->w * handle->h);
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_U]), (handle->w / 2) * (handle->h / 2));
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_V]), (handle->w / 2) * (handle->h / 2));
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
               handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ||
               handle->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
      int bpp = handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_PACKED]), handle->w * handle->h * bpp);
      return true;
    } else if (handle->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
      ifd.read(static_cast<char*>(handle->planes[UHDR_PLANE_Y]), handle->w * handle->h);
      return true;
    }
    return false;
  }
  std::cerr << "unable to open file : " << filename << std::endl;
  return false;
}

void initImageHandle(uhdr_raw_image_t* handle, int width, int height, uhdr_img_fmt_t format) {
  handle->fmt = format;
  handle->cg = UHDR_CG_DISPLAY_P3;
  handle->ct = UHDR_CT_SRGB;
  handle->range = UHDR_CR_UNSPECIFIED;
  handle->w = width;
  handle->h = height;
  if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    handle->planes[UHDR_PLANE_Y] = malloc(width * height * 2);
    handle->planes[UHDR_PLANE_UV] = malloc((width / 2) * (height / 2) * 2 * 2);
    handle->planes[UHDR_PLANE_V] = nullptr;
    handle->stride[UHDR_PLANE_Y] = width;
    handle->stride[UHDR_PLANE_UV] = width;
    handle->stride[UHDR_PLANE_V] = 0;
  } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    handle->planes[UHDR_PLANE_Y] = malloc(width * height);
    handle->planes[UHDR_PLANE_U] = malloc((width / 2) * (height / 2));
    handle->planes[UHDR_PLANE_V] = malloc((width / 2) * (height / 2));
    handle->stride[UHDR_PLANE_Y] = width;
    handle->stride[UHDR_PLANE_U] = width / 2;
    handle->stride[UHDR_PLANE_V] = width / 2;
  } else if (handle->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
             handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ||
             handle->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
    int bpp = handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
    handle->planes[UHDR_PLANE_PACKED] = malloc(width * height * bpp);
    handle->planes[UHDR_PLANE_U] = nullptr;
    handle->planes[UHDR_PLANE_V] = nullptr;
    handle->stride[UHDR_PLANE_PACKED] = width;
    handle->stride[UHDR_PLANE_U] = 0;
    handle->stride[UHDR_PLANE_V] = 0;
  } else if (handle->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    handle->planes[UHDR_PLANE_Y] = malloc(width * height);
    handle->planes[UHDR_PLANE_U] = nullptr;
    handle->planes[UHDR_PLANE_V] = nullptr;
    handle->stride[UHDR_PLANE_Y] = width;
    handle->stride[UHDR_PLANE_U] = 0;
    handle->stride[UHDR_PLANE_V] = 0;
  }
}

void compare_planes(void* ref_plane, void* test_plane, int ref_stride, int test_stride, int width,
                    int height, int bpp) {
  uint8_t* ref = (uint8_t*)ref_plane;
  uint8_t* test = (uint8_t*)test_plane;
  const size_t length = width * bpp;

  for (int i = 0; i < height; i++, ref += (ref_stride * bpp), test += (test_stride * bpp)) {
    ASSERT_EQ(0, memcmp(ref, ref, length));
  }
}

void compareImg(uhdr_raw_image_t* ref, uhdr_raw_image_t* test) {
  ASSERT_EQ(ref->fmt, test->fmt);
  ASSERT_EQ(ref->cg, test->cg);
  ASSERT_EQ(ref->ct, test->ct);
  ASSERT_EQ(ref->range, test->range);
  ASSERT_EQ(ref->w, test->w);
  ASSERT_EQ(ref->h, test->h);
  int bpp = 1;
  if (ref->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
    bpp = 2;
    compare_planes(ref->planes[UHDR_PLANE_Y], test->planes[UHDR_PLANE_Y], ref->stride[UHDR_PLANE_Y],
                   test->stride[UHDR_PLANE_Y], ref->w, ref->h, bpp);
    compare_planes(ref->planes[UHDR_PLANE_UV], test->planes[UHDR_PLANE_UV],
                   ref->stride[UHDR_PLANE_UV], test->stride[UHDR_PLANE_UV], ref->w, ref->h / 2,
                   bpp);
  } else if (ref->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
    compare_planes(ref->planes[UHDR_PLANE_Y], test->planes[UHDR_PLANE_Y], ref->stride[UHDR_PLANE_Y],
                   test->stride[UHDR_PLANE_Y], ref->w, ref->h, bpp);
    compare_planes(ref->planes[UHDR_PLANE_U], test->planes[UHDR_PLANE_U], ref->stride[UHDR_PLANE_U],
                   test->stride[UHDR_PLANE_U], ref->w / 2, ref->h / 2, bpp);
    compare_planes(ref->planes[UHDR_PLANE_V], test->planes[UHDR_PLANE_V], ref->stride[UHDR_PLANE_V],
                   test->stride[UHDR_PLANE_V], ref->w / 2, ref->h / 2, bpp);
  } else if (ref->fmt == UHDR_IMG_FMT_32bppRGBA8888 || ref->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
             ref->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
    bpp = ref->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
    compare_planes(ref->planes[UHDR_PLANE_PACKED], test->planes[UHDR_PLANE_PACKED],
                   ref->stride[UHDR_PLANE_PACKED], test->stride[UHDR_PLANE_PACKED], ref->w, ref->h,
                   bpp);
  } else if (ref->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
    compare_planes(ref->planes[UHDR_PLANE_Y], test->planes[UHDR_PLANE_Y], ref->stride[UHDR_PLANE_Y],
                   test->stride[UHDR_PLANE_Y], ref->w, ref->h, bpp);
  }
}

class EditorHelperTest
    : public ::testing::TestWithParam<std::tuple<std::string, int, int, uhdr_img_fmt_t>> {
 public:
  EditorHelperTest()
      : filename(std::get<0>(GetParam())),
        width(std::get<1>(GetParam())),
        height(std::get<2>(GetParam())),
        fmt(std::get<3>(GetParam())){};

  ~EditorHelperTest() {
    int count = sizeof img_a.planes / sizeof img_a.planes[0];
    for (int i = 0; i < count; i++) {
      if (img_a.planes[i]) {
        free(img_a.planes[i]);
      }
    }
  }

  std::string filename;
  int width;
  int height;
  uhdr_img_fmt_t fmt;
  uhdr_raw_image_t img_a;
};

TEST_P(EditorHelperTest, Rotate) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  auto dst = apply_rotate(&img_a, 90);
  dst = apply_rotate(dst.get(), 90);
  dst = apply_rotate(dst.get(), 180);
  dst = apply_rotate(dst.get(), 270);
  dst = apply_rotate(dst.get(), 90);
  dst = apply_rotate(dst.get(), 90);
  dst = apply_rotate(dst.get(), 270);
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()));
}

TEST_P(EditorHelperTest, Mirror) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  auto dst = apply_mirror(&img_a, UHDR_MIRROR_VERTICAL);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_VERTICAL);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_HORIZONTAL);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_HORIZONTAL);
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()));
}

TEST_P(EditorHelperTest, MultipleEffects) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  auto dst = apply_mirror(&img_a, UHDR_MIRROR_VERTICAL);
  dst = apply_rotate(dst.get(), 180);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_HORIZONTAL);
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()));

  dst = apply_mirror(dst.get(), UHDR_MIRROR_HORIZONTAL);
  dst = apply_rotate(dst.get(), 90);
  dst = apply_rotate(dst.get(), 90);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_VERTICAL);
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()));

  dst = apply_rotate(dst.get(), 270);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_VERTICAL);
  dst = apply_rotate(dst.get(), 90);
  dst = apply_mirror(dst.get(), UHDR_MIRROR_HORIZONTAL);
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()));

  dst = apply_resize(dst.get(), width / 2, height / 2);
  ASSERT_EQ(img_a.fmt, dst->fmt);
  ASSERT_EQ(img_a.cg, dst->cg);
  ASSERT_EQ(img_a.ct, dst->ct);
  ASSERT_EQ(img_a.range, dst->range);
  ASSERT_EQ(dst->w, width / 2);
  ASSERT_EQ(dst->h, height / 2);

  uhdr_raw_image_ext_t* img_copy = dst.get();
  apply_crop(img_copy, 8, 8, width / 4, height / 4);
  ASSERT_EQ(dst->fmt, img_copy->fmt);
  ASSERT_EQ(dst->cg, img_copy->cg);
  ASSERT_EQ(dst->ct, img_copy->ct);
  ASSERT_EQ(dst->range, img_copy->range);
  ASSERT_EQ(width / 4, img_copy->w);
  ASSERT_EQ(height / 4, img_copy->h);
}

TEST_P(EditorHelperTest, Crop) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  uhdr_raw_image_t img_copy = img_a;
  apply_crop(&img_copy, 8, 8, width / 2, height / 2);

  ASSERT_EQ(img_a.fmt, img_copy.fmt);
  ASSERT_EQ(img_a.cg, img_copy.cg);
  ASSERT_EQ(img_a.ct, img_copy.ct);
  ASSERT_EQ(img_a.range, img_copy.range);
  ASSERT_EQ(img_copy.w, width / 2);
  ASSERT_EQ(img_copy.h, height / 2);
#ifdef DUMP_OUTPUT
  if (!writeFile("cropped", &img_copy)) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_P(EditorHelperTest, Resize) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  auto dst = apply_resize(&img_a, width / 2, height / 2);

  ASSERT_EQ(img_a.fmt, dst->fmt);
  ASSERT_EQ(img_a.cg, dst->cg);
  ASSERT_EQ(img_a.ct, dst->ct);
  ASSERT_EQ(img_a.range, dst->range);
  ASSERT_EQ(dst->w, width / 2);
  ASSERT_EQ(dst->h, height / 2);
#ifdef DUMP_OUTPUT
  if (!writeFile("resize", dst.get())) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

#ifdef __ANDROID__
INSTANTIATE_TEST_SUITE_P(
    EditorAPIParameterizedTests, EditorHelperTest,
    ::testing::Values(std::make_tuple("/data/local/tmp/raw_p010_image.p010", 1280, 720,
                                      UHDR_IMG_FMT_24bppYCbCrP010),
                      std::make_tuple("/data/local/tmp/raw_yuv420_image.yuv420", 1280, 720,
                                      UHDR_IMG_FMT_12bppYCbCr420),
                      std::make_tuple("/data/local/tmp/raw_yuv420_image.yuv420", 1280, 720,
                                      UHDR_IMG_FMT_8bppYCbCr400),
                      std::make_tuple("/data/local/tmp/raw_p010_image.p010", 352, 288,
                                      UHDR_IMG_FMT_32bppRGBA1010102),
                      std::make_tuple("/data/local/tmp/raw_p010_image.p010", 352, 288,
                                      UHDR_IMG_FMT_64bppRGBAHalfFloat),
                      std::make_tuple("/data/local/tmp/raw_p010_image.p010", 352, 288,
                                      UHDR_IMG_FMT_32bppRGBA8888)));

#else
INSTANTIATE_TEST_SUITE_P(
    EditorAPIParameterizedTests, EditorHelperTest,
    ::testing::Values(
        std::make_tuple("./data/raw_p010_image.p010", 1280, 720, UHDR_IMG_FMT_24bppYCbCrP010),
        std::make_tuple("./data/raw_yuv420_image.yuv420", 1280, 720, UHDR_IMG_FMT_12bppYCbCr420),
        std::make_tuple("./data/raw_yuv420_image.yuv420", 1280, 720, UHDR_IMG_FMT_8bppYCbCr400),
        std::make_tuple("./data/raw_p010_image.p010", 352, 288, UHDR_IMG_FMT_32bppRGBA1010102),
        std::make_tuple("./data/raw_p010_image.p010", 352, 288, UHDR_IMG_FMT_64bppRGBAHalfFloat),
        std::make_tuple("./data/raw_p010_image.p010", 352, 288, UHDR_IMG_FMT_32bppRGBA8888)));
#endif

}  // namespace ultrahdr
