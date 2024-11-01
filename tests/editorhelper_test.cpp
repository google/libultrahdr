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

#ifdef __ANDROID__
#define INPUT_IMAGE "/data/local/tmp/raw_p010_image.p010"
#else
#define INPUT_IMAGE "./data/raw_p010_image.p010"
#endif

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
    for (unsigned i = 0; i < img->h; i++, data += stride) {
      ofd.write(data, length);
    }

    if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
      data = static_cast<char*>(img->planes[UHDR_PLANE_UV]);
      stride = img->stride[UHDR_PLANE_UV] * bpp;
      length = img->w * bpp;
      for (unsigned i = 0; i < img->h / 2; i++, data += stride) {
        ofd.write(data, length);
      }
    } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
      data = static_cast<char*>(img->planes[UHDR_PLANE_U]);
      stride = img->stride[UHDR_PLANE_U] * bpp;
      length = (img->w / 2) * bpp;
      for (unsigned i = 0; i < img->h / 2; i++, data += stride) {
        ofd.write(data, length);
      }
      data = static_cast<char*>(img->planes[UHDR_PLANE_V]);
      stride = img->stride[UHDR_PLANE_V] * bpp;
      length = (img->w / 2) * bpp;
      for (unsigned i = 0; i < img->h / 2; i++, data += stride) {
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
    ASSERT_EQ(0, memcmp(ref, test, length));
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
        fmt(std::get<3>(GetParam())) {
#ifdef UHDR_ENABLE_GLES
    gl_ctxt = new uhdr_opengl_ctxt();
    opengl_ctxt = static_cast<uhdr_opengl_ctxt*>(gl_ctxt);
    opengl_ctxt->init_opengl_ctxt();
    if (opengl_ctxt->mErrorStatus.error_code != UHDR_CODEC_OK) {
      opengl_ctxt->delete_opengl_ctxt();
      delete opengl_ctxt;
      gl_ctxt = nullptr;
    }
#endif
  };

  ~EditorHelperTest() {
    int count = sizeof img_a.planes / sizeof img_a.planes[0];
    for (int i = 0; i < count; i++) {
      if (img_a.planes[i]) {
        free(img_a.planes[i]);
        img_a.planes[i] = nullptr;
      }
    }
#ifdef UHDR_ENABLE_GLES
    if (gl_ctxt) {
      uhdr_opengl_ctxt* opengl_ctxt = static_cast<uhdr_opengl_ctxt*>(gl_ctxt);
      opengl_ctxt->delete_opengl_ctxt();
      delete opengl_ctxt;
    }
    if (Texture) glDeleteTextures(1, &Texture);
#endif
  }

  std::string filename;
  int width;
  int height;
  uhdr_img_fmt_t fmt;
  uhdr_raw_image_t img_a{};
  void* gl_ctxt = nullptr;
  void* texture = nullptr;
#ifdef UHDR_ENABLE_GLES
  GLuint Texture = 0;
  uhdr_opengl_ctxt* opengl_ctxt = nullptr;
#endif
};

TEST_P(EditorHelperTest, Rotate) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  ultrahdr::uhdr_rotate_effect_t r90(90), r180(180), r270(270);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
    texture = static_cast<void*>(&Texture);
  }
#endif
  auto dst = apply_rotate(&r90, &img_a, gl_ctxt, texture);
  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r180, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r270, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r270, dst.get(), gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()))
      << "failed for resolution " << width << " x " << height << " format: " << fmt;
}

TEST_P(EditorHelperTest, Mirror) {
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  ultrahdr::uhdr_mirror_effect_t mhorz(UHDR_MIRROR_HORIZONTAL), mvert(UHDR_MIRROR_VERTICAL);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
    texture = static_cast<void*>(&Texture);
  }
#endif
  auto dst = apply_mirror(&mhorz, &img_a, gl_ctxt, texture);
  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()))
      << "failed for resolution " << width << " x " << height << " format: " << fmt;
}

TEST_P(EditorHelperTest, Crop) {
  const int left = 16;
  const int top = 16;
  const int crop_wd = 32;
  const int crop_ht = 32;

  if (width < (left + crop_wd) || height <= (top + crop_ht)) {
    GTEST_SKIP() << "Test skipped as crop attributes are too large for resolution " +
                        std::to_string(width) + " x " + std::to_string(height) +
                        " format: " + std::to_string(fmt);
  }
  std::string msg = "failed for resolution " + std::to_string(width) + " x " +
                    std::to_string(height) + " format: " + std::to_string(fmt);
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  ultrahdr::uhdr_crop_effect_t crop(left, left + crop_wd, top, top + crop_ht);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
    texture = static_cast<void*>(&Texture);
  }
#endif
  auto dst = apply_crop(&crop, &img_a, left, top, crop_wd, crop_ht, gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
  ASSERT_EQ(img_a.cg, dst->cg) << msg;
  ASSERT_EQ(img_a.ct, dst->ct) << msg;
  ASSERT_EQ(img_a.range, dst->range) << msg;
  ASSERT_EQ(dst->w, crop_wd) << msg;
  ASSERT_EQ(dst->h, crop_ht) << msg;
#ifdef DUMP_OUTPUT
  if (!writeFile("cropped", dst.get())) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_P(EditorHelperTest, Resize) {
  if ((fmt == UHDR_IMG_FMT_12bppYCbCr420 || UHDR_IMG_FMT_24bppYCbCrP010) &&
      (((width / 2) % 2 != 0) || ((height / 2) % 2 != 0))) {
    GTEST_SKIP() << "Test skipped for resolution " + std::to_string(width) + " x " +
                        std::to_string(height) + " format: " + std::to_string(fmt);
  }
  std::string msg = "failed for resolution " + std::to_string(width) + " x " +
                    std::to_string(height) + " format: " + std::to_string(fmt);
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  ultrahdr::uhdr_resize_effect_t resize(width / 2, height / 2);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
    texture = static_cast<void*>(&Texture);
  }
#endif
  auto dst = apply_resize(&resize, &img_a, width / 2, height / 2, gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
  ASSERT_EQ(img_a.cg, dst->cg) << msg;
  ASSERT_EQ(img_a.ct, dst->ct) << msg;
  ASSERT_EQ(img_a.range, dst->range) << msg;
  ASSERT_EQ(dst->w, width / 2) << msg;
  ASSERT_EQ(dst->h, height / 2) << msg;
#ifdef DUMP_OUTPUT
  if (!writeFile("resize", dst.get())) {
    std::cerr << "unable to write output file" << std::endl;
  }
#endif
}

TEST_P(EditorHelperTest, MultipleEffects) {
  std::string msg = "failed for resolution " + std::to_string(width) + " x " +
                    std::to_string(height) + " format: " + std::to_string(fmt);
  initImageHandle(&img_a, width, height, fmt);
  ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
  ultrahdr::uhdr_rotate_effect_t r90(90), r180(180), r270(270);
  ultrahdr::uhdr_mirror_effect_t mhorz(UHDR_MIRROR_HORIZONTAL), mvert(UHDR_MIRROR_VERTICAL);
  ultrahdr::uhdr_resize_effect_t resize(width / 2, height / 2);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
    texture = static_cast<void*>(&Texture);
  }
#endif
  auto dst = apply_mirror(&mhorz, &img_a, gl_ctxt, texture);
  dst = apply_rotate(&r180, dst.get(), gl_ctxt, texture);
  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r180, dst.get(), gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get())) << msg;

  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get())) << msg;

  dst = apply_rotate(&r270, dst.get(), gl_ctxt, texture);
  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get())) << msg;

  dst = apply_resize(&resize, dst.get(), width * 2, height * 2, gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
  ASSERT_EQ(img_a.cg, dst->cg) << msg;
  ASSERT_EQ(img_a.ct, dst->ct) << msg;
  ASSERT_EQ(img_a.range, dst->range) << msg;
  ASSERT_EQ(dst->w, width * 2) << msg;
  ASSERT_EQ(dst->h, height * 2) << msg;

  const int left = 16;
  const int top = 16;
  const int crop_wd = 32;
  const int crop_ht = 32;
  if (dst->w < (left + crop_wd) || dst->h <= (top + crop_ht)) {
    GTEST_SKIP() << "Test skipped as crop attributes are too large for resolution " +
                        std::to_string(dst->w) + " x " + std::to_string(dst->h) +
                        " format: " + std::to_string(fmt);
  }
  ultrahdr::uhdr_crop_effect_t crop(left, left + crop_wd, top, top + crop_ht);
  dst = apply_crop(&crop, dst.get(), left, top, crop_wd, crop_ht, gl_ctxt, texture);
#ifdef UHDR_ENABLE_GLES
  if (gl_ctxt != nullptr) {
    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
                              dst->planes[0]);
  }
#endif
  ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
  ASSERT_EQ(img_a.cg, dst->cg) << msg;
  ASSERT_EQ(img_a.ct, dst->ct) << msg;
  ASSERT_EQ(img_a.range, dst->range) << msg;
  ASSERT_EQ(crop_wd, dst->w) << msg;
  ASSERT_EQ(crop_ht, dst->h) << msg;
}

INSTANTIATE_TEST_SUITE_P(
    EditorAPIParameterizedTests, EditorHelperTest,
    ::testing::Combine(::testing::Values(INPUT_IMAGE), ::testing::Range(2, 80, 2),
                       ::testing::Values(64),
                       ::testing::Values(UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_12bppYCbCr420,
                                         UHDR_IMG_FMT_8bppYCbCr400, UHDR_IMG_FMT_32bppRGBA1010102,
                                         UHDR_IMG_FMT_64bppRGBAHalfFloat,
                                         UHDR_IMG_FMT_32bppRGBA8888)));

}  // namespace ultrahdr
