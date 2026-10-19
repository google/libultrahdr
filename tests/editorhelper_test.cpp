/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#include <gtest/gtest.h>

#include <fstream>
#include <iostream>

#include "ultrahdr/editorhelper.h"

// #define DUMP_OUTPUT

#ifdef __ANDROID__
#define INPUT_IMAGE "/data/local/tmp/raw_p010_image.p010"
#else
#define INPUT_IMAGE "raw_p010_image.p010"
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
  std::vector<std::string> candidates = {
      filename,
      std::string("tests/data/") + filename,
      std::string("./data/") + filename,
      std::string("data/") + filename,
      std::string("../tests/data/") + filename,
      std::string("third_party/libultrahdr/tests/data/") + filename,
  };
  for (const auto& path : candidates) {
    std::ifstream ifd(path, std::ios::binary);
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
    }
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

// resize_image() interpolates between the four neighboring pixels, horizontally and vertically.
TEST(ResizeImageTest, InterpolatesInBothDirections) {
  uhdr_raw_image_ext_t src(UHDR_IMG_FMT_8bppYCbCr400, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,
                           UHDR_CR_FULL_RANGE, 2, 2, 1);
  uint8_t* src_data = static_cast<uint8_t*>(src.planes[UHDR_PLANE_Y]);
  const uint8_t src_values[2][2] = {{0, 100}, {200, 40}};
  for (int y = 0; y < 2; y++) {
    for (int x = 0; x < 2; x++) src_data[y * src.stride[UHDR_PLANE_Y] + x] = src_values[y][x];
  }

  auto dst = resize_image(&src, 4, 4);
  ASSERT_NE(dst, nullptr);
  ASSERT_EQ(dst->w, 4u);
  ASSERT_EQ(dst->h, 4u);
  // Pixel (x, y) samples the source at (x / 2, y / 2), clamped at the right and bottom edges.
  const int expected[4][4] = {
      {0, 50, 100, 100}, {100, 85, 70, 70}, {200, 120, 40, 40}, {200, 120, 40, 40}};
  uint8_t* dst_data = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
  for (int y = 0; y < 4; y++) {
    for (int x = 0; x < 4; x++) {
      EXPECT_EQ(static_cast<int>(dst_data[y * dst->stride[UHDR_PLANE_Y] + x]), expected[y][x])
          << "x: " << x << " y: " << y;
    }
  }
}

#ifdef UHDR_ENABLE_GLES
// Planes are tightly packed, so textures must hold exactly the bytes of the buffer for widths
// whose rows are not a multiple of 4 bytes.
TEST(OpenGLContextTest, TextureUploadOfTightlyPackedRows) {
  uhdr_opengl_ctxt opengl_ctxt;
  opengl_ctxt.init_opengl_ctxt();
  if (opengl_ctxt.mErrorStatus.error_code != UHDR_CODEC_OK) {
    GTEST_SKIP() << "opengl context unavailable";
  }
  struct {
    uhdr_img_fmt_t fmt;
    int rows_per_line;  // texture rows per image row, in halves
    int bpp;
  } formats[] = {
      {UHDR_IMG_FMT_8bppYCbCr400, 2, 1},  {UHDR_IMG_FMT_12bppYCbCr420, 3, 1},
      {UHDR_IMG_FMT_16bppYCbCr422, 4, 1}, {UHDR_IMG_FMT_24bppYCbCr444, 6, 1},
      {UHDR_IMG_FMT_24bppRGB888, 2, 3},
  };
  const int ht = 8;
  for (const auto& f : formats) {
    for (int wd = 1; wd <= 10; wd++) {
      std::string msg = "format: " + std::to_string(f.fmt) + " width: " + std::to_string(wd);
      const int tex_ht = ht * f.rows_per_line / 2;
      std::vector<uint8_t> src(static_cast<size_t>(wd) * tex_ht * f.bpp);
      for (size_t i = 0; i < src.size(); i++) src[i] = static_cast<uint8_t>(i * 7 + 1);
      GLuint texture = opengl_ctxt.create_texture(f.fmt, wd, ht, src.data());
      ASSERT_NE(texture, 0u) << msg;
      std::vector<uint8_t> dst;
      if (f.bpp == 1) {
        dst.resize(src.size());
        opengl_ctxt.read_texture(&texture, UHDR_IMG_FMT_8bppYCbCr400, wd, tex_ht, dst.data());
      } else {
        std::vector<uint8_t> rgba(static_cast<size_t>(wd) * tex_ht * 4);
        opengl_ctxt.read_texture(&texture, UHDR_IMG_FMT_32bppRGBA8888, wd, tex_ht, rgba.data());
        for (size_t i = 0; i < rgba.size(); i += 4) dst.insert(dst.end(), &rgba[i], &rgba[i + 3]);
      }
      glDeleteTextures(1, &texture);
      ASSERT_EQ(opengl_ctxt.mErrorStatus.error_code, UHDR_CODEC_OK) << msg;
      ASSERT_EQ(src, dst) << msg;
    }
  }
}
#endif

}  // namespace ultrahdr
