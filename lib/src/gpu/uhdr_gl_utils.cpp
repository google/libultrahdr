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

#include "ultrahdr/ultrahdrcommon.h"

namespace ultrahdr {

#ifdef UHDR_ENABLE_OPENGL

uhdr_opengl_ctxt::uhdr_opengl_ctxt() {
  mEGLDisplay = EGL_NO_DISPLAY;
  mEGLContext = EGL_NO_CONTEXT;
  mEGLSurface = EGL_NO_SURFACE;
  mEGLConfig = 0;
  mErrorStatus = g_no_error;
}

uhdr_opengl_ctxt::~uhdr_opengl_ctxt() { delete_opengl_ctxt(); }

uhdr_error_info_t uhdr_opengl_ctxt::init_opengl_ctxt() {
  uhdr_error_info_t status = g_no_error;
#define RET_IF_ERR(cond, msg)                                   \
  {                                                             \
    if (cond) {                                                 \
      status.error_code = UHDR_CODEC_INVALID_PARAM;             \
      status.has_detail = 1;                                    \
      snprintf(status.detail, sizeof status.detail, "%s", msg); \
      mErrorStatus = status;                                    \
      return status;                                            \
    }                                                           \
  }

  mEGLDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  RET_IF_ERR(mEGLDisplay == EGL_NO_DISPLAY, "failed to get EGL display")

  RET_IF_ERR(!eglInitialize(mEGLDisplay, NULL, NULL), "failed to initialize EGL")

  EGLint num_config;
#ifndef UHDR_ENABLE_GLESV3
  EGLint majorVersion = EGL_OPENGL_ES2_BIT;
#else
  EGLint majorVersion = EGL_OPENGL_ES3_BIT;
#endif
  EGLint attribs[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, majorVersion,
                      EGL_NONE};
  RET_IF_ERR(!eglChooseConfig(mEGLDisplay, attribs, &mEGLConfig, 1, &num_config),
             "failed to choose EGL config")

#ifdef UHDR_ENABLE_GLESV3
  EGLint context_attribs[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
#else
  EGLint context_attribs[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
#endif
  mEGLContext = eglCreateContext(mEGLDisplay, mEGLConfig, EGL_NO_CONTEXT, context_attribs);
  RET_IF_ERR(mEGLContext == EGL_NO_CONTEXT, "failed to create EGL context")

  EGLint pbuffer_attribs[] = {
      EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE,
  };
  mEGLSurface = eglCreatePbufferSurface(mEGLDisplay, mEGLConfig, pbuffer_attribs);
  RET_IF_ERR(mEGLSurface == EGL_NO_SURFACE, "failed to create EGL Pbuffer surface")

  // Make the context current
  RET_IF_ERR(!eglMakeCurrent(mEGLDisplay, mEGLSurface, mEGLSurface, mEGLContext),
             "failed to make EGL context current")

#undef RET_IF_ERR
  return status;
}

uhdr_error_info_t uhdr_opengl_ctxt::reset_opengl_ctxt() {
  delete_opengl_ctxt();
  return init_opengl_ctxt();
}

void uhdr_opengl_ctxt::delete_opengl_ctxt() {
  if (mEGLSurface != EGL_NO_SURFACE) {
    eglDestroySurface(mEGLDisplay, mEGLSurface);
    mEGLSurface = EGL_NO_SURFACE;
  }
  if (mEGLContext != EGL_NO_CONTEXT) {
    eglDestroyContext(mEGLDisplay, mEGLContext);
    mEGLContext = EGL_NO_CONTEXT;
  }
  if (mEGLDisplay != EGL_NO_DISPLAY) {
    eglTerminate(mEGLDisplay);
    mEGLDisplay = EGL_NO_DISPLAY;
  }
  if (mEGLConfig != 0) {
    mEGLConfig = 0;
  }
}
#endif
}  // namespace ultrahdr