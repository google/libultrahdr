/*
 * Copyright 2023 The Android Open Source Project
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

#ifndef ULTRAHDR_ULTRAHDRCOMMON_H
#define ULTRAHDR_ULTRAHDRCOMMON_H

//#define LOG_NDEBUG 0

#ifdef __ANDROID__
#include "log/log.h"
#else
#ifdef LOG_NDEBUG
#include <cstdio>

#define ALOGD(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)
#define ALOGE(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)
#define ALOGI(...)                \
  do {                            \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n");        \
  } while (0)
#define ALOGV(...)                \
  do {                            \
    fprintf(stdout, __VA_ARGS__); \
    fprintf(stdout, "\n");        \
  } while (0)
#define ALOGW(...)                \
  do {                            \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n");        \
  } while (0)
#else
#define ALOGD(...) ((void)0)
#define ALOGE(...) ((void)0)
#define ALOGI(...) ((void)0)
#define ALOGV(...) ((void)0)
#define ALOGW(...) ((void)0)
#endif
#endif

#define ALIGNM(x, m) ((((x) + ((m)-1)) / (m)) * (m))

#endif  // ULTRAHDR_ULTRAHDRCOMMON_H
