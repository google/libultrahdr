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

#ifndef ULTRAHDR_EDITORHELPER_H
#define ULTRAHDR_EDITORHELPER_H

#include "ultrahdr/ultrahdr.h"
#include "ultrahdr/jpegr.h"

namespace ultrahdr {
typedef enum {
  ULTRAHDR_MIRROR_VERTICAL,
  ULTRAHDR_MIRROR_HORIZONTAL,
} ultrahdr_mirroring_direction;

status_t crop(jr_uncompressed_ptr const in_img,
              int left, int right, int top, int bottom, jr_uncompressed_ptr out_img);

status_t mirror(jr_uncompressed_ptr const in_img,
                ultrahdr_mirroring_direction mirror_dir,
                jr_uncompressed_ptr out_img);

status_t rotate(jr_uncompressed_ptr const in_img, int clockwise_degree,
                jr_uncompressed_ptr out_img);

status_t resize(jr_uncompressed_ptr const in_img, int out_width, int out_height,
                jr_uncompressed_ptr out_img);

}  // namespace ultrahdr

#endif  // ULTRAHDR_EDITORHELPER_H
