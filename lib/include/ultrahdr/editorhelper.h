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

#include "ultrahdr_api.h"
#include "ultrahdr/ultrahdrcommon.h"

// todo: move this to ultrahdr_api.h
/*!\brief List of supported mirror directions */
typedef enum uhdr_mirror_direction {
  UHDR_MIRROR_VERTICAL,    /**< flip image over x axis */
  UHDR_MIRROR_HORIZONTAL,  /**< flip image over y axis */
} uhdr_mirror_direction_t; /**< alias for enum uhdr_mirror_direction */

namespace ultrahdr {

/*!\brief uhdr image effect descriptor */
typedef struct uhdr_effect_desc {
  virtual std::string to_string() = 0;

  virtual ~uhdr_effect_desc() = default;
} uhdr_effect_desc_t; /**< alias for struct uhdr_effect_desc */

/*!\brief mirror effect descriptor */
typedef struct uhdr_mirror_effect : uhdr_effect_desc {
  uhdr_mirror_effect(uhdr_mirror_direction_t direction) : m_direction{direction} {}

  std::string to_string() {
    return "effect : mirror, metadata : direction - " + ((m_direction == UHDR_MIRROR_HORIZONTAL)
                                                             ? std::string{"horizontal"}
                                                             : std::string{"vertical"});
  }

  uhdr_mirror_direction_t m_direction;
} uhdr_mirror_effect_t; /**< alias for struct uhdr_mirror_effect */

/*!\brief rotate effect descriptor */
typedef struct uhdr_rotate_effect : uhdr_effect_desc {
  uhdr_rotate_effect(int degree) : m_degree{degree} {}

  std::string to_string() {
    return "effect : rotate, metadata : degree - " + std::to_string(m_degree);
  }

  int m_degree;
} uhdr_rotate_effect_t; /**< alias for struct uhdr_rotate_effect */

/*!\brief crop effect descriptor */
typedef struct uhdr_crop_effect : uhdr_effect_desc {
  uhdr_crop_effect(int left, int right, int top, int bottom)
      : m_left{left}, m_right{right}, m_top{top}, m_bottom{bottom} {}

  std::string to_string() {
    return "effect : crop, metadata : left, right, top, bottom - " + std::to_string(m_left) + " ," +
           std::to_string(m_right) + " ," + std::to_string(m_top) + " ," + std::to_string(m_bottom);
  }

  int m_left;
  int m_right;
  int m_top;
  int m_bottom;
} uhdr_crop_effect_t; /**< alias for struct uhdr_crop_effect */

/*!\brief resize effect descriptor */
typedef struct uhdr_resize_effect : uhdr_effect_desc {
  uhdr_resize_effect(int width, int height) : m_width{width}, m_height{height} {}

  std::string to_string() {
    return "effect : resize, metadata : dimensions w, h" + std::to_string(m_width) + " ," +
           std::to_string(m_height);
  }

  int m_width;
  int m_height;
} uhdr_resize_effect_t; /**< alias for struct uhdr_resize_effect */

std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(uhdr_raw_image_t* src, int degree);

std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(uhdr_raw_image_t* src,
                                                   uhdr_mirror_direction_t direction);

std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(uhdr_raw_image* src, int dst_w, int dst_h);

void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht);

}  // namespace ultrahdr

#endif  // ULTRAHDR_EDITORHELPER_H
