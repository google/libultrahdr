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

#include <cstring>
#include <string>

#include "com_google_media_codecs_ultrahdr_UltraHDRCommon.h"
#include "com_google_media_codecs_ultrahdr_UltraHDRDecoder.h"
#include "com_google_media_codecs_ultrahdr_UltraHDREncoder.h"
#include "ultrahdr_api.h"

static_assert(sizeof(void *) <= sizeof(jlong),
              "unsupported architecture, size of pointer address exceeds jlong storage");

#define RET_IF_TRUE(cond, exception_class, msg)      \
  {                                                  \
    if ((cond) || env->ExceptionCheck()) {           \
      env->ExceptionClear();                         \
      auto _clazz = env->FindClass(exception_class); \
      if (!_clazz || env->ExceptionCheck()) {        \
        return;                                      \
      }                                              \
      env->ThrowNew(_clazz, msg);                    \
      return;                                        \
    }                                                \
  }

#define GET_HANDLE()                                                                         \
  jclass clazz = env->GetObjectClass(thiz);                                                  \
  RET_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error") \
  jfieldID fid = env->GetFieldID(clazz, "handle", "J");                                      \
  RET_IF_TRUE(fid == nullptr, "java/io/IOException",                                         \
              "GetFieldID for field 'handle' returned with error")                           \
  jlong handle = env->GetLongField(thiz, fid);

#define RET_VAL_IF_TRUE(cond, exception_class, msg, val) \
  {                                                      \
    if ((cond) || env->ExceptionCheck()) {               \
      env->ExceptionClear();                             \
      auto _clazz = env->FindClass(exception_class);     \
      if (!_clazz || env->ExceptionCheck()) {            \
        return (val);                                    \
      }                                                  \
      env->ThrowNew(_clazz, msg);                        \
      return (val);                                      \
    }                                                    \
  }

#define GET_HANDLE_VAL(val)                                                                      \
  jclass clazz = env->GetObjectClass(thiz);                                                      \
  RET_VAL_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error", \
                  (val))                                                                         \
  jfieldID fid = env->GetFieldID(clazz, "handle", "J");                                          \
  RET_VAL_IF_TRUE(fid == nullptr, "java/io/IOException",                                         \
                  "GetFieldID for field 'handle' returned with error", (val))                    \
  jlong handle = env->GetLongField(thiz, fid);

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_init(JNIEnv *env, jobject thiz) {
  jclass clazz = env->GetObjectClass(thiz);
  RET_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error")
  jfieldID fid = env->GetFieldID(clazz, "handle", "J");
  RET_IF_TRUE(fid == nullptr, "java/io/IOException",
              "GetFieldID for field 'handle' returned with error")
  uhdr_codec_private_t *handle = uhdr_create_encoder();
  RET_IF_TRUE(handle == nullptr, "java/lang/OutOfMemoryError",
              "Unable to allocate encoder instance")
  env->SetLongField(thiz, fid, (jlong)handle);
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_destroy(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  if (!handle) {
    uhdr_release_encoder((uhdr_codec_private_t *)handle);
    env->SetLongField(thiz, fid, (jlong)0);
  }
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3IIIIIIIII(
    JNIEnv *env, jobject thiz, jintArray rgb_buff, jint width, jint height, jint rgb_stride,
    jint color_gamut, jint color_transfer, jint color_range, jint color_format, jint intent) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(rgb_buff);
  RET_IF_TRUE(length < height * rgb_stride, "java/io/IOException",
              "raw image rgba byteArray size is less than required size")
  jint *rgbBody = env->GetIntArrayElements(rgb_buff, nullptr);
  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
                       (uhdr_color_gamut_t)color_gamut,
                       (uhdr_color_transfer_t)color_transfer,
                       (uhdr_color_range_t)color_range,
                       (unsigned int)width,
                       (unsigned int)height,
                       {rgbBody, nullptr, nullptr},
                       {(unsigned int)rgb_stride, 0u, 0u}};
  auto status =
      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
  env->ReleaseIntArrayElements(rgb_buff, rgbBody, 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3JIIIIIIII(
    JNIEnv *env, jobject thiz, jlongArray rgb_buff, jint width, jint height, jint rgb_stride,
    jint color_gamut, jint color_transfer, jint color_range, jint color_format, jint intent) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(rgb_buff);
  RET_IF_TRUE(length < height * rgb_stride, "java/io/IOException",
              "raw image rgba byteArray size is less than required size")
  jlong *rgbBody = env->GetLongArrayElements(rgb_buff, nullptr);
  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
                       (uhdr_color_gamut_t)color_gamut,
                       (uhdr_color_transfer_t)color_transfer,
                       (uhdr_color_range_t)color_range,
                       (unsigned int)width,
                       (unsigned int)height,
                       {rgbBody, nullptr, nullptr},
                       {(unsigned int)rgb_stride, 0u, 0u}};
  auto status =
      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
  env->ReleaseLongArrayElements(rgb_buff, rgbBody, 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3S_3SIIIIIIIII(
    JNIEnv *env, jobject thiz, jshortArray y_buff, jshortArray uv_buff, jint width, jint height,
    jint y_stride, jint uv_stride, jint color_gamut, jint color_transfer, jint color_range,
    jint color_format, jint intent) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(y_buff);
  RET_IF_TRUE(length < height * y_stride, "java/io/IOException",
              "raw image luma byteArray size is less than required size")
  length = env->GetArrayLength(uv_buff);
  RET_IF_TRUE(length < height * uv_stride / 2, "java/io/IOException",
              "raw image chroma byteArray size is less than required size")
  jshort *lumaBody = env->GetShortArrayElements(y_buff, nullptr);
  jshort *chromaBody = env->GetShortArrayElements(uv_buff, nullptr);
  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
                       (uhdr_color_gamut_t)color_gamut,
                       (uhdr_color_transfer_t)color_transfer,
                       (uhdr_color_range_t)color_range,
                       (unsigned int)width,
                       (unsigned int)height,
                       {lumaBody, chromaBody, nullptr},
                       {(unsigned int)y_stride, (unsigned int)uv_stride, 0u}};
  auto status =
      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
  env->ReleaseShortArrayElements(y_buff, lumaBody, 0);
  env->ReleaseShortArrayElements(uv_buff, chromaBody, 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3B_3B_3BIIIIIIIIII(
    JNIEnv *env, jobject thiz, jbyteArray y_buff, jbyteArray u_buff, jbyteArray v_buff, jint width,
    jint height, jint y_stride, jint u_stride, jint v_stride, jint color_gamut, jint color_transfer,
    jint color_range, jint color_format, jint intent) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(y_buff);
  RET_IF_TRUE(length < height * y_stride, "java/io/IOException",
              "raw image luma byteArray size is less than required size")
  length = env->GetArrayLength(u_buff);
  RET_IF_TRUE(length < height * u_stride / 4, "java/io/IOException",
              "raw image cb byteArray size is less than required size")
  length = env->GetArrayLength(v_buff);
  RET_IF_TRUE(length < height * v_stride / 4, "java/io/IOException",
              "raw image cb byteArray size is less than required size")
  jbyte *lumaBody = env->GetByteArrayElements(y_buff, nullptr);
  jbyte *cbBody = env->GetByteArrayElements(u_buff, nullptr);
  jbyte *crBody = env->GetByteArrayElements(v_buff, nullptr);
  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
                       (uhdr_color_gamut_t)color_gamut,
                       (uhdr_color_transfer_t)color_transfer,
                       (uhdr_color_range_t)color_range,
                       (unsigned int)width,
                       (unsigned int)height,
                       {lumaBody, cbBody, crBody},
                       {(unsigned int)y_stride, (unsigned int)u_stride, (unsigned int)v_stride}};
  auto status =
      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
  env->ReleaseByteArrayElements(y_buff, lumaBody, 0);
  env->ReleaseByteArrayElements(u_buff, cbBody, 0);
  env->ReleaseByteArrayElements(v_buff, crBody, 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setCompressedImageNative(
    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jint color_gamut, jint color_transfer,
    jint range, jint intent) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(data);
  RET_IF_TRUE(length < size, "java/io/IOException",
              "compressed image byteArray size is less than configured size")
  jbyte *body = env->GetByteArrayElements(data, nullptr);
  uhdr_compressed_image_t img{body,
                              (unsigned int)size,
                              (unsigned int)length,
                              (uhdr_color_gamut_t)color_gamut,
                              (uhdr_color_transfer_t)color_transfer,
                              (uhdr_color_range_t)range};
  auto status =
      uhdr_enc_set_compressed_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
  env->ReleaseByteArrayElements(data, body, 0);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_enc_set_compressed_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapImageInfoNative(
    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jfloatArray max_content_boost,
    jfloatArray min_content_boost, jfloatArray gainmap_gamma, jfloatArray offset_sdr,
    jfloatArray offset_hdr, jfloat hdr_capacity_min, jfloat hdr_capacity_max,
    jboolean use_base_color_space) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(data);
  RET_IF_TRUE(length < size, "java/io/IOException",
              "compressed image byteArray size is less than configured size")
  jbyte *body = env->GetByteArrayElements(data, nullptr);
  uhdr_compressed_image_t img{body,
                              (unsigned int)size,
                              (unsigned int)length,
                              UHDR_CG_UNSPECIFIED,
                              UHDR_CT_UNSPECIFIED,
                              UHDR_CR_UNSPECIFIED};

#define GET_FLOAT_ARRAY(env, srcArray, dstArray)                                   \
  {                                                                                \
    RET_IF_TRUE(srcArray == nullptr, "java/io/IOException", "received nullptr");   \
    jsize length = env->GetArrayLength(srcArray);                                  \
    RET_IF_TRUE(length != 3, "java/io/IOException", "array must have 3 elements"); \
    env->GetFloatArrayRegion(srcArray, 0, 3, dstArray);                            \
  }
  uhdr_gainmap_metadata_t metadata{};
  GET_FLOAT_ARRAY(env, max_content_boost, metadata.max_content_boost)
  GET_FLOAT_ARRAY(env, min_content_boost, metadata.min_content_boost)
  GET_FLOAT_ARRAY(env, gainmap_gamma, metadata.gamma)
  GET_FLOAT_ARRAY(env, offset_sdr, metadata.offset_sdr)
  GET_FLOAT_ARRAY(env, offset_hdr, metadata.offset_hdr)
  metadata.hdr_capacity_min = hdr_capacity_min;
  metadata.hdr_capacity_max = hdr_capacity_max;
  metadata.use_base_cg = use_base_color_space;
  auto status = uhdr_enc_set_gainmap_image((uhdr_codec_private_t *)handle, &img, &metadata);
  env->ReleaseByteArrayElements(data, body, 0);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_enc_set_gainmap_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setExifDataNative(JNIEnv *env, jobject thiz,
                                                                        jbyteArray data,
                                                                        jint size) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  jsize length = env->GetArrayLength(data);
  RET_IF_TRUE(length < size, "java/io/IOException",
              "compressed image byteArray size is less than configured size")
  jbyte *body = env->GetByteArrayElements(data, nullptr);
  uhdr_mem_block_t exif{body, (unsigned int)size, (unsigned int)length};
  auto status = uhdr_enc_set_exif_data((uhdr_codec_private_t *)handle, &exif);
  env->ReleaseByteArrayElements(data, body, 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_exif_data() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setQualityFactorNative(JNIEnv *env,
                                                                             jobject thiz,
                                                                             jint quality_factor,
                                                                             jint intent) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_enc_set_quality((uhdr_codec_private_t *)handle, quality_factor,
                                     (uhdr_img_label_t)intent);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_quality() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMultiChannelGainMapEncodingNative(
    JNIEnv *env, jobject thiz, jboolean enable) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status =
      uhdr_enc_set_using_multi_channel_gainmap((uhdr_codec_private_t *)handle, enable ? 1 : 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail
                                : "uhdr_enc_set_using_multi_channel_gainmap() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapScaleFactorNative(
    JNIEnv *env, jobject thiz, jint scale_factor) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_enc_set_gainmap_scale_factor((uhdr_codec_private_t *)handle, scale_factor);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_enc_set_gainmap_scale_factor() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapGammaNative(JNIEnv *env,
                                                                            jobject thiz,
                                                                            jfloat gamma) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_enc_set_gainmap_gamma((uhdr_codec_private_t *)handle, gamma);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_enc_set_gainmap_gamma() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setEncPresetNative(JNIEnv *env, jobject thiz,
                                                                         jint preset) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_enc_set_preset((uhdr_codec_private_t *)handle, (uhdr_enc_preset_t)preset);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_enc_set_preset() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setOutputFormatNative(JNIEnv *env,
                                                                            jobject thiz,
                                                                            jint media_type) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status =
      uhdr_enc_set_output_format((uhdr_codec_private_t *)handle, (uhdr_codec_t)media_type);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_enc_set_output_format() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMinMaxContentBoostNative(
    JNIEnv *env, jobject thiz, jfloat min_content_boost, jfloat max_content_boost) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_enc_set_min_max_content_boost((uhdr_codec_private_t *)handle,
                                                   min_content_boost, max_content_boost);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail
                                : "uhdr_enc_set_min_max_content_boost() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setTargetDisplayPeakBrightnessNative(
    JNIEnv *env, jobject thiz, jfloat nits) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_enc_set_target_display_peak_brightness((uhdr_codec_private_t *)handle, nits);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail
                  ? status.detail
                  : "uhdr_enc_set_target_display_peak_brightness() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_encodeNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  auto status = uhdr_encode((uhdr_codec_private_t *)handle);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_encode() returned with error")
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_getOutputNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  RET_VAL_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance", nullptr)
  auto enc_output = uhdr_get_encoded_stream((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(enc_output == nullptr, "java/io/IOException",
                  "no output returned, may be call to uhdr_encode() was not made or encountered "
                  "error during encoding process.",
                  nullptr)
  RET_VAL_IF_TRUE(enc_output->data_sz >= INT32_MAX, "java/lang/OutOfMemoryError",
                  "encoded output size exceeds integer max", nullptr)
  jbyteArray output = env->NewByteArray(enc_output->data_sz);
  RET_VAL_IF_TRUE(output == nullptr, "java/io/IOException", "failed to allocate storage for output",
                  nullptr)
  env->SetByteArrayRegion(output, 0, enc_output->data_sz, (jbyte *)enc_output->data);
  return output;
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_resetNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
  uhdr_reset_encoder((uhdr_codec_private_t *)handle);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_isUHDRImageNative(JNIEnv *env, jclass clazz,
                                                                        jbyteArray data,
                                                                        jint size) {
  jsize length = env->GetArrayLength(data);
  RET_VAL_IF_TRUE(length < size, "java/io/IOException",
                  "compressed image byteArray size is less than configured size", 0)
  jbyte *body = env->GetByteArrayElements(data, nullptr);
  auto status = is_uhdr_image(body, size);
  env->ReleaseByteArrayElements(data, body, 0);
  return status;
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_init(JNIEnv *env, jobject thiz) {
  jclass clazz = env->GetObjectClass(thiz);
  RET_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error")
  jfieldID fid = env->GetFieldID(clazz, "handle", "J");
  RET_IF_TRUE(fid == nullptr, "java/io/IOException",
              "GetFieldID for field 'handle' returned with error")
  uhdr_codec_private_t *handle = uhdr_create_decoder();
  RET_IF_TRUE(handle == nullptr, "java/lang/OutOfMemoryError",
              "Unable to allocate decoder instance")
  env->SetLongField(thiz, fid, (jlong)handle);
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_destroy(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  if (!handle) {
    uhdr_release_decoder((uhdr_codec_private *)handle);
    env->SetLongField(thiz, fid, (jlong)0);
  }
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setCompressedImageNative(
    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jint color_gamut, jint color_transfer,
    jint range) {
  RET_IF_TRUE(size < 0, "java/io/IOException", "invalid compressed image size")
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  jsize length = env->GetArrayLength(data);
  RET_IF_TRUE(length < size, "java/io/IOException",
              "compressed image byteArray size is less than configured size")
  jbyte *body = env->GetByteArrayElements(data, nullptr);
  uhdr_compressed_image_t img{body,
                              (unsigned int)size,
                              (unsigned int)length,
                              (uhdr_color_gamut_t)color_gamut,
                              (uhdr_color_transfer_t)color_transfer,
                              (uhdr_color_range_t)range};
  uhdr_error_info_t status = uhdr_dec_set_image((uhdr_codec_private_t *)handle, &img);
  env->ReleaseByteArrayElements(data, body, 0);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_dec_set_image() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setOutputFormatNative(JNIEnv *env,
                                                                            jobject thiz,
                                                                            jint fmt) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_error_info_t status =
      uhdr_dec_set_out_img_format((uhdr_codec_private_t *)handle, (uhdr_img_fmt_t)fmt);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_dec_set_out_img_format() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setColorTransferNative(JNIEnv *env,
                                                                             jobject thiz,
                                                                             jint ct) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_error_info_t status =
      uhdr_dec_set_out_color_transfer((uhdr_codec_private_t *)handle, (uhdr_color_transfer_t)ct);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_dec_set_out_color_transfer() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setMaxDisplayBoostNative(
    JNIEnv *env, jobject thiz, jfloat display_boost) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_error_info_t status =
      uhdr_dec_set_out_max_display_boost((uhdr_codec_private_t *)handle, (float)display_boost);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail
                                : "uhdr_dec_set_out_max_display_boost() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_enableGpuAccelerationNative(JNIEnv *env,
                                                                                  jobject thiz,
                                                                                  jint enable) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_error_info_t status = uhdr_enable_gpu_acceleration((uhdr_codec_private_t *)handle, enable);
  RET_IF_TRUE(
      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
      status.has_detail ? status.detail : "uhdr_enable_gpu_acceleration() returned with error")
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_probeNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_error_info_t status = uhdr_dec_probe((uhdr_codec_private_t *)handle);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_dec_probe() returned with error")
}

extern "C" JNIEXPORT jint JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getImageWidthNative(JNIEnv *env,
                                                                          jobject thiz) {
  GET_HANDLE_VAL(-1)
  auto val = uhdr_dec_get_image_width((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
  return val;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getImageHeightNative(JNIEnv *env,
                                                                           jobject thiz) {
  GET_HANDLE_VAL(-1)
  auto val = uhdr_dec_get_image_height((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
  return val;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapWidthNative(JNIEnv *env,
                                                                            jobject thiz) {
  GET_HANDLE_VAL(-1)
  auto val = uhdr_dec_get_gainmap_width((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
  return val;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapHeightNative(JNIEnv *env,
                                                                             jobject thiz) {
  GET_HANDLE_VAL(-1)
  auto val = uhdr_dec_get_gainmap_height((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
  return val;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getExifNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  uhdr_mem_block_t *exifData = uhdr_dec_get_exif((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(exifData == nullptr, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
  jbyteArray data = env->NewByteArray(exifData->data_sz);
  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
  std::memcpy(dataptr, exifData->data, exifData->data_sz);
  env->ReleaseByteArrayElements(data, dataptr, 0);
  return data;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getIccNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  uhdr_mem_block_t *iccData = uhdr_dec_get_icc((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(iccData == nullptr, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
  jbyteArray data = env->NewByteArray(iccData->data_sz);
  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
  std::memcpy(dataptr, iccData->data, iccData->data_sz);
  env->ReleaseByteArrayElements(data, dataptr, 0);
  return data;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getBaseImageNative(JNIEnv *env,
                                                                         jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  uhdr_mem_block_t *baseImgData = uhdr_dec_get_base_image((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(baseImgData == nullptr, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
  jbyteArray data = env->NewByteArray(baseImgData->data_sz);
  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
  std::memcpy(dataptr, baseImgData->data, baseImgData->data_sz);
  env->ReleaseByteArrayElements(data, dataptr, 0);
  return data;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapImageNative(JNIEnv *env,
                                                                            jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  uhdr_mem_block_t *gainmapImgData = uhdr_dec_get_gainmap_image((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(gainmapImgData == nullptr, "java/io/IOException",
                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
  jbyteArray data = env->NewByteArray(gainmapImgData->data_sz);
  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
  std::memcpy(dataptr, gainmapImgData->data, gainmapImgData->data_sz);
  env->ReleaseByteArrayElements(data, dataptr, 0);
  return data;
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainmapMetadataNative(JNIEnv *env,
                                                                               jobject thiz) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_gainmap_metadata_t *gainmap_metadata =
      uhdr_dec_get_gainmap_metadata((uhdr_codec_private_t *)handle);
  RET_IF_TRUE(gainmap_metadata == nullptr, "java/io/IOException",
              "uhdr_dec_probe() is not yet called or it has returned with error")
#define SET_FLOAT_ARRAY_FIELD(name, valArray)                         \
  {                                                                   \
    jfieldID fID = env->GetFieldID(clazz, name, "[F");                \
    RET_IF_TRUE(fID == nullptr, "java/io/IOException",                \
                "GetFieldID for field " #name " returned with error") \
    jfloatArray array = env->NewFloatArray(3);                        \
    RET_IF_TRUE(array == nullptr, "java/io/IOException",              \
                "Failed to allocate float array for field " #name)    \
    env->SetFloatArrayRegion(array, 0, 3, (const jfloat *)valArray);  \
    env->SetObjectField(thiz, fID, array);                            \
    env->DeleteLocalRef(array);                                       \
  }

#define SET_FLOAT_FIELD(name, val)                                    \
  {                                                                   \
    jfieldID fID = env->GetFieldID(clazz, name, "F");                 \
    RET_IF_TRUE(fID == nullptr, "java/io/IOException",                \
                "GetFieldID for field " #name " returned with error") \
    env->SetFloatField(thiz, fID, (jfloat)val);                       \
  }
  SET_FLOAT_ARRAY_FIELD("maxContentBoost", gainmap_metadata->max_content_boost)
  SET_FLOAT_ARRAY_FIELD("minContentBoost", gainmap_metadata->min_content_boost)
  SET_FLOAT_ARRAY_FIELD("gamma", gainmap_metadata->gamma)
  SET_FLOAT_ARRAY_FIELD("offsetSdr", gainmap_metadata->offset_sdr)
  SET_FLOAT_ARRAY_FIELD("offsetHdr", gainmap_metadata->offset_hdr)
  SET_FLOAT_FIELD("hdrCapacityMin", gainmap_metadata->hdr_capacity_min)
  SET_FLOAT_FIELD("hdrCapacityMax", gainmap_metadata->hdr_capacity_max)
#define SET_BOOLEAN_FIELD(name, val)                                  \
  {                                                                   \
    jfieldID fID = env->GetFieldID(clazz, name, "Z");                 \
    RET_IF_TRUE(fID == nullptr, "java/io/IOException",                \
                "GetFieldID for field " #name " returned with error") \
    env->SetBooleanField(thiz, fID, (jboolean)val);                   \
  }
  SET_BOOLEAN_FIELD("useBaseColorSpace", gainmap_metadata->use_base_cg)
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_decodeNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  auto status = uhdr_decode((uhdr_codec_private_t *)handle);
  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
              status.has_detail ? status.detail : "uhdr_decode() returned with error")
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getDecodedImageNative(JNIEnv *env,
                                                                            jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  uhdr_raw_image_t *decodedImg = uhdr_get_decoded_image((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(decodedImg == nullptr, "java/io/IOException",
                  "uhdr_decode() is not yet called or it has returned with error", nullptr)
  int bpp = decodedImg->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
  jbyteArray data = env->NewByteArray(decodedImg->stride[UHDR_PLANE_PACKED] * decodedImg->h * bpp);
  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
  std::memcpy(dataptr, decodedImg->planes[UHDR_PLANE_PACKED],
              decodedImg->stride[UHDR_PLANE_PACKED] * decodedImg->h * bpp);
  env->ReleaseByteArrayElements(data, dataptr, 0);
#define SET_INT_FIELD(name, val)                                                   \
  {                                                                                \
    jfieldID fID = env->GetFieldID(clazz, name, "I");                              \
    RET_VAL_IF_TRUE(fID == nullptr, "java/io/IOException",                         \
                    "GetFieldID for field " #name " returned with error", nullptr) \
    env->SetIntField(thiz, fID, (jint)val);                                        \
  }
  SET_INT_FIELD("imgWidth", decodedImg->w)
  SET_INT_FIELD("imgHeight", decodedImg->h)
  SET_INT_FIELD("imgStride", decodedImg->stride[UHDR_PLANE_PACKED])
  SET_INT_FIELD("imgFormat", decodedImg->fmt)
  SET_INT_FIELD("imgGamut", decodedImg->cg)
  SET_INT_FIELD("imgTransfer", decodedImg->ct)
  SET_INT_FIELD("imgRange", decodedImg->range)
  return data;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getDecodedGainMapImageNative(JNIEnv *env,
                                                                                   jobject thiz) {
  GET_HANDLE_VAL(nullptr)
  uhdr_raw_image_t *gainmapImg = uhdr_get_decoded_gainmap_image((uhdr_codec_private_t *)handle);
  RET_VAL_IF_TRUE(gainmapImg == nullptr, "java/io/IOException",
                  "uhdr_decode() is not yet called or it has returned with error", nullptr)
  int bpp = gainmapImg->fmt == UHDR_IMG_FMT_32bppRGBA8888 ? 4 : 1;
  jbyteArray data = env->NewByteArray(gainmapImg->stride[UHDR_PLANE_PACKED] * gainmapImg->h * bpp);
  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
  std::memcpy(dataptr, gainmapImg->planes[UHDR_PLANE_PACKED],
              gainmapImg->stride[UHDR_PLANE_PACKED] * gainmapImg->h * bpp);
  env->ReleaseByteArrayElements(data, dataptr, 0);
  SET_INT_FIELD("gainmapWidth", gainmapImg->w)
  SET_INT_FIELD("gainmapHeight", gainmapImg->h)
  SET_INT_FIELD("gainmapStride", gainmapImg->stride[UHDR_PLANE_PACKED])
  SET_INT_FIELD("gainmapFormat", gainmapImg->fmt)
  return data;
}

extern "C" JNIEXPORT void JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_resetNative(JNIEnv *env, jobject thiz) {
  GET_HANDLE()
  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
  uhdr_reset_decoder((uhdr_codec_private_t *)handle);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRCommon_getVersionStringNative(JNIEnv *env,
                                                                            jclass clazz) {
  std::string version{"v" UHDR_LIB_VERSION_STR};
  return env->NewStringUTF(version.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_google_media_codecs_ultrahdr_UltraHDRCommon_getVersionNative(JNIEnv *env, jclass clazz) {
  return UHDR_LIB_VERSION;
}
