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

#include <ultrahdr/jpegencoderhelper.h>
#include <gtest/gtest.h>
#include <utils/Log.h>

#include <fcntl.h>

namespace android::ultrahdr {

#define ALIGNED_IMAGE "/sdcard/Documents/minnie-320x240.yu12"
#define ALIGNED_IMAGE_WIDTH 320
#define ALIGNED_IMAGE_HEIGHT 240
#define SINGLE_CHANNEL_IMAGE "/sdcard/Documents/minnie-320x240.y"
#define SINGLE_CHANNEL_IMAGE_WIDTH ALIGNED_IMAGE_WIDTH
#define SINGLE_CHANNEL_IMAGE_HEIGHT ALIGNED_IMAGE_HEIGHT
#define UNALIGNED_IMAGE "/sdcard/Documents/minnie-318x240.yu12"
#define UNALIGNED_IMAGE_WIDTH 318
#define UNALIGNED_IMAGE_HEIGHT 240
#define JPEG_QUALITY 90

class JpegEncoderHelperTest : public testing::Test {
public:
    struct Image {
        std::unique_ptr<uint8_t[]> buffer;
        size_t width;
        size_t height;
    };
    JpegEncoderHelperTest();
    ~JpegEncoderHelperTest();
protected:
    virtual void SetUp();
    virtual void TearDown();

    Image mAlignedImage, mUnalignedImage, mSingleChannelImage;
};

JpegEncoderHelperTest::JpegEncoderHelperTest() {}

JpegEncoderHelperTest::~JpegEncoderHelperTest() {}

static size_t getFileSize(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        ALOGW("%s : fstat failed", __func__);
        return 0;
    }
    return st.st_size; // bytes
}

static bool loadFile(const char filename[], JpegEncoderHelperTest::Image* result) {
    int fd = open(filename, O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    int length = getFileSize(fd);
    if (length == 0) {
        close(fd);
        return false;
    }
    result->buffer.reset(new uint8_t[length]);
    if (read(fd, result->buffer.get(), length) != static_cast<ssize_t>(length)) {
        close(fd);
        return false;
    }
    close(fd);
    return true;
}

void JpegEncoderHelperTest::SetUp() {
    if (!loadFile(ALIGNED_IMAGE, &mAlignedImage)) {
        FAIL() << "Load file " << ALIGNED_IMAGE << " failed";
    }
    mAlignedImage.width = ALIGNED_IMAGE_WIDTH;
    mAlignedImage.height = ALIGNED_IMAGE_HEIGHT;
    if (!loadFile(UNALIGNED_IMAGE, &mUnalignedImage)) {
        FAIL() << "Load file " << UNALIGNED_IMAGE << " failed";
    }
    mUnalignedImage.width = UNALIGNED_IMAGE_WIDTH;
    mUnalignedImage.height = UNALIGNED_IMAGE_HEIGHT;
    if (!loadFile(SINGLE_CHANNEL_IMAGE, &mSingleChannelImage)) {
        FAIL() << "Load file " << SINGLE_CHANNEL_IMAGE << " failed";
    }
    mSingleChannelImage.width = SINGLE_CHANNEL_IMAGE_WIDTH;
    mSingleChannelImage.height = SINGLE_CHANNEL_IMAGE_HEIGHT;
}

void JpegEncoderHelperTest::TearDown() {}

TEST_F(JpegEncoderHelperTest, encodeAlignedImage) {
    JpegEncoderHelper encoder;
    EXPECT_TRUE(encoder.compressImage(mAlignedImage.buffer.get(), mAlignedImage.width,
                                      mAlignedImage.height, JPEG_QUALITY, NULL, 0));
    ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
}

TEST_F(JpegEncoderHelperTest, encodeUnalignedImage) {
    JpegEncoderHelper encoder;
    EXPECT_TRUE(encoder.compressImage(mUnalignedImage.buffer.get(), mUnalignedImage.width,
                                      mUnalignedImage.height, JPEG_QUALITY, NULL, 0));
    ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
}

TEST_F(JpegEncoderHelperTest, encodeSingleChannelImage) {
    JpegEncoderHelper encoder;
    EXPECT_TRUE(encoder.compressImage(mSingleChannelImage.buffer.get(), mSingleChannelImage.width,
                                         mSingleChannelImage.height, JPEG_QUALITY, NULL, 0, true));
    ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
}

}  // namespace android::ultrahdr

