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

#include <ultrahdr/jpegdecoderhelper.h>
#include <ultrahdr/icc.h>
#include <gtest/gtest.h>
#include <utils/Log.h>

#include <fcntl.h>

namespace android::ultrahdr {

// No ICC or EXIF
#define YUV_IMAGE "/sdcard/Documents/minnie-320x240-yuv.jpg"
#define YUV_IMAGE_SIZE 20193
// Has ICC and EXIF
#define YUV_ICC_IMAGE "/sdcard/Documents/minnie-320x240-yuv-icc.jpg"
#define YUV_ICC_IMAGE_SIZE 34266
// No ICC or EXIF
#define GREY_IMAGE "/sdcard/Documents/minnie-320x240-y.jpg"
#define GREY_IMAGE_SIZE 20193

#define IMAGE_WIDTH 320
#define IMAGE_HEIGHT 240

class JpegDecoderHelperTest : public testing::Test {
public:
    struct Image {
        std::unique_ptr<uint8_t[]> buffer;
        size_t size;
    };
    JpegDecoderHelperTest();
    ~JpegDecoderHelperTest();
protected:
    virtual void SetUp();
    virtual void TearDown();

    Image mYuvImage, mYuvIccImage, mGreyImage;
};

JpegDecoderHelperTest::JpegDecoderHelperTest() {}

JpegDecoderHelperTest::~JpegDecoderHelperTest() {}

static size_t getFileSize(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        ALOGW("%s : fstat failed", __func__);
        return 0;
    }
    return st.st_size; // bytes
}

static bool loadFile(const char filename[], JpegDecoderHelperTest::Image* result) {
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

void JpegDecoderHelperTest::SetUp() {
    if (!loadFile(YUV_IMAGE, &mYuvImage)) {
        FAIL() << "Load file " << YUV_IMAGE << " failed";
    }
    mYuvImage.size = YUV_IMAGE_SIZE;
    if (!loadFile(YUV_ICC_IMAGE, &mYuvIccImage)) {
        FAIL() << "Load file " << YUV_ICC_IMAGE << " failed";
    }
    mYuvIccImage.size = YUV_ICC_IMAGE_SIZE;
    if (!loadFile(GREY_IMAGE, &mGreyImage)) {
        FAIL() << "Load file " << GREY_IMAGE << " failed";
    }
    mGreyImage.size = GREY_IMAGE_SIZE;
}

void JpegDecoderHelperTest::TearDown() {}

TEST_F(JpegDecoderHelperTest, decodeYuvImage) {
    JpegDecoderHelper decoder;
    EXPECT_TRUE(decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size));
    ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
    EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
              ULTRAHDR_COLORGAMUT_UNSPECIFIED);
}

TEST_F(JpegDecoderHelperTest, decodeYuvIccImage) {
    JpegDecoderHelper decoder;
    EXPECT_TRUE(decoder.decompressImage(mYuvIccImage.buffer.get(), mYuvIccImage.size));
    ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
    EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
              ULTRAHDR_COLORGAMUT_BT709);
}

TEST_F(JpegDecoderHelperTest, decodeGreyImage) {
    JpegDecoderHelper decoder;
    EXPECT_TRUE(decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size));
    ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
}

TEST_F(JpegDecoderHelperTest, getCompressedImageParameters) {
    size_t width = 0, height = 0;
    std::vector<uint8_t> icc, exif;

    JpegDecoderHelper decoder;
    EXPECT_TRUE(decoder.getCompressedImageParameters(mYuvImage.buffer.get(), mYuvImage.size,
                                                     &width, &height, &icc, &exif));

    EXPECT_EQ(width, IMAGE_WIDTH);
    EXPECT_EQ(height, IMAGE_HEIGHT);
    EXPECT_EQ(icc.size(), 0);
    EXPECT_EQ(exif.size(), 0);
}

TEST_F(JpegDecoderHelperTest, getCompressedImageParametersIcc) {
    size_t width = 0, height = 0;
    std::vector<uint8_t> icc, exif;

    JpegDecoderHelper decoder;
    EXPECT_TRUE(decoder.getCompressedImageParameters(mYuvIccImage.buffer.get(), mYuvIccImage.size,
                                                     &width, &height, &icc, &exif));

    EXPECT_EQ(width, IMAGE_WIDTH);
    EXPECT_EQ(height, IMAGE_HEIGHT);
    EXPECT_GT(icc.size(), 0);
    EXPECT_GT(exif.size(), 0);

    EXPECT_EQ(IccHelper::readIccColorGamut(icc.data(), icc.size()),
              ULTRAHDR_COLORGAMUT_BT709);
}

}  // namespace android::ultrahdr
