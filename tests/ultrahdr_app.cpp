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

#include <unistd.h>

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iostream>

#include "ultrahdr/ultrahdrcommon.h"
#include "ultrahdr/gainmapmath.h"
#include "ultrahdr/jpegr.h"

using namespace ultrahdr;

const float BT601YUVtoRGBMatrix[9] =
        {1, 0, 1.402, 1, (-0.202008 / 0.587), (-0.419198 / 0.587), 1.0, 1.772, 0.0};
const float BT709YUVtoRGBMatrix[9] =
        {1, 0, 1.5748, 1, (-0.13397432 / 0.7152), (-0.33480248 / 0.7152), 1.0, 1.8556, 0.0};
const float BT2020YUVtoRGBMatrix[9] =
        {1, 0, 1.4746, 1, (-0.11156702 / 0.6780), (-0.38737742 / 0.6780), 1, 1.8814, 0};

const float BT601RGBtoYUVMatrix[9] = {0.299,
                                      0.587,
                                      0.114,
                                      (-0.299 / 1.772),
                                      (-0.587 / 1.772),
                                      0.5,
                                      0.5,
                                      (-0.587 / 1.402),
                                      (-0.114 / 1.402)};
const float BT709RGBtoYUVMatrix[9] = {0.2126,
                                      0.7152,
                                      0.0722,
                                      (-0.2126 / 1.8556),
                                      (-0.7152 / 1.8556),
                                      0.5,
                                      0.5,
                                      (-0.7152 / 1.5748),
                                      (-0.0722 / 1.5748)};
const float BT2020RGBtoYUVMatrix[9] = {0.2627,
                                       0.6780,
                                       0.0593,
                                       (-0.2627 / 1.8814),
                                       (-0.6780 / 1.8814),
                                       0.5,
                                       0.5,
                                       (-0.6780 / 1.4746),
                                       (-0.0593 / 1.4746)};

static bool loadFile(const char* filename, void*& result, int length) {
    std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
    if (ifd.good()) {
        int size = ifd.tellg();
        if (size < length) {
            std::cerr << "requested to read " << length << " bytes from file : " << filename
                      << ", file contains only " << size << " bytes" << std::endl;
            return false;
        }
        ifd.seekg(0, std::ios::beg);
        result = malloc(length);
        if (result == nullptr) {
            std::cerr << "failed to allocate memory to store contents of file : " << filename
                      << std::endl;
            return false;
        }
        ifd.read(static_cast<char*>(result), length);
        return true;
    }
    std::cerr << "unable to open file : " << filename << std::endl;
    return false;
}

static bool writeFile(const char* filename, void*& result, int length) {
    std::ofstream ofd(filename, std::ios::binary);
    if (ofd.is_open()) {
        ofd.write(static_cast<char*>(result), length);
        return true;
    }
    std::cerr << "unable to write to file : " << filename << std::endl;
    return false;
}

class UltraHdrAppInput {
public:
    UltraHdrAppInput(const char* p010File, const char* yuv420File, size_t width, size_t height,
                     ultrahdr_color_gamut p010Cg = ULTRAHDR_COLORGAMUT_BT709,
                     ultrahdr_color_gamut yuv420Cg = ULTRAHDR_COLORGAMUT_BT709,
                     ultrahdr_transfer_function tf = ULTRAHDR_TF_HLG, int quality = 100,
                     ultrahdr_output_format of = ULTRAHDR_OUTPUT_HDR_HLG)
          : mP010File(p010File),
            mYuv420File(yuv420File),
            mJpegRFile(nullptr),
            mWidth(width),
            mHeight(height),
            mP010Cg(p010Cg),
            mYuv420Cg(yuv420Cg),
            mTf(tf),
            mQuality(quality),
            mOf(of),
            mMode(0){};

    UltraHdrAppInput(const char* jpegRFile, ultrahdr_output_format of = ULTRAHDR_OUTPUT_HDR_HLG)
          : mP010File(nullptr),
            mYuv420File(nullptr),
            mJpegRFile(jpegRFile),
            mWidth(0),
            mHeight(0),
            mP010Cg(ULTRAHDR_COLORGAMUT_UNSPECIFIED),
            mYuv420Cg(ULTRAHDR_COLORGAMUT_UNSPECIFIED),
            mTf(ULTRAHDR_TF_UNSPECIFIED),
            mQuality(100),
            mOf(of),
            mMode(1){};

    ~UltraHdrAppInput() {
        if (mRawP010Image.data) free(mRawP010Image.data);
        if (mRawP010Image.chroma_data) free(mRawP010Image.chroma_data);
        if (mRawRgba1010102Image.data) free(mRawRgba1010102Image.data);
        if (mRawRgba1010102Image.chroma_data) free(mRawRgba1010102Image.chroma_data);
        if (mRawYuv420Image.data) free(mRawYuv420Image.data);
        if (mRawYuv420Image.chroma_data) free(mRawYuv420Image.chroma_data);
        if (mRawRgba8888Image.data) free(mRawRgba8888Image.data);
        if (mRawRgba8888Image.chroma_data) free(mRawRgba8888Image.chroma_data);
        if (mJpegImgR.data) free(mJpegImgR.data);
        if (mDestImage.data) free(mDestImage.data);
        if (mDestImage.chroma_data) free(mDestImage.chroma_data);
        if (mDestYUV444Image.data) free(mDestYUV444Image.data);
        if (mDestYUV444Image.chroma_data) free(mDestYUV444Image.chroma_data);
    }

    bool fillJpegRImageHandle();
    bool fillP010ImageHandle();
    bool convertP010ToRGBImage();
    bool fillYuv420ImageHandle();
    bool convertYuv420ToRGBImage();
    bool convertRgba8888ToYUV444Image();
    bool convertRgba1010102ToYUV444Image();
    bool encode();
    bool decode();
    void computeRGBHdrPSNR();
    void computeRGBSdrPSNR();
    void computeYUVHdrPSNR();
    void computeYUVSdrPSNR();

    const char* mP010File;
    const char* mYuv420File;
    const char* mJpegRFile;
    const int mWidth;
    const int mHeight;
    const ultrahdr_color_gamut mP010Cg;
    const ultrahdr_color_gamut mYuv420Cg;
    const ultrahdr_transfer_function mTf;
    const int mQuality;
    const ultrahdr_output_format mOf;
    const int mMode;
    jpegr_uncompressed_struct mRawP010Image{};
    jpegr_uncompressed_struct mRawRgba1010102Image{};
    jpegr_uncompressed_struct mRawYuv420Image{};
    jpegr_uncompressed_struct mRawRgba8888Image{};
    jpegr_compressed_struct mJpegImgR{};
    jpegr_uncompressed_struct mDestImage{};
    jpegr_uncompressed_struct mDestYUV444Image{};
    double mPsnr[3]{};
};

bool UltraHdrAppInput::fillP010ImageHandle() {
    const int bpp = 2;
    int p010Size = mWidth * mHeight * bpp * 1.5;
    mRawP010Image.width = mWidth;
    mRawP010Image.height = mHeight;
    mRawP010Image.colorGamut = mP010Cg;
    return loadFile(mP010File, mRawP010Image.data, p010Size);
}

bool UltraHdrAppInput::fillYuv420ImageHandle() {
    int yuv420Size = mWidth * mHeight * 1.5;
    mRawYuv420Image.width = mWidth;
    mRawYuv420Image.height = mHeight;
    mRawYuv420Image.colorGamut = mYuv420Cg;
    return loadFile(mYuv420File, mRawYuv420Image.data, yuv420Size);
}

bool UltraHdrAppInput::fillJpegRImageHandle() {
    std::ifstream ifd(mJpegRFile, std::ios::binary | std::ios::ate);
    if (ifd.good()) {
        int size = ifd.tellg();
        mJpegImgR.length = size;
        mJpegImgR.maxLength = size;
        mJpegImgR.data = nullptr;
        mJpegImgR.colorGamut = mYuv420Cg;
        ifd.close();
        return loadFile(mJpegRFile, mJpegImgR.data, size);
    }
    return false;
}

bool UltraHdrAppInput::encode() {
    if (!fillP010ImageHandle()) return false;
    if (mYuv420File != nullptr && !fillYuv420ImageHandle()) return false;

    mJpegImgR.maxLength = std::max(static_cast<size_t>(8 * 1024) /* min size 8kb */,
                                   mRawP010Image.width * mRawP010Image.height * 3 * 2);
    mJpegImgR.data = malloc(mJpegImgR.maxLength);
    if (mJpegImgR.data == nullptr) {
        std::cerr << "unable to allocate memory to store compressed image" << std::endl;
        return false;
    }

    JpegR jpegHdr;
    status_t status = UNKNOWN_ERROR;
    if (mYuv420File == nullptr) { // api-0
        status = jpegHdr.encodeJPEGR(&mRawP010Image, mTf, &mJpegImgR, mQuality, nullptr);
        if (OK != status) {
            std::cerr << "Encountered error during encodeJPEGR call, error code " << status
                      << std::endl;
            return false;
        }
    } else { // api-1
        status = jpegHdr.encodeJPEGR(&mRawP010Image, &mRawYuv420Image, mTf, &mJpegImgR, mQuality,
                                     nullptr);
        if (OK != status) {
            std::cerr << "Encountered error during encodeJPEGR call, error code " << status
                      << std::endl;
            return false;
        }
    }
    writeFile("out.jpeg", mJpegImgR.data, mJpegImgR.length);
    return true;
}

bool UltraHdrAppInput::decode() {
    if (mMode == 1 && !fillJpegRImageHandle()) return false;
    std::vector<uint8_t> iccData(0);
    std::vector<uint8_t> exifData(0);
    jpegr_info_struct info{0, 0, &iccData, &exifData};
    JpegR jpegHdr;
    status_t status = jpegHdr.getJPEGRInfo(&mJpegImgR, &info);
    if (OK == status) {
        size_t outSize = info.width * info.height * ((mOf == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
        mDestImage.data = malloc(outSize);
        if (mDestImage.data == nullptr) {
            std::cerr << "failed to allocate memory to store decoded output" << std::endl;
            return false;
        }
        status = jpegHdr.decodeJPEGR(&mJpegImgR, &mDestImage, FLT_MAX, nullptr, mOf, nullptr,
                                     nullptr);
        if (OK != status) {
            std::cerr << "Encountered error during decodeJPEGR call, error code " << status
                      << std::endl;
            return false;
        }
        writeFile("outrgb.raw", mDestImage.data, outSize);
    } else {
        std::cerr << "Encountered error during getJPEGRInfo call, error code " << status
                  << std::endl;
        return false;
    }
    return true;
}

bool UltraHdrAppInput::convertP010ToRGBImage() {
    const float* coeffs = BT2020YUVtoRGBMatrix;
    if (mP010Cg == ULTRAHDR_COLORGAMUT_BT709) {
        coeffs = BT709YUVtoRGBMatrix;
    } else if (mP010Cg == ULTRAHDR_COLORGAMUT_BT2100) {
        coeffs = BT2020YUVtoRGBMatrix;
    } else if (mP010Cg == ULTRAHDR_COLORGAMUT_P3) {
        coeffs = BT601YUVtoRGBMatrix;
    } else {
        std::cerr << "color matrix not present for gamut " << mP010Cg << " using BT2020Matrix"
                  << std::endl;
    }

    mRawRgba1010102Image.data = malloc(mRawP010Image.width * mRawP010Image.height * 4);
    if (mRawRgba1010102Image.data == nullptr) {
        std::cerr << "failed to allocate memory to store Rgba1010102" << std::endl;
        return false;
    }
    mRawRgba1010102Image.width = mRawP010Image.width;
    mRawRgba1010102Image.height = mRawP010Image.height;
    mRawRgba1010102Image.colorGamut = mRawP010Image.colorGamut;
    uint32_t* rgbData = static_cast<uint32_t*>(mRawRgba1010102Image.data);
    uint16_t* y = static_cast<uint16_t*>(mRawP010Image.data);
    uint16_t* u = y + mRawP010Image.width * mRawP010Image.height;
    uint16_t* v = u + 1;

    for (size_t i = 0; i < mRawP010Image.height; i++) {
        for (size_t j = 0; j < mRawP010Image.width; j++) {
            float y0 = float(y[mRawP010Image.width * i + j] >> 6);
            float u0 = float(u[mRawP010Image.width * (i / 2) + (j / 2) * 2] >> 6);
            float v0 = float(v[mRawP010Image.width * (i / 2) + (j / 2) * 2] >> 6);

            y0 = CLIP3(y0, 64.0f, 940.0f);
            u0 = CLIP3(u0, 64.0f, 960.0f);
            v0 = CLIP3(v0, 64.0f, 960.0f);

            y0 = (y0 - 64.0f) / 876.0f;
            u0 = (u0 - 64.0f) / 896.0f - 0.5f;
            v0 = (v0 - 64.0f) / 896.0f - 0.5f;

            float r = coeffs[0] * y0 + coeffs[1] * u0 + coeffs[2] * v0;
            float g = coeffs[3] * y0 + coeffs[4] * u0 + coeffs[5] * v0;
            float b = coeffs[6] * y0 + coeffs[7] * u0 + coeffs[8] * v0;

            r = CLIP3(r * 1023.0f + 0.5f, 0.0f, 1023.0f);
            g = CLIP3(g * 1023.0f + 0.5f, 0.0f, 1023.0f);
            b = CLIP3(b * 1023.0f + 0.5f, 0.0f, 1023.0f);

            int32_t r0 = int32_t(r);
            int32_t g0 = int32_t(g);
            int32_t b0 = int32_t(b);
            *rgbData = (0x3ff & r0) | ((0x3ff & g0) << 10) | ((0x3ff & b0) << 20) |
                    (0x3 << 30); // Set alpha to 1.0

            rgbData++;
        }
    }
    writeFile("inRgba1010102.raw", mRawRgba1010102Image.data,
              mRawP010Image.width * mRawP010Image.height * 4);
    return true;
}

bool UltraHdrAppInput::convertYuv420ToRGBImage() {
    mRawRgba8888Image.data = malloc(mRawYuv420Image.width * mRawYuv420Image.height * 4);
    if (mRawRgba8888Image.data == nullptr) {
        std::cerr << "failed to allocate memory to store rgba888" << std::endl;
        return false;
    }
    mRawRgba8888Image.width = mRawYuv420Image.width;
    mRawRgba8888Image.height = mRawYuv420Image.height;
    mRawRgba8888Image.colorGamut = mRawYuv420Image.colorGamut;
    uint32_t* rgbData = static_cast<uint32_t*>(mRawRgba8888Image.data);
    uint8_t* y = static_cast<uint8_t*>(mRawYuv420Image.data);
    uint8_t* u = y + (mRawYuv420Image.width * mRawYuv420Image.height);
    uint8_t* v = u + (mRawYuv420Image.width * mRawYuv420Image.height / 4);

    const float* coeffs = BT601YUVtoRGBMatrix;
    for (size_t i = 0; i < mRawYuv420Image.height; i++) {
        for (size_t j = 0; j < mRawYuv420Image.width; j++) {
            float y0 = float(y[mRawYuv420Image.width * i + j]);
            float u0 = float(u[mRawYuv420Image.width / 2 * (i / 2) + (j / 2)] - 128);
            float v0 = float(v[mRawYuv420Image.width / 2 * (i / 2) + (j / 2)] - 128);

            y0 /= 255.0f;
            u0 /= 255.0f;
            v0 /= 255.0f;

            float r = coeffs[0] * y0 + coeffs[1] * u0 + coeffs[2] * v0;
            float g = coeffs[3] * y0 + coeffs[4] * u0 + coeffs[5] * v0;
            float b = coeffs[6] * y0 + coeffs[7] * u0 + coeffs[8] * v0;

            r = r * 255.0f + 0.5f;
            g = g * 255.0f + 0.5f;
            b = b * 255.0f + 0.5f;

            r = CLIP3(r, 0.0f, 255.0f);
            g = CLIP3(g, 0.0f, 255.0f);
            b = CLIP3(b, 0.0f, 255.0f);

            int32_t r0 = int32_t(r);
            int32_t g0 = int32_t(g);
            int32_t b0 = int32_t(b);
            *rgbData = r0 | (g0 << 8) | (b0 << 16) | (255 << 24); // Set alpha to 1.0

            rgbData++;
        }
    }
    writeFile("inRgba8888.raw", mRawRgba8888Image.data,
              mRawYuv420Image.width * mRawYuv420Image.height * 4);
    return true;
}

bool UltraHdrAppInput::convertRgba8888ToYUV444Image() {
    mDestYUV444Image.data = malloc(mDestImage.width * mDestImage.height * 3);
    if (mDestYUV444Image.data == nullptr) {
        std::cerr << "failed to allocate memory to store yuv444" << std::endl;
        return false;
    }
    mDestYUV444Image.width = mDestImage.width;
    mDestYUV444Image.height = mDestImage.height;
    mDestYUV444Image.colorGamut = mDestImage.colorGamut;

    uint32_t* rgbData = static_cast<uint32_t*>(mDestImage.data);

    uint8_t* yData = static_cast<uint8_t*>(mDestYUV444Image.data);
    uint8_t* uData = yData + (mDestYUV444Image.width * mDestYUV444Image.height);
    uint8_t* vData = uData + (mDestYUV444Image.width * mDestYUV444Image.height);

    const float* coeffs = BT601RGBtoYUVMatrix;
    for (size_t i = 0; i < mDestImage.height; i++) {
        for (size_t j = 0; j < mDestImage.width; j++) {
            float r0 = float(rgbData[mDestImage.width * i + j] & 0xff);
            float g0 = float((rgbData[mDestImage.width * i + j] >> 8) & 0xff);
            float b0 = float((rgbData[mDestImage.width * i + j] >> 16) & 0xff);

            r0 /= 255.0f;
            g0 /= 255.0f;
            b0 /= 255.0f;

            float y = coeffs[0] * r0 + coeffs[1] * g0 + coeffs[2] * b0;
            float u = coeffs[3] * r0 + coeffs[4] * g0 + coeffs[5] * b0;
            float v = coeffs[6] * r0 + coeffs[7] * g0 + coeffs[8] * b0;

            y = y * 255.0f + 0.5f;
            u = u * 255.0f + 0.5f + 128.0f;
            v = v * 255.0f + 0.5f + 128.0f;

            y = CLIP3(y, 0.0f, 255.0f);
            u = CLIP3(u, 0.0f, 255.0f);
            v = CLIP3(v, 0.0f, 255.0f);

            yData[mDestYUV444Image.width * i + j] = uint8_t(y);
            uData[mDestYUV444Image.width * i + j] = uint8_t(u);
            vData[mDestYUV444Image.width * i + j] = uint8_t(v);
        }
    }
    writeFile("outyuv444.yuv", mDestYUV444Image.data,
              mDestYUV444Image.width * mDestYUV444Image.height * 3);
    return true;
}

bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
    const float* coeffs = BT2020RGBtoYUVMatrix;
    if (mP010Cg == ULTRAHDR_COLORGAMUT_BT709) {
        coeffs = BT709RGBtoYUVMatrix;
    } else if (mP010Cg == ULTRAHDR_COLORGAMUT_BT2100) {
        coeffs = BT2020RGBtoYUVMatrix;
    } else if (mP010Cg == ULTRAHDR_COLORGAMUT_P3) {
        coeffs = BT601RGBtoYUVMatrix;
    } else {
        std::cerr << "color matrix not present for gamut " << mP010Cg << " using BT2020Matrix"
                  << std::endl;
    }

    mDestYUV444Image.data = malloc(mDestImage.width * mDestImage.height * 3 * 2);
    if (mDestYUV444Image.data == nullptr) {
        std::cerr << "failed to allocate memory to store yuv444" << std::endl;
        return false;
    }
    mDestYUV444Image.width = mDestImage.width;
    mDestYUV444Image.height = mDestImage.height;
    mDestYUV444Image.colorGamut = mDestImage.colorGamut;

    uint32_t* rgbData = static_cast<uint32_t*>(mDestImage.data);

    uint16_t* yData = static_cast<uint16_t*>(mDestYUV444Image.data);
    uint16_t* uData = yData + (mDestYUV444Image.width * mDestYUV444Image.height);
    uint16_t* vData = uData + (mDestYUV444Image.width * mDestYUV444Image.height);

    for (size_t i = 0; i < mDestImage.height; i++) {
        for (size_t j = 0; j < mDestImage.width; j++) {
            float r0 = float(rgbData[mDestImage.width * i + j] & 0x3ff);
            float g0 = float((rgbData[mDestImage.width * i + j] >> 10) & 0x3ff);
            float b0 = float((rgbData[mDestImage.width * i + j] >> 20) & 0x3ff);

            r0 /= 1023.0f;
            g0 /= 1023.0f;
            b0 /= 1023.0f;

            float y = coeffs[0] * r0 + coeffs[1] * g0 + coeffs[2] * b0;
            float u = coeffs[3] * r0 + coeffs[4] * g0 + coeffs[5] * b0;
            float v = coeffs[6] * r0 + coeffs[7] * g0 + coeffs[8] * b0;

            y = (y * 876.0f) + 64.0f + 0.5f;
            u = (u * 896.0f) + 64.0f + 512.0f + 0.5f;
            v = (v * 896.0f) + 64.0f + 512.0f + 0.5f;

            y = CLIP3(y, 64.0f, 940.0f);
            u = CLIP3(u, 64.0f, 960.0f);
            v = CLIP3(v, 64.0f, 960.0f);

            yData[mDestYUV444Image.width * i + j] = uint16_t(y);
            uData[mDestYUV444Image.width * i + j] = uint16_t(u);
            vData[mDestYUV444Image.width * i + j] = uint16_t(v);
        }
    }
    writeFile("outyuv444.yuv", mDestYUV444Image.data,
              mDestYUV444Image.width * mDestYUV444Image.height * 3 * 2);
    return true;
}

void UltraHdrAppInput::computeRGBHdrPSNR() {
    if (mOf == ULTRAHDR_OUTPUT_SDR || mOf == ULTRAHDR_OUTPUT_HDR_LINEAR) {
        std::cout << "psnr not supported for output format " << mOf << std::endl;
        return;
    }
    uint32_t* rgbDataSrc = static_cast<uint32_t*>(mRawRgba1010102Image.data);
    uint32_t* rgbDataDst = static_cast<uint32_t*>(mDestImage.data);
    if (rgbDataSrc == nullptr || rgbDataDst == nullptr) {
        std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
        return;
    }
    if ((mOf == ULTRAHDR_OUTPUT_HDR_PQ && mTf != ULTRAHDR_TF_PQ) ||
        (mOf == ULTRAHDR_OUTPUT_HDR_HLG && mTf != ULTRAHDR_TF_HLG)) {
        std::cout << "input transfer function and output format are not compatible, psnr results "
                     "may be unreliable"
                  << std::endl;
    }
    uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
    for (size_t i = 0; i < mRawP010Image.width * mRawP010Image.height; i++) {
        int rSrc = *rgbDataSrc & 0x3ff;
        int rDst = *rgbDataDst & 0x3ff;
        rSqError += (rSrc - rDst) * (rSrc - rDst);

        int gSrc = (*rgbDataSrc >> 10) & 0x3ff;
        int gDst = (*rgbDataDst >> 10) & 0x3ff;
        gSqError += (gSrc - gDst) * (gSrc - gDst);

        int bSrc = (*rgbDataSrc >> 20) & 0x3ff;
        int bDst = (*rgbDataDst >> 20) & 0x3ff;
        bSqError += (bSrc - bDst) * (bSrc - bDst);

        rgbDataSrc++;
        rgbDataDst++;
    }
    double meanSquareError = (double)rSqError / (mRawP010Image.width * mRawP010Image.height);
    mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

    meanSquareError = (double)gSqError / (mRawP010Image.width * mRawP010Image.height);
    mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

    meanSquareError = (double)bSqError / (mRawP010Image.width * mRawP010Image.height);
    mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

    std::cout << "psnr r :: " << mPsnr[0] << " psnr g :: " << mPsnr[1] << " psnr b :: " << mPsnr[2]
              << std::endl;
}

void UltraHdrAppInput::computeRGBSdrPSNR() {
    if (mOf != ULTRAHDR_OUTPUT_SDR) {
        std::cout << "psnr not supported for output format " << mOf << std::endl;
        return;
    }
    uint32_t* rgbDataSrc = static_cast<uint32_t*>(mRawRgba8888Image.data);
    uint32_t* rgbDataDst = static_cast<uint32_t*>(mDestImage.data);
    if (rgbDataSrc == nullptr || rgbDataDst == nullptr) {
        std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
        return;
    }

    uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
    for (size_t i = 0; i < mRawYuv420Image.width * mRawYuv420Image.height; i++) {
        int rSrc = *rgbDataSrc & 0xff;
        int rDst = *rgbDataDst & 0xff;
        rSqError += (rSrc - rDst) * (rSrc - rDst);

        int gSrc = (*rgbDataSrc >> 8) & 0xff;
        int gDst = (*rgbDataDst >> 8) & 0xff;
        gSqError += (gSrc - gDst) * (gSrc - gDst);

        int bSrc = (*rgbDataSrc >> 16) & 0xff;
        int bDst = (*rgbDataDst >> 16) & 0xff;
        bSqError += (bSrc - bDst) * (bSrc - bDst);

        rgbDataSrc++;
        rgbDataDst++;
    }
    double meanSquareError = (double)rSqError / (mRawYuv420Image.width * mRawYuv420Image.height);
    mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

    meanSquareError = (double)gSqError / (mRawYuv420Image.width * mRawYuv420Image.height);
    mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

    meanSquareError = (double)bSqError / (mRawYuv420Image.width * mRawYuv420Image.height);
    mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

    std::cout << "psnr r :: " << mPsnr[0] << " psnr g :: " << mPsnr[1] << " psnr b :: " << mPsnr[2]
              << std::endl;
}

void UltraHdrAppInput::computeYUVHdrPSNR() {
    if (mOf == ULTRAHDR_OUTPUT_SDR || mOf == ULTRAHDR_OUTPUT_HDR_LINEAR) {
        std::cout << "psnr not supported for output format " << mOf << std::endl;
        return;
    }
    uint16_t* yuvDataSrc = static_cast<uint16_t*>(mRawP010Image.data);
    uint16_t* yuvDataDst = static_cast<uint16_t*>(mDestYUV444Image.data);
    if (yuvDataSrc == nullptr || yuvDataDst == nullptr) {
        std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
        return;
    }
    if ((mOf == ULTRAHDR_OUTPUT_HDR_PQ && mTf != ULTRAHDR_TF_PQ) ||
        (mOf == ULTRAHDR_OUTPUT_HDR_HLG && mTf != ULTRAHDR_TF_HLG)) {
        std::cout << "input transfer function and output format are not compatible, psnr results "
                     "may be unreliable"
                  << std::endl;
    }

    uint16_t* yDataSrc = static_cast<uint16_t*>(mRawP010Image.data);
    uint16_t* uDataSrc = yDataSrc + (mRawP010Image.width * mRawP010Image.height);
    uint16_t* vDataSrc = uDataSrc + 1;

    uint16_t* yDataDst = static_cast<uint16_t*>(mDestYUV444Image.data);
    uint16_t* uDataDst = yDataDst + (mDestYUV444Image.width * mDestYUV444Image.height);
    uint16_t* vDataDst = uDataDst + (mDestYUV444Image.width * mDestYUV444Image.height);

    uint64_t ySqError = 0, uSqError = 0, vSqError = 0;
    for (size_t i = 0; i < mDestYUV444Image.height; i++) {
        for (size_t j = 0; j < mDestYUV444Image.width; j++) {
            int ySrc = (yDataSrc[mRawP010Image.width * i + j] >> 6) & 0x3ff;
            ySrc = CLIP3(ySrc, 64, 940);
            int yDst = yDataDst[mDestYUV444Image.width * i + j] & 0x3ff;
            ySqError += (ySrc - yDst) * (ySrc - yDst);

            if (i % 2 == 0 && j % 2 == 0) {
                int uSrc = (uDataSrc[mRawP010Image.width * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
                uSrc = CLIP3(uSrc, 64, 960);
                int uDst = uDataDst[mDestYUV444Image.width * i + j] & 0x3ff;
                uDst += uDataDst[mDestYUV444Image.width * i + j + 1] & 0x3ff;
                uDst += uDataDst[mDestYUV444Image.width * (i + 1) + j + 1] & 0x3ff;
                uDst += uDataDst[mDestYUV444Image.width * (i + 1) + j + 1] & 0x3ff;
                uDst = (uDst + 2) >> 2;
                uSqError += (uSrc - uDst) * (uSrc - uDst);

                int vSrc = (vDataSrc[mRawP010Image.width * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
                vSrc = CLIP3(vSrc, 64, 960);
                int vDst = vDataDst[mDestYUV444Image.width * i + j] & 0x3ff;
                vDst += vDataDst[mDestYUV444Image.width * i + j + 1] & 0x3ff;
                vDst += vDataDst[mDestYUV444Image.width * (i + 1) + j + 1] & 0x3ff;
                vDst += vDataDst[mDestYUV444Image.width * (i + 1) + j + 1] & 0x3ff;
                vDst = (vDst + 2) >> 2;
                vSqError += (vSrc - vDst) * (vSrc - vDst);
            }
        }
    }

    double meanSquareError = (double)ySqError / (mDestYUV444Image.width * mDestYUV444Image.height);
    mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

    meanSquareError = (double)uSqError / (mDestYUV444Image.width * mDestYUV444Image.height / 4);
    mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

    meanSquareError = (double)vSqError / (mDestYUV444Image.width * mDestYUV444Image.height / 4);
    mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;

    std::cout << "psnr y :: " << mPsnr[0] << " psnr u :: " << mPsnr[1] << " psnr v :: " << mPsnr[2]
              << std::endl;
}

void UltraHdrAppInput::computeYUVSdrPSNR() {
    if (mOf != ULTRAHDR_OUTPUT_SDR) {
        std::cout << "psnr not supported for output format " << mOf << std::endl;
        return;
    }

    uint8_t* yDataSrc = static_cast<uint8_t*>(mRawYuv420Image.data);
    uint8_t* uDataSrc = yDataSrc + (mRawYuv420Image.width * mRawYuv420Image.height);
    uint8_t* vDataSrc = uDataSrc + (mRawYuv420Image.width * mRawYuv420Image.height / 4);

    uint8_t* yDataDst = static_cast<uint8_t*>(mDestYUV444Image.data);
    uint8_t* uDataDst = yDataDst + (mDestYUV444Image.width * mDestYUV444Image.height);
    uint8_t* vDataDst = uDataDst + (mDestYUV444Image.width * mDestYUV444Image.height);

    uint64_t ySqError = 0, uSqError = 0, vSqError = 0;
    for (size_t i = 0; i < mDestYUV444Image.height; i++) {
        for (size_t j = 0; j < mDestYUV444Image.width; j++) {
            int ySrc = yDataSrc[mRawYuv420Image.width * i + j];
            int yDst = yDataDst[mDestYUV444Image.width * i + j];
            ySqError += (ySrc - yDst) * (ySrc - yDst);

            if (i % 2 == 0 && j % 2 == 0) {
                int uSrc = uDataSrc[mRawYuv420Image.width / 2 * (i / 2) + j / 2];
                int uDst = uDataDst[mDestYUV444Image.width * i + j];
                uDst += uDataDst[mDestYUV444Image.width * i + j + 1];
                uDst += uDataDst[mDestYUV444Image.width * (i + 1) + j];
                uDst += uDataDst[mDestYUV444Image.width * (i + 1) + j + 1];
                uDst = (uDst + 2) >> 2;
                uSqError += (uSrc - uDst) * (uSrc - uDst);

                int vSrc = vDataSrc[mRawYuv420Image.width / 2 * (i / 2) + j / 2];
                int vDst = vDataDst[mDestYUV444Image.width * i + j];
                vDst += vDataDst[mDestYUV444Image.width * i + j + 1];
                vDst += vDataDst[mDestYUV444Image.width * (i + 1) + j];
                vDst += vDataDst[mDestYUV444Image.width * (i + 1) + j + 1];
                vDst = (vDst + 2) >> 2;
                vSqError += (vSrc - vDst) * (vSrc - vDst);
            }
        }
    }
    double meanSquareError = (double)ySqError / (mDestYUV444Image.width * mDestYUV444Image.height);
    mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

    meanSquareError = (double)uSqError / (mDestYUV444Image.width * mDestYUV444Image.height / 4);
    mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

    meanSquareError = (double)vSqError / (mDestYUV444Image.width * mDestYUV444Image.height / 4);
    mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;

    std::cout << "psnr y :: " << mPsnr[0] << " psnr  u:: " << mPsnr[1] << " psnr v :: " << mPsnr[2]
              << std::endl;
}

static void usage(const char* name) {
    fprintf(stderr, "Usage: %s \n", name);
    fprintf(stderr, "ultra hdr demo application \n");
    fprintf(stderr, "    -p    p010 file path, mandatory in encode mode \n");
    fprintf(stderr, "    -y    yuv420 file path, optional \n");
    fprintf(stderr, "    -w    input width, mandatory in encode mode \n");
    fprintf(stderr, "    -h    input height, mandatory in encode mode \n");
    fprintf(stderr, "    -C    p010 color gamut, optional [0:bt709, 1:p3, 2:bt2100] \n");
    fprintf(stderr, "    -c    yuv420 color gamut, optional [0:bt709, 1:p3, 2:bt2100] \n");
    fprintf(stderr, "    -t    input transfer function, optional [0:linear, 1:hlg, 2:pq] \n");
    fprintf(stderr, "    -q    quality factor, optional [0-100] \n");
    fprintf(stderr, "    -j    jpegr file path, mandatory in decode mode \n");
    fprintf(stderr, "    -m    mode [0: encode, 1:decode] \n");
    fprintf(stderr,
            "    -o    output transfer function, optional [0:sdr, 1:hdr_linear, 2:hdr_pq, "
            "3:hdr_hlg] \n");
}

int main(int argc, char* argv[]) {
    char *p010_file = nullptr, *yuv420_file = nullptr, *jpegr_file = nullptr;
    int width = 0, height = 0;
    ultrahdr_color_gamut p010Cg = ULTRAHDR_COLORGAMUT_BT709;
    ultrahdr_color_gamut yuv420Cg = ULTRAHDR_COLORGAMUT_BT709;
    ultrahdr_transfer_function tf = ULTRAHDR_TF_HLG;
    int quality = 100;
    ultrahdr_output_format of = ULTRAHDR_OUTPUT_HDR_HLG;
    int mode = 0;
    int ch;
    while ((ch = getopt(argc, argv, "p:y:w:h:C:c:t:q:o:m:j:")) != -1) {
        switch (ch) {
            case 'p':
                p010_file = optarg;
                break;
            case 'y':
                yuv420_file = optarg;
                break;
            case 'w':
                width = atoi(optarg);
                break;
            case 'h':
                height = atoi(optarg);
                break;
            case 'C':
                p010Cg = static_cast<ultrahdr_color_gamut>(atoi(optarg));
                break;
            case 'c':
                yuv420Cg = static_cast<ultrahdr_color_gamut>(atoi(optarg));
                break;
            case 't':
                tf = static_cast<ultrahdr_transfer_function>(atoi(optarg));
                break;
            case 'q':
                quality = atoi(optarg);
                break;
            case 'o':
                of = static_cast<ultrahdr_output_format>(atoi(optarg));
                break;
            case 'm':
                mode = atoi(optarg);
                break;
            case 'j':
                jpegr_file = optarg;
                break;
            default:
                usage(argv[0]);
                return -1;
        }
    }
    if (mode == 0) {
        if (width <= 0 || height <= 0 || p010_file == nullptr) {
            std::cerr << "invalid raw file name or raw image dimensions" << std::endl;
            usage(argv[0]);
            return -1;
        }
        UltraHdrAppInput appInput(p010_file, yuv420_file, width, height, p010Cg, yuv420Cg, tf,
                                  quality, of);
        if (!appInput.encode()) return -1;
        if (!appInput.decode()) return -1;
        if (of == ULTRAHDR_OUTPUT_SDR && yuv420_file != nullptr) {
            appInput.convertYuv420ToRGBImage();
            appInput.computeRGBSdrPSNR();
            appInput.convertRgba8888ToYUV444Image();
            appInput.computeYUVSdrPSNR();
        } else if (of == ULTRAHDR_OUTPUT_HDR_HLG || of == ULTRAHDR_OUTPUT_HDR_PQ) {
            appInput.convertP010ToRGBImage();
            appInput.computeRGBHdrPSNR();
            appInput.convertRgba1010102ToYUV444Image();
            appInput.computeYUVHdrPSNR();
        }
    } else if (mode == 1) {
        if (jpegr_file == nullptr) {
            std::cerr << "invalid jpegr image file name " << std::endl;
            usage(argv[0]);
            return -1;
        }
        UltraHdrAppInput appInput(jpegr_file, of);
        if (!appInput.decode()) return -1;
    } else {
        std::cerr << "unrecognized input mode " << mode << std::endl;
        usage(argv[0]);
        return -1;
    }

    return 0;
}
