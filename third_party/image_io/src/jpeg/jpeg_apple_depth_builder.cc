#include "image_io/jpeg/jpeg_apple_depth_builder.h"

#include <cstring>
#include <sstream>

#include "image_io/base/byte_buffer.h"
#include "image_io/base/data_segment_data_source.h"
#include "image_io/base/message.h"
#include "image_io/base/message_handler.h"
#include "image_io/jpeg/jpeg_info.h"
#include "image_io/jpeg/jpeg_info_builder.h"
#include "image_io/jpeg/jpeg_scanner.h"
#include "image_io/jpeg/jpeg_segment_info.h"

namespace photos_editing_formats {
namespace image_io {

using std::string;
using std::vector;

namespace {

/// The special Apple depth JFIF segment suffix and length. The -1 in the
/// kAmpfLength compuration is because the size of kAmpf is 5 bytes, including
/// the terminating null character, but the kAmpfLength should be 4. Can't use
/// strlen (which would be better) because it is not constexpr-able.
const char kAmpf[] = "AMPF";
constexpr size_t kAmpfLength = sizeof(kAmpf) - 1;

/// The contents of the MPF segment length and value in three parts. For more
/// information, see go/photos-image-io-phase2-summary.
const size_t kMpfSegmentLength = 0x5A;
const char kMpfHex0[] =
    "FFE200584D5046004D4D002A000000080003B00000070000000430313030B0010004000000"
    "0100000002B002000700000020000000320000000000030000";
// Four byte primary image length value
const char kMpfHex1[] = "000000000000000000000000";
// Four byte depth image length value
// Four byte depth image offset value
const char kMpfHex2[] = "00000000";

/// The optimum size to use for the DataSource::TransferData() function.
constexpr size_t kBestDataSize = 0x10000;

/// @param image_limit The limit on the number of images to get info of.
/// @param data_source The data source from which to get info.
/// @param info A pointer to the jpeg_info object to receive the info.
/// @param message_handler For use when reporting messages.
/// @return Whether the info was obtained successfully or not.
bool GetJpegInfo(int image_limit, DataSource* data_source, JpegInfo* info,
                 MessageHandler* message_handler) {
  JpegInfoBuilder info_builder;
  info_builder.SetImageLimit(image_limit);
  info_builder.SetCaptureSegmentBytes(kJfif);
  JpegScanner scanner(message_handler);
  scanner.Run(data_source, &info_builder);
  if (scanner.HasError()) {
    return false;
  }
  *info = info_builder.GetInfo();
  return true;
}

}  // namespace

bool JpegAppleDepthBuilder::Run(DataSource* primary_image_data_source,
                                DataSource* depth_image_data_source,
                                DataDestination* data_destination) {
  primary_image_data_source_ = primary_image_data_source;
  depth_image_data_source_ = depth_image_data_source;
  data_destination_ = data_destination;
  if (!GetPrimaryImageData()) {
    if (message_handler_) {
      message_handler_->ReportMessage(Message::kDecodingError,
                                      "Primary image data");
    }
    return false;
  }
  if (!GetDepthImageData()) {
    if (message_handler_) {
      message_handler_->ReportMessage(Message::kDecodingError,
                                      "Depth image data");
    }
    return false;
  }
  data_destination->StartTransfer();
  bool status = TransferPrimaryImage();
  if (status) {
    status = TransferDepthImage();
  }
  data_destination->FinishTransfer();
  return status;
}

bool JpegAppleDepthBuilder::GetPrimaryImageData() {
  JpegInfo info;
  if (!GetJpegInfo(1, primary_image_data_source_, &info, message_handler_)) {
    return false;
  }
  if (info.GetImageRanges().empty()) {
    return false;
  }
  primary_image_range_ = info.GetImageRanges()[0];
  JpegSegmentInfo jfif_segment_info = info.GetSegmentInfo(0, kJfif);
  if (!jfif_segment_info.IsValid() ||
      jfif_segment_info.GetBytes().size() < kAmpfLength) {
    return false;
  }
  primary_image_jfif_segment_range_ = jfif_segment_info.GetDataRange();
  primary_image_jfif_segment_bytes_ = jfif_segment_info.GetBytes();

  JpegSegmentInfo exif_info = info.GetSegmentInfo(0, kExif);
  if (!exif_info.IsValid()) {
    return false;
  }
  JpegSegmentInfo mpf_info = info.GetSegmentInfo(0, kMpf);
  if (mpf_info.IsValid()) {
    primary_image_mpf_segment_range_ = mpf_info.GetDataRange();
  } else {
    size_t exif_end = exif_info.GetDataRange().GetEnd();
    primary_image_mpf_segment_range_ = DataRange(exif_end, exif_end);
  }
  return true;
}

bool JpegAppleDepthBuilder::GetDepthImageData() {
  JpegInfo info;
  if (!GetJpegInfo(2, depth_image_data_source_, &info, message_handler_)) {
    return false;
  }
  if (!info.HasAppleDepth()) {
    return false;
  }
  depth_image_range_ = info.GetAppleDepthImageRange();
  return true;
}

bool JpegAppleDepthBuilder::TransferPrimaryImage() {
  // The first move involves all from the start of the data source to the
  // mpf location or the beginning of the jfif segment, which ever comes first.
  size_t first_end = std::min(primary_image_jfif_segment_range_.GetBegin(),
                              primary_image_mpf_segment_range_.GetBegin());
  DataRange first_range(0, first_end);
  if (!TransferData(primary_image_data_source_, first_range)) {
    return false;
  }

  // Move the new Jfif segment. If the primary image jfif came right after the
  // SOI then the first_end is positioned at the start of the jfif segment. So
  // move it to the end so that the original jfif segment does not get copied
  // to the output destination.
  size_t jfif_length_delta = 0;
  if (!TransferNewJfifSegment(&jfif_length_delta)) {
    return false;
  }
  if (first_end == primary_image_jfif_segment_range_.GetBegin()) {
    first_end = primary_image_jfif_segment_range_.GetEnd();
  }

  // The second move is from the end of the first move or the end of the jfif
  // segment, which ever comes first to the mpf location.
  size_t second_begin =
      std::min(first_end, primary_image_jfif_segment_range_.GetEnd());
  DataRange second_range(second_begin,
                         primary_image_mpf_segment_range_.GetBegin());
  if (second_range.IsValid()) {
    if (!TransferData(primary_image_data_source_, second_range)) {
      return false;
    }
  }

  // Move the new Mpf segment.
  if (!TransferNewMpfSegment(jfif_length_delta)) {
    return false;
  }

  // The third move is from from the end of the mpf to the end of the image.
  DataRange mpf_eoi_range(primary_image_mpf_segment_range_.GetEnd(),
                          primary_image_range_.GetEnd());
  if (!mpf_eoi_range.IsValid()) {
    return false;
  }
  return TransferData(primary_image_data_source_, mpf_eoi_range);
}

bool JpegAppleDepthBuilder::TransferNewJfifSegment(size_t* jfif_length_delta) {
  *jfif_length_delta = 0;
  size_t jfif_size = primary_image_jfif_segment_bytes_.size();
  Byte* jfif_bytes = new Byte[jfif_size + kAmpfLength];
  memcpy(jfif_bytes, primary_image_jfif_segment_bytes_.data(), jfif_size);
  if (memcmp(jfif_bytes + jfif_size - kAmpfLength, kAmpf, kAmpfLength) != 0) {
    memcpy(jfif_bytes + jfif_size, kAmpf, kAmpfLength);
    *jfif_length_delta = kAmpfLength;
    jfif_size += kAmpfLength;
    size_t jfif_data_length = jfif_size - 2;
    jfif_bytes[2] = ((jfif_data_length >> 8) & 0xFF);
    jfif_bytes[3] = (jfif_data_length & 0xFF);
  }
  DataRange jfif_range(0, jfif_size);
  auto jfif_segment = DataSegment::Create(jfif_range, jfif_bytes);
  DataSegmentDataSource jfif_data_source(jfif_segment);
  return TransferData(&jfif_data_source, jfif_range);
}

bool JpegAppleDepthBuilder::TransferNewMpfSegment(size_t jfif_length_delta) {
  size_t primary_image_length =
      primary_image_range_.GetLength() + jfif_length_delta -
      primary_image_mpf_segment_range_.GetLength() + kMpfSegmentLength;
  size_t depth_image_length = depth_image_range_.GetLength();
  size_t depth_image_offset =
      primary_image_length - primary_image_mpf_segment_range_.GetBegin() - 8;
  vector<ByteData> mpf_bytes;
  mpf_bytes.reserve(5);
  mpf_bytes.emplace_back(ByteData::kHex, kMpfHex0);
  mpf_bytes.emplace_back(ByteData::kHex,
                         ByteData::Size2BigEndianHex(primary_image_length));
  mpf_bytes.emplace_back(ByteData::kHex, kMpfHex1);
  mpf_bytes.emplace_back(ByteData::kHex,
                         ByteData::Size2BigEndianHex(depth_image_length));
  mpf_bytes.emplace_back(ByteData::kHex,
                         ByteData::Size2BigEndianHex(depth_image_offset));
  mpf_bytes.emplace_back(ByteData::kHex, kMpfHex2);
  ByteBuffer mpf_byte_buffer(mpf_bytes);
  size_t mpf_segment_size = mpf_byte_buffer.GetSize();
  if (!mpf_byte_buffer.IsValid() || mpf_segment_size != kMpfSegmentLength) {
    return false;
  }
  DataRange mpf_range(0, mpf_segment_size);
  auto mpf_segment = DataSegment::Create(mpf_range, mpf_byte_buffer.Release());
  DataSegmentDataSource mpf_data_source(mpf_segment);
  return TransferData(&mpf_data_source, mpf_range);
}

bool JpegAppleDepthBuilder::TransferDepthImage() {
  return TransferData(depth_image_data_source_, depth_image_range_);
}

bool JpegAppleDepthBuilder::TransferData(DataSource* data_source,
                                         const DataRange& data_range) {
  size_t old_byte_count = data_destination_->GetBytesTransferred();
  DataSource::TransferDataResult result =
      data_source->TransferData(data_range, kBestDataSize, data_destination_);
  if (result == DataSource::kTransferDataSuccess) {
    size_t bytes_transferred =
        data_destination_->GetBytesTransferred() - old_byte_count;
    if (bytes_transferred != data_range.GetLength()) {
      result = DataSource::kTransferDataError;
      if (message_handler_) {
        std::stringstream ss;
        ss << "JpegAppleDepthBuilder:data source transferred "
           << bytes_transferred << " bytes instead of "
           << data_range.GetLength();
        message_handler_->ReportMessage(Message::kInternalError, ss.str());
      }
    }
  }
  return result == DataSource::kTransferDataSuccess;
}

}  // namespace image_io
}  // namespace photos_editing_formats
