#ifndef IMAGE_IO_JPEG_JPEG_APPLE_DEPTH_BUILDER_H_  // NOLINT
#define IMAGE_IO_JPEG_JPEG_APPLE_DEPTH_BUILDER_H_  // NOLINT

#include <vector>

#include "image_io/base/data_destination.h"
#include "image_io/base/data_range.h"
#include "image_io/base/data_source.h"
#include "image_io/base/message_handler.h"

namespace photos_editing_formats {
namespace image_io {

/// Builds an Apple depth file containing a (possibly scaled down) primary image
/// and original depth image.
class JpegAppleDepthBuilder {
 public:
  explicit JpegAppleDepthBuilder(MessageHandler* message_handler)
      : message_handler_(message_handler),
        primary_image_data_source_(nullptr),
        depth_image_data_source_(nullptr),
        data_destination_(nullptr) {}

  /// @param primary_image_data_source The data source containing the primary
  ///     image. The builder uses the first image in this data source.
  /// @param depth_image_data_source The data source containing the depth image.
  ///     The builder finds the depth image using a JpegInfoBuilder and the
  ///     JpegInfo::GetAppleDepthImageRange() function. Consequently, this
  ///     image source must refer a valid Apple depth file.
  /// @param data_destination The data destination for the combined primary
  ///     and depth images.
  /// @return Whether the building and transfer was successful.
  bool Run(DataSource* primary_image_data_source,
           DataSource* depth_image_data_source,
           DataDestination* data_destination);

 private:
  /// Gets the data associated with the primary image its data source.
  /// @return Whether the primary image data was gotten successfully.
  bool GetPrimaryImageData();

  /// Gets the data associated with the depth image from its data source.
  /// @return Whether the depth image data was gotten successfully.
  bool GetDepthImageData();

  /// Transfers the primary image from its data source to the data destination,
  /// adding and transforming the jpeg segments it needs to make the resulting
  /// data destination a valid Apple depth file.
  /// @return Whether the transfer was successful or not.
  bool TransferPrimaryImage();

  /// Transfers the depth image from its data source to the data destination.
  /// @return Whether the transfer was successful or not.
  bool TransferDepthImage();

  /// Modifies the existing primary Jfif segment to contain the information
  /// needed for a valid Apple depth file, and transfers the result to the data
  /// destination.
  /// @param jfif_length_delta The increased size of the Jfif segment.
  /// @return Whether the transfer was successful or not.
  bool TransferNewJfifSegment(size_t *jfif_length_delta);

  /// Creates a new Mpf segment needed for a valid Apple depth file and
  /// transfers the result to the data destination.
  /// @param jfif_length_delta The increased size of the Jfif segment.
  /// @return Whether the transfer was successful or not.
  bool TransferNewMpfSegment(size_t jfif_length_delta);

  /// @param data_source The data source from which to transfer bytes to the
  ///     data destination.
  /// @param data_range The data range in the data source to transfer.
  bool TransferData(DataSource *data_source, const DataRange& data_range);

  /// An optional message handler to write messages to.
  MessageHandler* message_handler_;

  /// The data source containing the primary image.
  DataSource* primary_image_data_source_;

  /// The data source representing a valid Apple depth file.
  DataSource* depth_image_data_source_;

  /// The final destination of the new Apple depth data.
  DataDestination* data_destination_;

  /// The range in the primary image data source containing the primary image.
  DataRange primary_image_range_;

  /// The range in the primary image data source containing the primary image's
  /// Jfif segment.
  DataRange primary_image_jfif_segment_range_;

  /// The bytes of the primary image's Jfif segment.
  std::vector<Byte> primary_image_jfif_segment_bytes_;

  /// The range in the primary image data source containing the primary images's
  /// Mpf segment, or the location at a new Mpf segment should be written.
  DataRange primary_image_mpf_segment_range_;

  /// The range in the depth image data source containing the depth image.
  DataRange depth_image_range_;
};

}  // namespace image_io
}  // namespace photos_editing_formats

#endif // IMAGE_IO_JPEG_JPEG_APPLE_DEPTH_BUILDER_H_  // NOLINT
