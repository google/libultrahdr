/*
 * Copyright 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#ifndef ULTRAHDR_BYTEBUFFER_H
#define ULTRAHDR_BYTEBUFFER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

#if defined(__clang__) && defined(__has_warning)
#if __has_warning("-Wunsafe-buffer-usage")
#if !defined(__apple_build_version__) && __clang_major__ >= 18
#define UHDR_UNSAFE_BUFFER_USAGE_BEGIN _Pragma("clang unsafe_buffer_usage begin")
#define UHDR_UNSAFE_BUFFER_USAGE_END _Pragma("clang unsafe_buffer_usage end")
#else
#define UHDR_UNSAFE_BUFFER_USAGE_BEGIN \
  _Pragma("clang diagnostic push") _Pragma("clang diagnostic ignored \"-Wunsafe-buffer-usage\"")
#define UHDR_UNSAFE_BUFFER_USAGE_END _Pragma("clang diagnostic pop")
#endif
#endif
#endif
#ifndef UHDR_UNSAFE_BUFFER_USAGE_BEGIN
#define UHDR_UNSAFE_BUFFER_USAGE_BEGIN
#define UHDR_UNSAFE_BUFFER_USAGE_END
#endif

namespace ultrahdr {

// Returns true iff [pos, pos + len) fits within [0, cap] without overflow.
inline constexpr bool checkedRangeFits(size_t pos, size_t len, size_t cap) noexcept {
  return pos <= cap && len <= cap - pos;
}

// Non-owning view over a fixed-size C array.
template <typename T, size_t N>
class FixedSpan {
 public:
  explicit constexpr FixedSpan(T (&arr)[N]) noexcept : data_(arr) {}

  template <typename U, typename = std::enable_if_t<std::is_const_v<T> &&
                                                    std::is_same_v<std::remove_const_t<T>, U>>>
  constexpr FixedSpan(FixedSpan<U, N> other) noexcept : data_(other.data()) {}

  constexpr T* data() const noexcept { return data_; }
  constexpr size_t size() const noexcept { return N; }

  constexpr T& operator[](size_t index) const noexcept {
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    return data_[index];
    UHDR_UNSAFE_BUFFER_USAGE_END
  }

  void fill(const std::remove_const_t<T>& value) const noexcept {
    for (size_t i = 0; i < N; ++i) {
      (*this)[i] = value;
    }
  }

  void copyFrom(FixedSpan<const std::remove_const_t<T>, N> src) const noexcept {
    for (size_t i = 0; i < N; ++i) {
      (*this)[i] = src[i];
    }
  }

  bool allEqual() const noexcept {
    for (size_t i = 1; i < N; ++i) {
      if (!((*this)[0] == (*this)[i])) {
        return false;
      }
    }
    return true;
  }

 private:
  T* data_;
};

template <typename T, size_t N>
inline constexpr FixedSpan<T, N> asSpan(T (&arr)[N]) noexcept {
  return FixedSpan<T, N>(arr);
}

// Non-owning read-only view over a byte buffer with bounds-checked reads.
class ByteSpan {
 public:
  constexpr ByteSpan() noexcept : data_(nullptr), size_(0) {}

  constexpr ByteSpan(const uint8_t* data, size_t size) noexcept
      : data_(data == nullptr ? nullptr : data), size_(data == nullptr ? 0 : size) {}

  ByteSpan(const void* data, size_t size) noexcept
      : ByteSpan(static_cast<const uint8_t*>(data), size) {}

  ByteSpan(const std::vector<uint8_t>& vec) noexcept : ByteSpan(vec.data(), vec.size()) {}

  template <size_t N>
  constexpr ByteSpan(const std::array<uint8_t, N>& arr) noexcept
      : data_(arr.data()), size_(N) {}

  template <size_t N>
  constexpr ByteSpan(const uint8_t (&arr)[N]) noexcept : data_(arr), size_(N) {}

  constexpr const uint8_t* data() const noexcept { return data_; }
  constexpr size_t size() const noexcept { return size_; }
  constexpr bool empty() const noexcept { return size_ == 0; }

  constexpr bool hasRange(size_t offset, size_t count) const noexcept {
    return checkedRangeFits(offset, count, size_);
  }

  bool subspan(size_t offset, size_t count, ByteSpan* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, count, size_)) {
      return false;
    }
    if (count == 0) {
      *out = ByteSpan();
      return true;
    }
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    *out = ByteSpan(data_ + offset, count);
    UHDR_UNSAFE_BUFFER_USAGE_END
    return true;
  }

  bool subspan(size_t offset, ByteSpan* out) const noexcept {
    if (out == nullptr || offset > size_) {
      return false;
    }
    return subspan(offset, size_ - offset, out);
  }

  bool equalsAt(size_t offset, ByteSpan expected) const noexcept {
    if (!checkedRangeFits(offset, expected.size_, size_)) {
      return false;
    }
    if (expected.size_ == 0) {
      return true;
    }
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    return std::memcmp(data_ + offset, expected.data_, expected.size_) == 0;
    UHDR_UNSAFE_BUFFER_USAGE_END
  }

  bool startsWith(ByteSpan prefix) const noexcept { return equalsAt(0, prefix); }

  bool readU8At(size_t offset, uint8_t* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, 1, size_)) {
      return false;
    }
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    *out = data_[offset];
    UHDR_UNSAFE_BUFFER_USAGE_END
    return true;
  }

  bool readU16BEAt(size_t offset, uint16_t* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, 2, size_)) {
      return false;
    }
    std::array<uint8_t, 2> b{};
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    std::memcpy(b.data(), data_ + offset, b.size());
    UHDR_UNSAFE_BUFFER_USAGE_END
    *out = static_cast<uint16_t>((static_cast<unsigned>(b[0]) << 8) | static_cast<unsigned>(b[1]));
    return true;
  }

  bool readU16LEAt(size_t offset, uint16_t* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, 2, size_)) {
      return false;
    }
    std::array<uint8_t, 2> b{};
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    std::memcpy(b.data(), data_ + offset, b.size());
    UHDR_UNSAFE_BUFFER_USAGE_END
    *out = static_cast<uint16_t>(static_cast<unsigned>(b[0]) | (static_cast<unsigned>(b[1]) << 8));
    return true;
  }

  bool readU32BEAt(size_t offset, uint32_t* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, 4, size_)) {
      return false;
    }
    std::array<uint8_t, 4> b{};
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    std::memcpy(b.data(), data_ + offset, b.size());
    UHDR_UNSAFE_BUFFER_USAGE_END
    *out = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
    return true;
  }

  bool readU32LEAt(size_t offset, uint32_t* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, 4, size_)) {
      return false;
    }
    std::array<uint8_t, 4> b{};
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    std::memcpy(b.data(), data_ + offset, b.size());
    UHDR_UNSAFE_BUFFER_USAGE_END
    *out = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
    return true;
  }

  bool readS32BEAt(size_t offset, int32_t* out) const noexcept {
    uint32_t u = 0;
    if (out == nullptr || !readU32BEAt(offset, &u)) {
      return false;
    }
    std::memcpy(out, &u, sizeof(u));
    return true;
  }

  bool readS32LEAt(size_t offset, int32_t* out) const noexcept {
    uint32_t u = 0;
    if (out == nullptr || !readU32LEAt(offset, &u)) {
      return false;
    }
    std::memcpy(out, &u, sizeof(u));
    return true;
  }

  bool readU8(size_t& pos, uint8_t* out) const noexcept {
    if (!readU8At(pos, out)) {
      return false;
    }
    pos += 1;
    return true;
  }

  bool readU16BE(size_t& pos, uint16_t* out) const noexcept {
    if (!readU16BEAt(pos, out)) {
      return false;
    }
    pos += 2;
    return true;
  }

  bool readU16(size_t& pos, bool is_big_endian, uint16_t* out) const noexcept {
    const bool ok = is_big_endian ? readU16BEAt(pos, out) : readU16LEAt(pos, out);
    if (!ok) {
      return false;
    }
    pos += 2;
    return true;
  }

  bool readU32BE(size_t& pos, uint32_t* out) const noexcept {
    if (!readU32BEAt(pos, out)) {
      return false;
    }
    pos += 4;
    return true;
  }

  bool readU32(size_t& pos, bool is_big_endian, uint32_t* out) const noexcept {
    const bool ok = is_big_endian ? readU32BEAt(pos, out) : readU32LEAt(pos, out);
    if (!ok) {
      return false;
    }
    pos += 4;
    return true;
  }

  bool readS32BE(size_t& pos, int32_t* out) const noexcept {
    if (!readS32BEAt(pos, out)) {
      return false;
    }
    pos += 4;
    return true;
  }

  bool readS32(size_t& pos, bool is_big_endian, int32_t* out) const noexcept {
    const bool ok = is_big_endian ? readS32BEAt(pos, out) : readS32LEAt(pos, out);
    if (!ok) {
      return false;
    }
    pos += 4;
    return true;
  }

  std::string toString() const {
    if (size_ == 0) {
      return std::string();
    }
    return std::string(reinterpret_cast<const char*>(data_), size_);
  }

 private:
  const uint8_t* data_;
  size_t size_;
};

// Non-owning writable view over a byte buffer with bounds-checked writes.
class MutableByteSpan {
 public:
  constexpr MutableByteSpan() noexcept : data_(nullptr), size_(0) {}

  constexpr MutableByteSpan(uint8_t* data, size_t size) noexcept
      : data_(data == nullptr ? nullptr : data), size_(data == nullptr ? 0 : size) {}

  MutableByteSpan(void* data, size_t size) noexcept
      : MutableByteSpan(static_cast<uint8_t*>(data), size) {}

  MutableByteSpan(std::vector<uint8_t>& vec) noexcept : MutableByteSpan(vec.data(), vec.size()) {}

  constexpr uint8_t* data() const noexcept { return data_; }
  constexpr size_t size() const noexcept { return size_; }

  bool subspan(size_t offset, size_t count, MutableByteSpan* out) const noexcept {
    if (out == nullptr || !checkedRangeFits(offset, count, size_)) {
      return false;
    }
    if (count == 0) {
      *out = MutableByteSpan();
      return true;
    }
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    *out = MutableByteSpan(data_ + offset, count);
    UHDR_UNSAFE_BUFFER_USAGE_END
    return true;
  }

  bool writeAt(size_t offset, const void* src, size_t len) const noexcept {
    if (!checkedRangeFits(offset, len, size_)) {
      return false;
    }
    if (len == 0) {
      return true;
    }
    if (src == nullptr) {
      return false;
    }
    UHDR_UNSAFE_BUFFER_USAGE_BEGIN
    std::memcpy(data_ + offset, src, len);
    UHDR_UNSAFE_BUFFER_USAGE_END
    return true;
  }

  bool writeU16BEAt(size_t offset, uint16_t value) const noexcept {
    const std::array<uint8_t, 2> bytes = {
        static_cast<uint8_t>((value >> 8) & 0xffu),
        static_cast<uint8_t>(value & 0xffu),
    };
    return writeAt(offset, bytes.data(), bytes.size());
  }

 private:
  uint8_t* data_;
  size_t size_;
};

}  // namespace ultrahdr

#endif  // ULTRAHDR_BYTEBUFFER_H
