with open('lib/src/jpegr.cpp', 'r') as f:
    data = f.read()

conflict = """<<<<<<< HEAD
          Color yuv_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
          // Assuming the sdr image is a decoded JPEG, we should always use Rec.601 YUV coefficients
          Color rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
=======
          Color rgb_gamma_sdr;

          if (isSdrIntentRgb) {
            rgb_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
          } else {
            Color yuv_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
            // Assuming the sdr image is a decoded JPEG, we should always use Rec.601 YUV
            // coefficients
            rgb_gamma_sdr = bt601YuvToRgb(yuv_gamma_sdr);
          }

>>>>>>> e36a60c ([EXP] add support for formats heif and avif)"""

resolution = """          Color rgb_gamma_sdr;

          if (isSdrIntentRgb) {
            rgb_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
          } else {
            Color yuv_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
            rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
          }"""

data = data.replace(conflict, resolution)
with open('lib/src/jpegr.cpp', 'w') as f:
    f.write(data)
