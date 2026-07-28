with open('lib/src/gainmapmath.cpp', 'r') as f:
    data = f.read()

conflict = """<<<<<<< HEAD
  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
    if (src->cg == UHDR_CG_BT_709) {
=======
  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
      src->fmt == UHDR_IMG_FMT_24bppRGB888) {
    if (use_bt601) {
      rgbToyuv = bt601RgbToYuv;
    } else if (src->cg == UHDR_CG_BT_709) {
>>>>>>> e36a60c ([EXP] add support for formats heif and avif)"""

resolution = """  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
      src->fmt == UHDR_IMG_FMT_24bppRGB888) {
    if (src->cg == UHDR_CG_BT_709) {"""

data = data.replace(conflict, resolution)
with open('lib/src/gainmapmath.cpp', 'w') as f:
    f.write(data)
