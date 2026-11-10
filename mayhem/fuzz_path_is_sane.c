// mg_path_is_sane() is exported (mongoose.h) and takes a struct mg_str: a pointer and a length, with no
// promise of a NUL terminator. Callers pass slices of larger buffers (mg_http_start_upload()'s `name` is a
// slice of the request), so the input is: byte 0 = how many of the following bytes the slice covers
// (modulo the available length + 1), the rest = the bytes. They are copied into a heap block of exactly
// that size, so ASan sees any read past the end of the data when the slice reaches its end.
// An input with no length byte is rejected: the format needs it.
#define MG_ENABLE_LOG 0

#include "mongoose.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t avail, len;
  char *buf;
  if (size < 1) return -1;
  avail = size - 1;
  len = data[0] % (avail + 1);
  buf = (char *) malloc(avail);
  if (buf == NULL) return -1;
  if (avail > 0) memcpy(buf, data + 1, avail);
  (void) mg_path_is_sane(mg_str_n(buf, len));
  free(buf);
  return 0;
}
