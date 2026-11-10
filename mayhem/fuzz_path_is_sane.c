// mg_path_is_sane() is exported (mongoose.h) and takes a struct mg_str: a pointer and a length, with no
// promise of a NUL terminator. The input is copied into a heap block of exactly `size` bytes so that
// ASan sees any read past the length the caller passed.
#define MG_ENABLE_LOG 0

#include "mongoose.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *buf = (char *) malloc(size);
  if (buf == NULL) return -1;
  if (size > 0) memcpy(buf, data, size);
  (void) mg_path_is_sane(mg_str_n(buf, size));
  free(buf);
  return 0;
}
