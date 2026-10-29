// In-process libFuzzer port of OSS-Fuzz's honggfuzz-only fuzz_netdriver_http: the HTTP server
// serving static files, fed bytes as if they had been received on an accepted connection.
#define MG_ENABLE_LOG 0
#define MG_ENABLE_LINES 1

#include "mongoose.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void fn(struct mg_connection *c, int ev, void *ev_data) {
  struct mg_http_serve_opts opts = {.root_dir = "."};
  if (ev == MG_EV_HTTP_MSG) {
    mg_http_serve_dir(c, (struct mg_http_message *) ev_data, &opts);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct mg_mgr mgr;
  struct mg_connection *c;
  mg_mgr_init(&mgr);
  c = mg_alloc_conn(&mgr);
  if (c == NULL) return -1;
  c->is_accepted = 1;
  c->fn = fn;
  c->pfn = http_cb;
  LIST_ADD_HEAD(struct mg_connection, &mgr.conns, c);
  if (size > 0) mg_iobuf_add(&c->recv, 0, data, size);
  c->pfn(c, MG_EV_READ, NULL);
  mg_close_conn(c);
  mg_mgr_free(&mgr);
  return 0;
}
