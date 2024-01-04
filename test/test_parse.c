/* Copyright (c) 2023 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/evp.h>
#include <unistd.h>
#include "cel_types.h"
#include "cel_parse.h"


struct data {
  uint8_t *bios;
  size_t bios_len;
  uint8_t *ima;
  size_t ima_len;
};

int decode_file(const char *path, uint8_t **dest, size_t *dest_len) {
  int r, fd, outlen = 0;
  const uint8_t *b64 = NULL;
  size_t b64_len = 0;
  struct stat s;
  EVP_ENCODE_CTX *ctx = NULL;

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    return fd;
  }

  r = fstat(fd, &s);
  if (r) {
    return r;
  }
  b64_len = s.st_size;

  b64 = mmap(NULL, b64_len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (!b64) {
    return -1;
  }

  *dest = malloc(b64_len);
  if (!*dest) {
    return -1;
  }
  memset(*dest, 0, b64_len);
  *dest_len = s.st_size;


  ctx = EVP_ENCODE_CTX_new();
  if (!ctx) {
    errno = ENOMEM;
    goto fail;
  }

  EVP_DecodeInit(ctx);

  r = EVP_DecodeUpdate(ctx, *dest, &outlen, b64, b64_len);
  if (r == -1) {
    errno = EINVAL;
    goto fail;
  }
  *dest_len = outlen;
  return EXIT_SUCCESS;

 fail:
  free(*dest);
  return -1;
}

void load_data(const char *name, uint8_t data[2048]) {
  int r, fd;

  memset(data, 0, 2048);
  fd = open(name, O_RDONLY);
  assert_true(fd >= 0);

  r = read(fd, data, 2048);
  assert_true(r > 0);
}

void test_parse_uefi(void **state) {
  struct data *data = *state;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;
  CEL_RC cr;
  size_t off = 0, count = 0;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, data->bios, data->bios_len, &off);
  assert_int_equal(cr, CEL_RC_SUCCESS);
  assert_int_equal(off, 65);
  assert_int_equal(event.recnum, 0);
  assert_int_equal(event.handle, 0);
  assert_int_equal(event.content_type, CEL_TYPE_PCCLIENT_STD);
  assert_int_equal(event.content.pcclient_std.event_type, 0x00000003);
  assert_int_equal(event.content.pcclient_std.event_data.size, 33);
  assert_int_equal(event.digests.count, 1);
  assert_int_equal(event.digests.digests[0].hashAlg, TPM2_ALG_SHA1);
  assert_memory_equal(event.digests.digests[0].digest.sha1,
		      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		      20);
  while (off < data->bios_len) {
    cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, data->bios_len, &off);
    assert_int_equal(cr, CEL_RC_SUCCESS);
    count++;
  }
  assert_int_equal(off, data->bios_len);
  assert_int_equal(count, 54);
  assert_int_equal(event.handle, 5);
  assert_int_equal(event.recnum, 2);
  assert_int_equal(event.content_type, CEL_TYPE_PCCLIENT_STD);
  assert_int_equal(event.content.pcclient_std.event_type, 0x80000007);
  assert_int_equal(event.content.pcclient_std.event_data.size, 40);
  assert_int_equal(event.digests.count, 1);
  assert_int_equal(event.digests.digests[0].hashAlg, TPM2_ALG_SHA256);

  CEL_Parse_Free(&ctx);
  assert_null(ctx);
}

void test_parse_ima(void **state) {
  struct data *data = *state;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;
  CEL_RC cr;
  size_t off = 0, count = 0;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, CEL_RC_SUCCESS);

  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, data->ima, data->ima_len, &off);
  assert_int_equal(cr, CEL_RC_SUCCESS);
  assert_int_equal(off, 101);
  assert_int_equal(event.recnum, 0);
  assert_int_equal(event.handle, 10);
  assert_int_equal(event.content_type, CEL_TYPE_IMA_TEMPLATE);
  assert_string_equal(event.content.ima_template.template_name, "ima-ng");
  assert_int_equal(event.content.ima_template.template_data.size, 63);
  assert_int_equal(event.digests.count, 1);
  assert_int_equal(event.digests.digests[0].hashAlg, TPM2_ALG_SHA1);

  while (off < data->ima_len) {
    cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, data->ima, data->ima_len, &off);
    assert_int_equal(cr, CEL_RC_SUCCESS);
    count++;
  }
  assert_int_equal(off, data->ima_len);
  assert_int_equal(count, 57);

  CEL_Parse_Free(&ctx);
  assert_null(ctx);
}

void test_parse_null(void **state) {
  (void) state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;

  cr = CEL_Parse_Init(NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  CEL_Parse_Free(NULL);
  CEL_Parse_Free(&ctx);

  cr = CEL_Parse_UEFI_Event(NULL, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, CEL_RC_SUCCESS);

  cr = CEL_Parse_UEFI_Event(ctx, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_UEFI_Event(ctx, &event, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_UEFI_EventHeader(NULL, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_UEFI_EventHeader(ctx, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_IMA_TEMPLATE_Event(NULL, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_Get_RECNUM(NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_Get_RECNUM(ctx, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);
}

void test_parse_get_recnum(void **state) {
  (void) state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  RECNUM recnum = 1234;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, CEL_RC_SUCCESS);

  cr = CEL_Parse_Get_RECNUM(ctx, 0x20000000, &recnum);
  assert_int_equal(cr, CEL_RC_SUCCESS);
  assert_int_equal(recnum, 0);

  cr = CEL_Parse_Get_RECNUM(ctx, 0x20000000, &recnum);
  assert_int_equal(cr, CEL_RC_SUCCESS);
  assert_int_equal(recnum, 1);

  cr = CEL_Parse_Get_RECNUM(ctx, 0xFFFFFFFF, &recnum);
  assert_int_equal(cr, CEL_RC_INVALID_VALUE);
}

void test_parse_uefi_header_short(void **state) {
  struct data *data = *state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;
  size_t off = 0, slen = 0;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  // header too short for handle
  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for event type
  slen = 4;
  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for digest
  slen = 8;
  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for event data
  slen = 28;
  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

}

void test_parse_uefi_short(void **state) {
  struct data *data = *state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;
  size_t off = 0, slen = 0;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  cr = CEL_Parse_UEFI_EventHeader(ctx, &event, data->bios, data->bios_len, &off);
  assert_int_equal(cr, CEL_RC_SUCCESS);

  slen = off;
  // header too short for handle
  cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for event type
  slen += 4;
  cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for num digest
  slen += 4;
  cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for digest type
  slen += 4;
  cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for digest data
  slen += 2;
  cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // header too short for event data
  slen += 32;
  cr = CEL_Parse_UEFI_Event(ctx, &event, data->bios, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

}

void test_parse_ima_short(void **state) {
  struct data *data = *state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;
  size_t off = 0, slen = 0;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  // too short for handle
  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, data->ima, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // too short for digest
  slen += 4;
  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, data->ima, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // too short for template name
  slen += 20;
  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, data->ima, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

  // too short for template data
  slen += 12;
  cr = CEL_Parse_IMA_TEMPLATE_Event(ctx, &event, data->ima, slen, &off);
  assert_int_equal(cr, CEL_RC_SHORT_BUFFER);

}

void test_parse_systemd(void **state) {
  (void) state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;
  uint8_t data[2048];
  size_t off = 0, sl = 0;

  load_data("data/systemd-seq.json", data);
  sl = strlen((const char *) data);

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, data, sl, &off);
  assert_int_equal(cr, 0);
  assert_int_equal(event.content_type, CEL_TYPE_SYSTEMD);
  assert_int_equal(event.recnum, 0);
  assert_int_equal(event.handle, 1);
  assert_int_equal(event.content.systemd.timestamp, 1);
  assert_int_equal(event.content.systemd.event_type, CEL_TYPE_SYSTEMD_EVENT_PHASE);
  assert_memory_equal(event.content.systemd.boot_id, "\xfa\x1a\xfe\x1f\xa1\xaf\xe1\xfa\x1a\xfe\x1f\xa1\xaf\xe1\xff\xff", 16);
  assert_memory_equal(event.content.systemd.string.buffer, "phase-tahini", event.content.systemd.string.size);

  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, data, sl, &off);
  assert_int_equal(cr, 0);
  assert_int_equal(event.content_type, CEL_TYPE_SYSTEMD);
  assert_int_equal(event.recnum, 1);
  assert_int_equal(event.handle, 1);
  assert_int_equal(event.content.systemd.timestamp, 2);
  assert_int_equal(event.content.systemd.event_type, CEL_TYPE_SYSTEMD_EVENT_FILESYSTEM);
  assert_memory_equal(event.content.systemd.string.buffer, "filesystem-tahini", event.content.systemd.string.size);

  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, data, sl, &off);
  assert_int_equal(cr, 0);
  assert_int_equal(event.content_type, CEL_TYPE_SYSTEMD);
  assert_int_equal(event.recnum, 2);
  assert_int_equal(event.handle, 1);
  assert_int_equal(event.content.systemd.timestamp, 3);
  assert_int_equal(event.content.systemd.event_type, CEL_TYPE_SYSTEMD_EVENT_MACHINE_ID);
  assert_memory_equal(event.content.systemd.string.buffer, "machine-id-tahini", event.content.systemd.string.size);

  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, data, sl, &off);
  assert_int_equal(cr, 0);
  assert_int_equal(event.content_type, CEL_TYPE_SYSTEMD);
  assert_int_equal(event.recnum, 3);
  assert_int_equal(event.handle, 1);
  assert_int_equal(event.content.systemd.timestamp, 4);
  assert_int_equal(event.content.systemd.event_type, CEL_TYPE_SYSTEMD_EVENT_VOLUME_KEY);
  assert_memory_equal(event.content.systemd.string.buffer, "volume-key-tahini", event.content.systemd.string.size);

  assert_int_equal(off, sl);
}

void test_parse_systemd_nulls(void **state) {
  (void) state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;

  cr = CEL_Parse_SYSTEMD_Event(NULL, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  cr = CEL_Parse_SYSTEMD_Event(ctx, NULL, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, NULL, 0, NULL);
  assert_int_equal(cr, CEL_RC_BAD_REFERENCE);

}

void test_parse_systemd_bad(void **state) {
  (void) state;
  CEL_RC cr;
  CEL_PARSE_CONTEXT *ctx = NULL;
  TPMS_CEL_EVENT event;

  cr = CEL_Parse_Init(&ctx);
  assert_int_equal(cr, 0);

  // bad json
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "\"", 1, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_VALUE);

  // not json object
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "[]", 2, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_TYPE);

  // missing content type
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{}", 2, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_VALUE);

  // content type not string/int
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{\"content_type\": []}", 20, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_TYPE);

  // not systemd type
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{\"content_type\": \"cel\"}", 23, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_TYPE);

  // missing handle
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{\"content_type\": \"systemd\"}", 27, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_VALUE);

  // missing digests
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{\"content_type\": \"systemd\", \"pcr\": 1}", 37, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_VALUE);

  // bad digests
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{\"content_type\": \"systemd\", \"pcr\": 1, \"digests\": {}}", 52, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_TYPE);

  // missing content
  cr = CEL_Parse_SYSTEMD_Event(ctx, &event, (uint8_t *) "{\"content_type\": \"systemd\", \"pcr\": 1, \"digests\": []}", 52, NULL);
  assert_int_equal(cr, CEL_RC_INVALID_VALUE);
}

int main(int argc, char **argv)
{
  (void) argc;
  (void) argv;
  int r;

  struct data data = { NULL, 0, NULL, 0 };

  r = decode_file("data/binary_bios_measurements.b64", &data.bios, &data.bios_len);
  if (r) {
    dprintf(2, "failed decode data/binary_bios_measurements.b64: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  r = decode_file("data/binary_runtime_measurements.b64", &data.ima, &data.ima_len);
  if (r) {
    dprintf(2, "failed decode data/binary_rumtime_measurements.b64: %s\n", strerror(errno));
    return EXIT_FAILURE;
  }

  const struct CMUnitTest tests[] = {
    cmocka_unit_test_prestate(test_parse_uefi, &data),
    cmocka_unit_test_prestate(test_parse_ima, &data),
    cmocka_unit_test(test_parse_null),
    cmocka_unit_test(test_parse_get_recnum),
    cmocka_unit_test_prestate(test_parse_uefi_header_short, &data),
    cmocka_unit_test_prestate(test_parse_uefi_short, &data),
    cmocka_unit_test_prestate(test_parse_ima_short, &data),
    cmocka_unit_test(test_parse_systemd),
    cmocka_unit_test(test_parse_systemd_nulls),
    cmocka_unit_test(test_parse_systemd_bad),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
