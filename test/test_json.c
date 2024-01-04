#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "cel_types.h"
#include "cel_json.h"

enum {
  JSON_KEY, JSON_INDEX, JSON_VALUE, JSON_STRING, JSON_INTEGER,
};

int json_value_by_path(json_object *root, json_object **obj, va_list args) {
  json_object *cur = root;
  int type, index, p = 0;
  size_t len;
  char *key;
  json_bool hasit;

  while (1) {
    type = va_arg(args, int);
    switch (type) {
    case JSON_KEY:
      if (!json_object_is_type(cur, json_type_object)) {
	goto fail;
      }
      p++;
      key = va_arg(args, char *);
      hasit = json_object_object_get_ex(cur, key, &cur);
      if (!hasit) {
	goto fail;
      }
      break;
    case JSON_INDEX:
      if (!json_object_is_type(cur, json_type_array)) {
	goto fail;
      }
      p++;
      index = va_arg(args, int);
      len = json_object_array_length(cur);
      if ((size_t) index > len) {
	goto fail;
      }
      cur = json_object_array_get_idx(cur, index);
      if (!cur) {
	goto fail;
      }
      break;
    case JSON_VALUE:
      goto done;
      break;
    case JSON_STRING:
      if (!json_object_is_type(cur, json_type_string)) {
	goto fail;
      }
      goto done;
      break;
    case JSON_INTEGER:
      if (!json_object_is_type(cur, json_type_int)) {
	goto fail;
      }
      goto done;
      break;
    default:
      goto fail;
    }
    p++;
  }

 done:
  *obj = cur;
  return 0;
 fail:
  return p;
}

void assert_json_string_equal(json_object *root, const char *value, ...) {
  int r;
  va_list args;
  const char *str = NULL;
  json_object *obj = NULL;

  va_start(args, value);

  r = json_value_by_path(root, &obj, args);
  va_end(args);
  if (r) {
    assert_int_equal(r, 0);
  }
  assert_non_null(obj);

  r = json_object_is_type(obj, json_type_string);
  if (!r) {
    assert_int_not_equal(r, 0);
    // FIXME
  }

  str = json_object_get_string(obj);
  if (!str) {
    // FIXME
  }

  assert_string_equal(value, str);
}

void assert_json_int_equal(json_object *root, uint64_t value, ...) {
  int r;
  va_list args;
  uint64_t num;
  json_object *obj = NULL;

  va_start(args, value);

  r = json_value_by_path(root, &obj, args);
  va_end(args);
  if (r) {
    // FIXME
  }

  r = json_object_is_type(obj, json_type_int);
  if (!r) {
    // FIXME
  }

  num = json_object_get_uint64(obj);

  assert_int_equal(value, num);
}

json_object *json_get_value(json_object *root, ...) {
  int r;
  json_object *obj;
  va_list args;

  va_start(args, root);

  r = json_value_by_path(root, &obj, args);
  va_end(args);
  if (r) {
    return NULL;
  }

  return obj;
}

void test_json_cel_version(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_MGMT,
  };

  event.content.celmgt.count = 1;
  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_CEL_VERSION;
  event.content.celmgt.events[0].data.cel_version.major = 255;
  event.content.celmgt.events[0].data.cel_version.minor = 522;
  event.digests.count = 1;
  event.digests.digests[0].hashAlg = TPM2_ALG_SHA1;
  memset(event.digests.digests[0].digest.sha1, 0xAA, 20);

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "cel", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_int_equal(obj, event.recnum, JSON_KEY, "recnum", JSON_INTEGER);
  assert_json_int_equal(obj, event.handle, JSON_KEY, "pcr", JSON_INTEGER);
  assert_json_string_equal(obj, "cel_version", JSON_KEY, "content", JSON_KEY, "type", JSON_STRING);
  assert_json_int_equal(obj, event.content.celmgt.events[0].data.cel_version.major, JSON_KEY, "content", JSON_KEY, "data", JSON_KEY, "major", JSON_INTEGER);
  assert_json_int_equal(obj, event.content.celmgt.events[0].data.cel_version.minor, JSON_KEY, "content", JSON_KEY, "data", JSON_KEY, "minor", JSON_INTEGER);
  assert_json_string_equal(obj, "sha1", JSON_KEY, "digests", JSON_INDEX, 0, JSON_KEY, "hashAlg", JSON_STRING);
  assert_json_string_equal(obj, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JSON_KEY, "digests", JSON_INDEX, 0, JSON_KEY, "digest", JSON_STRING);
  json_object_put(obj);

  // test with numbers here
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, CEL_JSON_FLAGS_USE_NUMBERS);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_int_equal(obj, CEL_TYPE_MGMT, JSON_KEY, "content_type", JSON_INTEGER);
  assert_json_int_equal(obj, CEL_TYPE_MGMT_CEL_VERSION, JSON_KEY, "content", JSON_KEY, "type", JSON_INTEGER);
  assert_json_int_equal(obj, TPM2_ALG_SHA1, JSON_KEY, "digests", JSON_INDEX, 0, JSON_KEY, "hashAlg", JSON_INTEGER);
  json_object_put(obj);

  // test NULL here
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, NULL, 0);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  obj = NULL;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(NULL, &obj, 0);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
  assert_null(obj);
}

void test_json_cel_firmware_end(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_MGMT,
  };

  event.content.celmgt.count = 1;
  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_FIRMWARE_END;

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "cel", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_int_equal(obj, event.recnum, JSON_KEY, "recnum", JSON_INTEGER);
  assert_json_int_equal(obj, event.handle, JSON_KEY, "pcr", JSON_INTEGER);
  assert_json_string_equal(obj, "firmware_end", JSON_KEY, "content", JSON_KEY, "type", JSON_STRING);
  json_object_put(obj);
}

void test_json_cel_timestamp(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 0x20000000,
    .content_type = CEL_TYPE_MGMT,
  };

  event.content.celmgt.count = 1;
  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_CEL_TIMESTAMP;
  event.content.celmgt.events[0].data.cel_timestamp = 72057594037927936;

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "cel", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_int_equal(obj, event.recnum, JSON_KEY, "recnum", JSON_INTEGER);
  assert_json_int_equal(obj, event.handle, JSON_KEY, "nv_index", JSON_INTEGER);
  assert_json_string_equal(obj, "cel_timestamp", JSON_KEY, "content", JSON_KEY, "type", JSON_STRING);
  assert_json_int_equal(obj, 72057594037927936, JSON_KEY, "content", JSON_KEY, "data", JSON_INTEGER);
  json_object_put(obj);
}

void test_json_cel_state_trans(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_MGMT,
  };

  event.content.celmgt.count = 1;
  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_STATE_TRANS;
  event.content.celmgt.events[0].data.state_trans = CEL_STATE_TRANS_KEXEC;

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "cel", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_string_equal(obj, "state_trans", JSON_KEY, "content", JSON_KEY, "type", JSON_STRING);
  assert_json_string_equal(obj, "kexec", JSON_KEY, "content", JSON_KEY, "data", JSON_STRING);
  json_object_put(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, CEL_JSON_FLAGS_USE_NUMBERS);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_int_equal(obj, CEL_TYPE_MGMT, JSON_KEY, "content_type", JSON_INTEGER);
  assert_json_int_equal(obj, CEL_TYPE_MGMT_STATE_TRANS, JSON_KEY, "content", JSON_KEY, "type", JSON_INTEGER);
  assert_json_int_equal(obj, CEL_STATE_TRANS_KEXEC, JSON_KEY, "content", JSON_KEY, "data", JSON_INTEGER);
  json_object_put(obj);
}

void test_json_cel_multi(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_MGMT,
  };

  event.content.celmgt.count = 2;
  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_FIRMWARE_END;
  event.content.celmgt.events[1].type = CEL_TYPE_MGMT_STATE_TRANS;
  event.content.celmgt.events[1].data.state_trans = CEL_STATE_TRANS_KEXEC;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "cel", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_string_equal(obj, "firmware_end", JSON_KEY, "content", JSON_INDEX, 0, JSON_KEY, "type", JSON_STRING);
  assert_json_string_equal(obj, "state_trans", JSON_KEY, "content", JSON_INDEX, 1, JSON_KEY, "type", JSON_STRING);
  assert_json_string_equal(obj, "kexec", JSON_KEY, "content", JSON_INDEX, 1, JSON_KEY, "data", JSON_STRING);
  json_object_put(obj);
}

void test_json_pcclient(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_PCCLIENT_STD,
  };

  event.content.pcclient_std.event_type = 0x800000E2;
  event.content.pcclient_std.event_data.size = 5;
  memset(event.content.pcclient_std.event_data.buffer, 0xBB, 5);

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "pcclient_std", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_string_equal(obj, "ev_efi_spdm_firmware_config", JSON_KEY, "content", JSON_KEY, "event_type", JSON_STRING);
  assert_json_string_equal(obj, "bbbbbbbbbb", JSON_KEY, "content", JSON_KEY, "event_data", JSON_STRING);
  json_object_put(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, CEL_JSON_FLAGS_USE_NUMBERS);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_int_equal(obj, CEL_TYPE_PCCLIENT_STD, JSON_KEY, "content_type", JSON_VALUE);
  assert_json_int_equal(obj, event.content.pcclient_std.event_type, JSON_KEY, "content", JSON_KEY, "event_type", JSON_INTEGER);
  json_object_put(obj);
}

void test_json_ima_template(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_IMA_TEMPLATE,
  };

  memcpy(event.content.ima_template.template_name, "falafel\x00", 8);
  event.content.ima_template.template_data.size = 3;
  memset(event.content.ima_template.template_data.buffer, 0xCC, 3);

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "ima_template", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_string_equal(obj, "falafel", JSON_KEY, "content", JSON_KEY, "template_name", JSON_STRING);
  assert_json_string_equal(obj, "cccccc", JSON_KEY, "content", JSON_KEY, "template_data", JSON_STRING);
  json_object_put(obj);
}

void test_json_bad_types(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_MGMT,
  };

  event.digests.count = 1;
  event.digests.digests[0].hashAlg = TPM2_ALG_NULL;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_UNSUPPORTED_DIGEST);
  event.digests.count = 0;

  event.content_type = 0xFF;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, CEL_JSON_FLAGS_USE_NUMBERS);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  event.content_type = CEL_TYPE_MGMT;

  event.content.celmgt.count = 1;
  event.content.celmgt.events[0].type = 0xFF;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_STATE_TRANS;
  event.content.celmgt.events[0].data.state_trans = 0xFF;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  event.handle = 0xFF000000;
  event.content.celmgt.events[0].data.state_trans = CEL_STATE_TRANS_KEXEC;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  event.handle = 6;

  event.content_type = CEL_TYPE_PCCLIENT_STD;
  event.content.pcclient_std.event_type = 0xFF000000;
  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void load_data(const char *name, char data[2048]) {
  int r, fd;

  memset(data, 0, 2048);
  fd = open(name, O_RDONLY);
  assert_true(fd >= 0);

  r = read(fd, data, 2048);
  assert_true(r > 0);
}

void test_json_unmarshal_cel_version(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/cel_version.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
  json_object_put(obj);
  assert_int_equal(event.handle, 3);
  assert_int_equal(event.recnum, 6);
  assert_int_equal(event.content_type, CEL_TYPE_MGMT);
  assert_int_equal(event.digests.count, 1);
  assert_int_equal(event.digests.digests[0].hashAlg, TPM2_ALG_SHA1);
  assert_memory_equal(event.digests.digests[0].digest.sha1, "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB", 20);
  assert_int_equal(event.content.celmgt.count, 1);
  assert_int_equal(event.content.celmgt.events[0].type, CEL_TYPE_MGMT_CEL_VERSION);
  assert_int_equal(event.content.celmgt.events[0].data.cel_version.major, 123);
  assert_int_equal(event.content.celmgt.events[0].data.cel_version.minor, 456);
}

void test_json_unmarshal_cel_multi(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/cel_multi.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
  json_object_put(obj);
  assert_int_equal(event.handle, 2);
  assert_int_equal(event.recnum, 4);
  assert_int_equal(event.content_type, CEL_TYPE_MGMT);
  assert_int_equal(event.digests.count, 0);
  assert_int_equal(event.content.celmgt.count, 3);

  assert_int_equal(event.content.celmgt.events[0].type, CEL_TYPE_MGMT_FIRMWARE_END);

  assert_int_equal(event.content.celmgt.events[1].type, CEL_TYPE_MGMT_CEL_TIMESTAMP);
  assert_int_equal(event.content.celmgt.events[1].data.cel_timestamp, 1234567890);

  assert_int_equal(event.content.celmgt.events[2].type, CEL_TYPE_MGMT_STATE_TRANS);
  assert_int_equal(event.content.celmgt.events[2].data.state_trans, CEL_STATE_TRANS_KEXEC);
}

void test_json_unmarshal_cel_multi_numbers(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/cel_multi_numbers.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
  json_object_put(obj);
  assert_int_equal(event.handle, 10);
  assert_int_equal(event.recnum, 20);
  assert_int_equal(event.content_type, CEL_TYPE_MGMT);
  assert_int_equal(event.digests.count, 1);
  assert_int_equal(event.digests.digests[0].hashAlg, TPM2_ALG_SHA1);
  assert_memory_equal(event.digests.digests[0].digest.sha1, "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", 20);
  assert_int_equal(event.content.celmgt.count, 4);

  assert_int_equal(event.content.celmgt.events[0].type, CEL_TYPE_MGMT_FIRMWARE_END);

  assert_int_equal(event.content.celmgt.events[1].type, CEL_TYPE_MGMT_CEL_TIMESTAMP);
  assert_int_equal(event.content.celmgt.events[1].data.cel_timestamp, 1234567890);

  assert_int_equal(event.content.celmgt.events[2].type, CEL_TYPE_MGMT_STATE_TRANS);
  assert_int_equal(event.content.celmgt.events[2].data.state_trans, CEL_STATE_TRANS_KEXEC);

  assert_int_equal(event.content.celmgt.events[3].type, CEL_TYPE_MGMT_CEL_VERSION);
  assert_int_equal(event.content.celmgt.events[3].data.cel_version.major, 123);
  assert_int_equal(event.content.celmgt.events[3].data.cel_version.minor, 456);
}

void test_json_unmarshal_bad_recnum(void **state) {
  (void) state;
  char *recnum_str = "{ \"recnum\": \"1\" }";
  char *recnum_missing = "{}";
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  obj = json_tokener_parse(recnum_str);
  assert_non_null(obj);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  json_object_put(obj);

  obj = json_tokener_parse(recnum_missing);
  assert_non_null(obj);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  json_object_put(obj);
}

void test_json_unmarshal_bad_handle(void **state) {
  (void) state;
  char *handle_obj = "{ \"recnum\": 1, \"pcr\": {} }";
  char *handle_missing = "{ \"recnum\": 1 }";
  char *handle_large = "{ \"recnum\": 1, \"pcr\": 4294967296 }";
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  obj = json_tokener_parse(handle_obj);
  assert_non_null(obj);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  json_object_put(obj);

  obj = json_tokener_parse(handle_missing);
  assert_non_null(obj);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  json_object_put(obj);

  obj = json_tokener_parse(handle_large);
  assert_non_null(obj);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  json_object_put(obj);
}

void test_json_unmarshal_bad_digests(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_digests.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "not_array", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "not_object", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_hashalg_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_hashalg_value", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_hashalg_string", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_digest_len", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "digest_not_hex", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "missing_digest", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_digest_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "missing_hashalg", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "large_hashalg", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  json_object_put(obj);
}

void test_json_unmarshal_bad_cel_version(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_cel_version.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "missing_major", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "missing_minor", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "large_major", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "large_minor", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

void test_json_unmarshal_bad_state_trans(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_state_trans.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "large_state_trans", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_state_trans_str", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_state_trans_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_unmarshal_bad_cel(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_cel.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "missing_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "large_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_type_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_type_string", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "missing_data", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_content", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_type_multi", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_unmarshal_pcclient(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/pcclient.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
  json_object_put(obj);
  assert_int_equal(event.handle, 9);
  assert_int_equal(event.recnum, 12);
  assert_int_equal(event.content_type, CEL_TYPE_PCCLIENT_STD);
  assert_int_equal(event.content.pcclient_std.event_type, 3);
  assert_int_equal(event.content.pcclient_std.event_data.size, 4);
  assert_memory_equal(event.content.pcclient_std.event_data.buffer, "\xAA\xBB\xCC\xDD", 4);
}

void test_json_unmarshal_pcclient_numbers(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/pcclient_numbers.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
  json_object_put(obj);
  assert_int_equal(event.handle, 9);
  assert_int_equal(event.recnum, 12);
  assert_int_equal(event.content_type, CEL_TYPE_PCCLIENT_STD);
  assert_int_equal(event.content.pcclient_std.event_type, 3);
  assert_int_equal(event.content.pcclient_std.event_data.size, 4);
  assert_memory_equal(event.content.pcclient_std.event_data.buffer, "\xAA\xBB\xCC\xDD", 4);
}

void test_json_unmarshal_bad_pcclient(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_pcclient.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "missing_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "large_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_type_str", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_type_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "missing_data", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_data_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_hex", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

void test_json_unmarshal_ima_template(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/ima_template.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
  json_object_put(obj);
  assert_int_equal(event.handle, 12);
  assert_int_equal(event.recnum, 9);
  assert_int_equal(event.content_type, CEL_TYPE_IMA_TEMPLATE);
  assert_string_equal(event.content.ima_template.template_name, "name");
  assert_int_equal(event.content.ima_template.template_data.size, 4);
  assert_memory_equal(event.content.ima_template.template_data.buffer, "\xAA\xBB\xCC\xDD", 4);
}

void test_json_unmarshal_bad_ima_template(void **state) {
  (void) state;
  char data[2048], *ls = NULL;
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL, *js = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_ima_template.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "missing_name", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_name_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "large_name", &jt);
  assert_true(hasit);
  ls = malloc(sizeof(event.content.ima_template.template_name) + 1);
  assert_non_null(ls);
  memset(ls, 'f', sizeof(event.content.ima_template.template_name));
  ls[sizeof(event.content.ima_template.template_name) + 1] = '\x00';
  js = json_get_value(jt, JSON_KEY, "content", JSON_KEY, "template_name", JSON_STRING);
  assert_non_null(js);
  json_object_set_string(js, ls);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  hasit = json_object_object_get_ex(obj, "missing_data", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_data_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_hex", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

void test_json_unmarshal_bad_event(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  int hasit;
  json_object *obj = NULL, *jt = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/bad_event.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  hasit = json_object_object_get_ex(obj, "missing_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "large_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_type_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "missing_content", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  hasit = json_object_object_get_ex(obj, "bad_type_str", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  hasit = json_object_object_get_ex(obj, "bad_type", &jt);
  assert_true(hasit);
  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(jt, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(NULL, &event);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
}

void test_json_systemd(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_SYSTEMD,
  };

  event.content.systemd.event_type = CEL_TYPE_SYSTEMD_EVENT_PHASE;
  memcpy(event.content.systemd.string.buffer, "falafel", 7);
  event.content.systemd.string.size = 7;
  event.content.systemd.timestamp = 7843;
  memset(event.content.systemd.boot_id, 0xFA, 16);

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_string_equal(obj, "systemd", JSON_KEY, "content_type", JSON_VALUE);
  assert_json_string_equal(obj, "falafel", JSON_KEY, "content", JSON_KEY, "string", JSON_VALUE);
  assert_json_string_equal(obj, "fafafafafafafafafafafafafafafafa", JSON_KEY, "content", JSON_KEY, "bootId", JSON_VALUE);
  assert_json_int_equal(obj, 7843, JSON_KEY, "content", JSON_KEY, "timestamp", JSON_INTEGER);

}

void test_json_systemd_numbers(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_SYSTEMD,
  };

  event.content.systemd.event_type = CEL_TYPE_SYSTEMD_EVENT_FILESYSTEM;

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, CEL_JSON_FLAGS_USE_NUMBERS);
  assert_int_equal(r, CEL_RC_SUCCESS);
  assert_non_null(obj);

  assert_json_int_equal(obj, CEL_TYPE_SYSTEMD_EVENT_FILESYSTEM, JSON_KEY, "content", JSON_KEY, "event_type", JSON_INTEGER);

}

void test_json_systemd_bad_event_type(void **state) {
  (void) state;
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event = {
    .recnum = 1234,
    .handle = 6,
    .content_type = CEL_TYPE_SYSTEMD,
  };

  event.content.systemd.event_type = 0xFF;

  r = CEL_JSON_TPMS_CEL_EVENT_Marshal(&event, &obj, 0);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_systemd_unmarshal(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, 0);
}

void test_json_systemd_unmarshal_bad_event_type(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_bad_event_type.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_systemd_unmarshal_bad_event_type_str(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_bad_event_type_str.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_systemd_unmarshal_bad_event_type_json_type(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_bad_event_type_json_type.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_systemd_unmarshal_bad_event_type_num(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_bad_event_type_num.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

void test_json_systemd_unmarshal_bad_timestamp(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_bad_timestamp.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_json_systemd_unmarshal_missing_event_type(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_missing_event_type.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

void test_json_systemd_unmarshal_missing_string(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_missing_string.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

void test_json_systemd_unmarshal_bad_bootid(void **state) {
  (void) state;
  char data[2048];
  CEL_RC r;
  json_object *obj = NULL;
  TPMS_CEL_EVENT event;

  load_data("data/systemd_bad_bootid.json", data);
  obj = json_tokener_parse(data);
  assert_non_null(obj);

  r = CEL_JSON_TPMS_CEL_EVENT_Unmarshal(obj, &event);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
}

int main(int argc, char **argv)
{
  (void) argc;
  (void) argv;

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_json_cel_version),
    cmocka_unit_test(test_json_cel_firmware_end),
    cmocka_unit_test(test_json_cel_timestamp),
    cmocka_unit_test(test_json_cel_state_trans),
    cmocka_unit_test(test_json_cel_multi),
    cmocka_unit_test(test_json_pcclient),
    cmocka_unit_test(test_json_ima_template),
    cmocka_unit_test(test_json_bad_types),
    cmocka_unit_test(test_json_unmarshal_cel_version),
    cmocka_unit_test(test_json_unmarshal_cel_multi),
    cmocka_unit_test(test_json_unmarshal_cel_multi_numbers),
    cmocka_unit_test(test_json_unmarshal_bad_recnum),
    cmocka_unit_test(test_json_unmarshal_bad_handle),
    cmocka_unit_test(test_json_unmarshal_bad_digests),
    cmocka_unit_test(test_json_unmarshal_bad_cel_version),
    cmocka_unit_test(test_json_unmarshal_bad_state_trans),
    cmocka_unit_test(test_json_unmarshal_bad_cel),
    cmocka_unit_test(test_json_unmarshal_pcclient),
    cmocka_unit_test(test_json_unmarshal_pcclient_numbers),
    cmocka_unit_test(test_json_unmarshal_bad_pcclient),
    cmocka_unit_test(test_json_unmarshal_ima_template),
    cmocka_unit_test(test_json_unmarshal_bad_ima_template),
    cmocka_unit_test(test_json_unmarshal_bad_event),
    cmocka_unit_test(test_json_systemd),
    cmocka_unit_test(test_json_systemd_numbers),
    cmocka_unit_test(test_json_systemd_bad_event_type),
    cmocka_unit_test(test_json_systemd_unmarshal),
    cmocka_unit_test(test_json_systemd_unmarshal_bad_event_type),
    cmocka_unit_test(test_json_systemd_unmarshal_bad_event_type_str),
    cmocka_unit_test(test_json_systemd_unmarshal_bad_event_type_json_type),
    cmocka_unit_test(test_json_systemd_unmarshal_bad_event_type_num),
    cmocka_unit_test(test_json_systemd_unmarshal_bad_timestamp),
    cmocka_unit_test(test_json_systemd_unmarshal_missing_event_type),
    cmocka_unit_test(test_json_systemd_unmarshal_missing_string),
    cmocka_unit_test(test_json_systemd_unmarshal_bad_bootid),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
