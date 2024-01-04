/* Copyright (c) 2024 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <json-c/json_object.h>
#include <string.h>
#include <stdlib.h>
#include "cel_types.h"
#include "cel_strings.h"
#include "cel_io.h"

CEL_RC
get_json_number(
  const json_object *obj,
  const char *key,
  uint64_t *dest)
{
  json_object *ji = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(key);
  CHECK_NULL(dest);

  ji = json_object_object_get(obj, key);
  if (!ji) {
    return CEL_RC_INVALID_VALUE;
  }

  if (!json_object_is_type(ji, json_type_int)) {
    return CEL_RC_INVALID_TYPE;
  }

  *dest = json_object_get_uint64(ji);
  return CEL_RC_SUCCESS;
}

CEL_RC
get_json_handle(
  const json_object *obj,
  TPM2_HANDLE *dest)
{
  uint64_t ti;
  json_object *ji = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  if (!json_object_object_get_ex(obj, "pcr", &ji) &&
      !json_object_object_get_ex(obj, "nv_index", &ji)) {
    return CEL_RC_INVALID_VALUE;
  }

  if (!json_object_is_type(ji, json_type_int)) {
    return CEL_RC_INVALID_TYPE;
  }

  ti = json_object_get_uint64(ji);
  if (ti > UINT32_MAX) {
    return CEL_RC_INVALID_VALUE;
  }

  *dest = ti;
  return CEL_RC_SUCCESS;
}

CEL_RC
get_json_bytebuffer(
  const json_object *obj,
  const char *key,
  BYTEBUFFER *dest)
{
  int hasit;
  json_object *js = NULL;
  const char *ts = NULL;
  size_t sl = 0;

  hasit = json_object_object_get_ex(obj, key, &js);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  if (!json_object_is_type(js, json_type_string)) {
    return CEL_RC_INVALID_TYPE;
  }
  ts = json_object_get_string(js);
  if (!ts) {
    return CEL_RC_INVALID_TYPE;
  }

  sl = strlen(ts);
  if (sl > sizeof(dest->buffer)) {
    return CEL_RC_SHORT_BUFFER;
  }

  memcpy(dest->buffer, ts, sl);
  dest->size = sl;

  return CEL_RC_SUCCESS;
}

CEL_RC
get_json_hex_string_full(
  const json_object *obj,
  const char *key,
  uint8_t *dest,
  size_t len)
{
  CEL_RC r;
  int hasit;
  json_object *js = NULL;
  const char *ts = NULL;
  int expected_len = len * 2;

  hasit = json_object_object_get_ex(obj, key, &js);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  if (!json_object_is_type(js, json_type_string)) {
    return CEL_RC_INVALID_TYPE;
  }
  if (json_object_get_string_len(js) != expected_len) {
    return CEL_RC_INVALID_VALUE;
  }
  ts = json_object_get_string(js);
  if (!ts) {
    return CEL_RC_INVALID_TYPE;
  }

  r = unhexlify(ts, dest, len);
  return r;
}

CEL_RC
get_json_content_type(
  const json_object *obj,
  CEL_TYPE *dest)
{
  CEL_RC r;
  int hasit;
  json_object *jt = NULL;
  const char *ts = NULL;
  uint64_t ti = 0;

  hasit = json_object_object_get_ex(obj, "content_type", &jt);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  switch (json_object_get_type(jt)) {
  case json_type_int:
    ti = json_object_get_uint64(jt);
    if (ti > UINT8_MAX) {
      return CEL_RC_INVALID_VALUE;
    }
    *dest = ti;
    break;
  case json_type_string:
    ts = json_object_get_string(jt);
    r = str_to_content_type(ts, dest);
    if (r) {
      return r;
    }
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }

  return CEL_RC_SUCCESS;
}

CEL_RC
put_json_hex_string(
  json_object *obj,
  const char *key,
  const uint8_t *src,
  size_t len)
{
  CEL_RC r;
  int jr;
  char *buf;
  size_t buflen = (len * 2) + 1;
  json_object *jf = NULL;

  buf = malloc(buflen);
  if (!buf) {
    return CEL_RC_MEMORY;
  }

  r = hexlify(src, len, buf, buflen);
  if (r) {
    goto out;
  }

  jf = json_object_new_string(buf);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto out;
  }

  jr = json_object_object_add(obj, key, jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    json_object_put(jf);
    goto out;
  }

  r = CEL_RC_SUCCESS;
 out:
  free(buf);
  return r;
}
