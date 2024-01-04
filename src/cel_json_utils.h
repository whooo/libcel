/* Copyright (c) 2024 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <json-c/json_object.h>
#include "cel_types.h"

#ifndef _CEL_JSON_UTILS_H_
#define _CEL_JSON_UTILS_H_

CEL_RC
get_json_number(
  const json_object *obj,
  const char *key,
  uint64_t *dest);

CEL_RC
get_json_handle(
  const json_object *obj,
  TPM2_HANDLE *dest);

CEL_RC
get_json_bytebuffer(
  const json_object *obj,
  const char *key,
  BYTEBUFFER *dest);

CEL_RC
get_json_hex_string_full(
  const json_object *obj,
  const char *key,
  uint8_t *dest,
  size_t len);

CEL_RC
get_json_content_type(
  const json_object *obj,
  CEL_TYPE *dest);

CEL_RC
put_json_hex_string(
  json_object *obj,
  const char *key,
  const uint8_t *src,
  size_t len);

#endif
