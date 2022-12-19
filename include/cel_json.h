/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <json-c/json_object.h>
#include "cel_types.h"

#ifndef _CEL_JSON_H_
#define _CEL_JSON_H_

typedef uint8_t CEL_JSON_FLAGS;
#define CEL_JSON_FLAGS_USE_NUMBERS 0x01
#define CEL_JSON_FLAGS_ALWAYS_ARRAY 0x02

CEL_RC
CEL_JSON_TPMS_CEL_EVENT_Marshal(
  const TPMS_CEL_EVENT *src,
  json_object **obj,
  CEL_JSON_FLAGS flags);

CEL_RC
CEL_JSON_TPMS_CEL_EVENT_Unmarshal(
  const json_object *obj,
  TPMS_CEL_EVENT *dest);

#endif
