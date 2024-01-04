/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stddef.h>
#include "cel_types.h"

#ifndef _CEL_PARSE_H_
#define _CEL_PARSE_H_

typedef struct CEL_PARSE_CONTEXT CEL_PARSE_CONTEXT;

CEL_RC
CEL_Parse_Init(
  CEL_PARSE_CONTEXT **ctx);

void
CEL_Parse_Free(
  CEL_PARSE_CONTEXT **ctx);

CEL_RC
CEL_Parse_Get_RECNUM(
  CEL_PARSE_CONTEXT *ctx,
  TPM2_HANDLE pcr,
  RECNUM *recnum);

CEL_RC
CEL_Parse_UEFI_EventHeader(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_Parse_UEFI_Event(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_Parse_IMA_TEMPLATE_Event(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_Parse_SYSTEMD_Event(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  const uint8_t *buffer,
  size_t len,
  size_t *offset);
#endif
