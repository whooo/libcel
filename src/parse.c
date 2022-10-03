/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdlib.h>
#include <string.h>
#include "cel_types.h"
#include "cel_io.h"


typedef struct CEL_PARSE_CONTEXT CEL_PARSE_CONTEXT;
struct CEL_PARSE_CONTEXT {
  UINT64 seqnums[TPM2_MAX_PCRS];
};


CEL_RC
CEL_Parse_Init(
  CEL_PARSE_CONTEXT **ctx)
{
  *ctx = malloc(sizeof(CEL_PARSE_CONTEXT));
  if (!*ctx) {
    return 1;
  }

  memset(*ctx, 0, sizeof(CEL_PARSE_CONTEXT));

  return 0;
}

void
CEL_Parse_Free(
  CEL_PARSE_CONTEXT **ctx)
{
  free(*ctx);
  *ctx = NULL;
}

UINT64 get_seqnum(
  CEL_PARSE_CONTEXT *ctx, UINT32 pcr)
{
  return ctx->seqnums[pcr]++;
}

CEL_RC
CEL_Parse_UEFI_Event(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  uint32_t num_digs;
  uint16_t alg;
  size_t diglen, off = get_offset(offset);

  CHECK_NULL(ctx);
  CHECK_NULL(event);
  CHECK_NULL(buffer);

  event->content_type = CEL_TYPE_PCCLIENT_STD;

  r = get_le_uint32(buffer, len, &off, &event->pcr);
  if (r) {
    return r;
  }

  event->recnum = get_seqnum(ctx, event->pcr);

  r = get_le_uint32(buffer, len, &off, &event->content.pcclient_std.event_type);
  if (r) {
    return r;
  }

  r = get_le_uint32(buffer, len, &off, &num_digs);
  if (r) {
    return r;
  }

  for (uint32_t i=0;i < num_digs;i++) {
    r = get_le_uint16(buffer, len, &off, &alg);
    if (r) {
      return r;
    }
    event->digests.digests[i].hashAlg = alg;
    diglen = get_digest_size(alg);
    if (!diglen) {
      return CEL_RC_UNSUPPORTED_DIGEST;
    }
    r = get_bytes(buffer,
		  len,
		  &off,
		  event->digests.digests[i].digest.sha512,
		  diglen);
    if (r) {
      return r;
    }
    event->digests.count++;
  }

  r = get_uefi_bytebuffer(buffer,
			  len,
			  &off,
			  &event->content.pcclient_std.event_data);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_Parse_UEFI_EventHeader(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset);

  CHECK_NULL(ctx);
  CHECK_NULL(event);
  CHECK_NULL(buffer);

  event->content_type = CEL_TYPE_PCCLIENT_STD;

  r = get_le_uint32(buffer, len, &off, &event->pcr);
  if (r) {
    return r;
  }

  event->recnum = get_seqnum(ctx, event->pcr);

  r = get_le_uint32(buffer, len, &off, &event->content.pcclient_std.event_type);
  if (r) {
    return r;
  }

  r = get_bytes(buffer,
		len,
		&off,
		event->digests.digests[0].digest.sha1,
		TPM2_SHA1_DIGEST_SIZE);
  if (r) {
    return r;
  }

  event->digests.digests[0].hashAlg = TPM2_ALG_SHA1;
  event->digests.count = 1;

  r = get_uefi_bytebuffer(buffer,
			  len,
			  &off,
			  &event->content.pcclient_std.event_data);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_Parse_IMA_TEMPLATE_Event(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset);

  CHECK_NULL(ctx);
  CHECK_NULL(event);
  CHECK_NULL(buffer);

  event->content_type = CEL_TYPE_IMA_TEMPLATE;

  r = get_le_uint32(buffer, len, &off, &event->pcr);
  if (r) {
    return r;
  }

  r = get_bytes(buffer,
		len,
		&off,
		event->digests.digests[0].digest.sha1,
		TPM2_SHA1_DIGEST_SIZE);
  if (r) {
    return r;
  }

  event->digests.digests[0].hashAlg = TPM2_ALG_SHA1;
  event->digests.count = 1;

  r = get_uefi_bytebuffer(buffer,
			  len,
			  &off,
			  &event->content.ima_template.template_name);
  if (r) {
    return r;
  }

  r = get_uefi_bytebuffer(buffer,
			  len,
			  &off,
			  &event->content.ima_template.template_data);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}
