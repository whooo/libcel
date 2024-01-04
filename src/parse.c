/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include "cel_types.h"
#include "cel_io.h"
#include "cel_json_utils.h"


/* needed for systemd parsing */
CEL_RC
CEL_JSON_TPML_DIGEST_VALUES_Unmarshal(
  const json_object *obj,
  TPML_DIGEST_VALUES *dest);

/* needed for systemd parsing */
CEL_RC
CEL_JSON_TPMS_EVENT_SYSTEMD_Unmarshal(
  const json_object *obj,
  TPMS_EVENT_SYSTEMD *dest);

struct pair_entry {
  TPM2_HANDLE handle;
  RECNUM recnum;
  SLIST_ENTRY(pair_entry) entries;
};

SLIST_HEAD(pairhead, pair_entry);

typedef struct CEL_PARSE_CONTEXT CEL_PARSE_CONTEXT;
struct CEL_PARSE_CONTEXT {
  struct pairhead head;
};


CEL_RC
CEL_Parse_Init(
  CEL_PARSE_CONTEXT **ctx)
{
  struct pair_entry *p = NULL;

  CHECK_NULL(ctx);

  *ctx = malloc(sizeof(CEL_PARSE_CONTEXT));
  if (!*ctx) {
    return CEL_RC_MEMORY;
  }

  memset(*ctx, 0, sizeof(CEL_PARSE_CONTEXT));

  SLIST_INIT(&(*ctx)->head);

  for (TPM2_HANDLE pcr=(TPM2_MAX_PCRS-1);pcr < TPM2_MAX_PCRS;pcr--) {
    p = malloc(sizeof(struct pair_entry));
    if (!p) {
      return CEL_RC_MEMORY;
    }
    p->handle = pcr;
    p->recnum = 0;
    SLIST_INSERT_HEAD(&(*ctx)->head, p, entries);
  }

  return 0;
}

void
CEL_Parse_Free(
  CEL_PARSE_CONTEXT **ctx)
{
  struct pair_entry *p = NULL;

  if (!ctx || !*ctx) {
    return;
  }

  while (!SLIST_EMPTY(&(*ctx)->head)) {
    p = SLIST_FIRST(&(*ctx)->head);
    SLIST_REMOVE_HEAD(&(*ctx)->head, entries);
    free(p);
  }

  free(*ctx);
  *ctx = NULL;
}

CEL_RC
CEL_Parse_Get_RECNUM(
  CEL_PARSE_CONTEXT *ctx,
  TPM2_HANDLE handle,
  RECNUM *recnum)
{
  struct pair_entry *p = NULL;

  CHECK_NULL(ctx);
  CHECK_NULL(recnum);

  if (!is_pcr(handle) && !is_nv_index(handle)) {
    return CEL_RC_INVALID_VALUE;
  }

  SLIST_FOREACH(p, &ctx->head, entries) {
    if (p->handle == handle) {
      *recnum = p->recnum++;
      return CEL_RC_SUCCESS;
    }
  }

  p = malloc(sizeof(struct pair_entry));
  if (!p) {
    return CEL_RC_MEMORY;
  }

  p->handle = handle;
  p->recnum = 0;
  SLIST_INSERT_HEAD(&ctx->head, p, entries);
  *recnum = p->recnum++;

  return CEL_RC_SUCCESS;
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

  r = get_le_uint32(buffer, len, &off, &event->handle);
  if (r) {
    return r;
  }

  r = CEL_Parse_Get_RECNUM(ctx, event->handle, &event->recnum);
  if (r) {
    return r;
  }

  r = get_le_uint32(buffer,
		    len,
		    &off,
		    &event->content.pcclient_std.event_type);
  if (r) {
    return r;
  }

  r = get_le_uint32(buffer, len, &off, &num_digs);
  if (r) {
    return r;
  }

  event->digests.count = 0;
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

  r = get_le_uint32(buffer, len, &off, &event->handle);
  if (r) {
    return r;
  }

  r = CEL_Parse_Get_RECNUM(ctx, event->handle, &event->recnum);
  if (r) {
    return r;
  }

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

  r = get_le_uint32(buffer, len, &off, &event->handle);
  if (r) {
    return r;
  }

  r = CEL_Parse_Get_RECNUM(ctx, event->handle, &event->recnum);
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

  memset(event->content.ima_template.template_name,
	 0,
	 sizeof(event->content.ima_template.template_name));
  r = get_string(buffer,
		len,
		&off,
		event->content.ima_template.template_name,
		sizeof(event->content.ima_template.template_name) - 1);
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

CEL_RC
CEL_Parse_SYSTEMD_Event(
  CEL_PARSE_CONTEXT *ctx,
  TPMS_CEL_EVENT *event,
  const uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset);
  int hasit;
  struct json_tokener *jtok = NULL;
  json_object *obj = NULL, *jd = NULL, *jc = NULL;

  CHECK_NULL(ctx);
  CHECK_NULL(event);
  CHECK_NULL(buffer);

  jtok = json_tokener_new();
  if (!jtok) {
    return CEL_RC_MEMORY;
  }
  obj = json_tokener_parse_ex(jtok, (const char *) &buffer[off], len - off);
  if (!obj) {
    r = CEL_RC_INVALID_VALUE;
    goto out;
  }

  if (!json_object_is_type(obj, json_type_object)) {
    r = CEL_RC_INVALID_TYPE;
    goto out;
  }

  r = get_json_content_type(obj, &event->content_type);
  if (r) {
    goto out;
  }

  if (event->content_type != CEL_TYPE_SYSTEMD) {
    r = CEL_RC_INVALID_TYPE;
    goto out;
  }

  r = get_json_handle(obj, &event->handle);
  if (r) {
    goto out;
  }

  hasit = json_object_object_get_ex(obj, "digests", &jd);
  if (!hasit) {
    r = CEL_RC_INVALID_VALUE;
    goto out;
  }
  r = CEL_JSON_TPML_DIGEST_VALUES_Unmarshal(jd, &event->digests);
  if (r) {
    goto out;
  }

  hasit = json_object_object_get_ex(obj, "content", &jc);
  if (!hasit) {
    r = CEL_RC_INVALID_VALUE;
    goto out;
  }

  r = CEL_JSON_TPMS_EVENT_SYSTEMD_Unmarshal(jc, &event->content.systemd);
  if (r) {
    goto out;
  }

  r = CEL_Parse_Get_RECNUM(ctx, event->handle, &event->recnum);
  if (r) {
    goto out;
  }

  off = json_tokener_get_parse_end(jtok) + off;
  set_offset(offset, off);

  r = CEL_RC_SUCCESS;
 out:
  if (jtok) {
    json_tokener_free(jtok);
  }
  return r;
}
