/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <json-c/json_object.h>
#include <stdlib.h>
#include <string.h>
#include "cel_strings.h"
#include "cel_types.h"
#include "cel_json.h"
#include "cel_io.h"


CEL_RC
CEL_JSON_TPMT_HA_Marshal(
  const TPMT_HA *src,
  json_object **obj,
  uint8_t flags
) {
  CEL_RC r;
  int jr;
  size_t diglen = 0;
  const char *algstr = NULL; char hexdig[MAX_DIGEST_HEX + 1];
  json_object *jd = NULL, *ja = NULL, *jh = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);

  jd = json_object_new_object();
  if (!jd) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  if (flags & CEL_JSON_FLAGS_USE_NUMBERS) {
    ja = json_object_new_uint64(src->hashAlg);
  } else {
    algstr = alg_to_str(src->hashAlg);
    if (!algstr) {
      r = CEL_RC_UNSUPPORTED_DIGEST;
      goto fail;
    }
    ja = json_object_new_string(algstr);
  }
  if (!ja) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jr = json_object_object_add(jd, "hashAlg", ja);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  diglen = get_digest_size(src->hashAlg);
  if (!diglen) {
    r = CEL_RC_UNSUPPORTED_DIGEST;
    goto fail;
  }
  r = hexlify(src->digest.sha512, diglen, hexdig, MAX_DIGEST_HEX + 1);
  if (r) {
    goto fail;
  }

  jh = json_object_new_string(hexdig);
  if (!jh) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  r = json_object_object_add(jd, "digest", jh);
  if (r) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  *obj = jd;
  return CEL_RC_SUCCESS;
 fail:
  json_object_put(jd);
  return r;
}

CEL_RC
CEL_JSON_TPML_DIGEST_VALUES_Marshal(
  const TPML_DIGEST_VALUES *src,
  json_object **obj,
  uint8_t flags)
{
  CEL_RC r;
  int jr;
  json_object *ja = NULL, *jd = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);

  ja = json_object_new_array();
  if (!ja) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  for (uint32_t i=0;i < src->count;i++) {
    r = CEL_JSON_TPMT_HA_Marshal(&src->digests[i], &jd, flags);
    if (r) {
      goto fail;
    }
    jr = json_object_array_add(ja, jd);
    if (jr) {
      r = CEL_RC_MEMORY;
      goto fail;
    }
  }
  *obj = ja;
  return CEL_RC_SUCCESS;
 fail:
  json_object_put(ja);
  return r;
}

CEL_RC
CEL_JSON_TPMS_EVENT_PCCLIENT_STD_Marshal(
  const TPMS_EVENT_PCCLIENT_STD *src,
  json_object **obj,
  CEL_JSON_FLAGS flags)
{
  CEL_RC r;
  int jr;
  const char *event_str = NULL;
  char *eventhex = NULL;
  size_t hexlen = 0;
  json_object *je = NULL, *jf = NULL;;

  CHECK_NULL(src);
  CHECK_NULL(obj);

  je = json_object_new_object();
  if (!je) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  if (flags & CEL_JSON_FLAGS_USE_NUMBERS) {
    jf = json_object_new_uint64(src->event_type);
  } else {
    event_str = pcclient_event_to_str(src->event_type);
    if (!event_str) {
      r = CEL_RC_INVALID_TYPE;
      goto fail;
    }
    jf = json_object_new_string(event_str);
  }
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  jr = json_object_object_add(je, "event_type", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  hexlen = (src->event_data.size * 2) + 1;
  eventhex = malloc(hexlen);
  if (!eventhex) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  r = hexlify(src->event_data.buffer,
	      src->event_data.size,
	      eventhex, hexlen);
  if (r) {
    goto fail;
  }

  jf = json_object_new_string(eventhex);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jr = json_object_object_add(je, "event_data", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  free(eventhex);
  *obj = je;
  return CEL_RC_SUCCESS;
 fail:
  free(eventhex);
  json_object_put(je);
  return r;
}

CEL_RC
CEL_JSON_TPMS_EVENT_IMA_TEMPLATE_Marshal(
  const TPMS_EVENT_IMA_TEMPLATE *src,
  json_object **obj)
{
  CEL_RC r;
  int jr;
  char *datahex = NULL;
  size_t hexlen;
  const BYTEBUFFER *name = NULL;
  json_object *jt = NULL, *jf = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);
  name = &src->template_name;

  jt = json_object_new_object();
  if (!jt) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jf = json_object_new_string_len((const char *) name->buffer, name->size);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jr = json_object_object_add(jt, "template_name", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  hexlen = (src->template_data.size * 2) + 1;
  datahex = malloc(hexlen);
  if (!datahex) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  r = hexlify(src->template_data.buffer,
	      src->template_data.size,
	      datahex,
	      hexlen);
  if (r) {
    goto fail;
  }
  jf = json_object_new_string(datahex);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  free(datahex);
  jr = json_object_object_add(jt, "template_data", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  *obj = jt;
  return CEL_RC_SUCCESS;
 fail:
  free(datahex);
  json_object_put(jt);
  return r;
}

CEL_RC
CEL_JSON_TPMS_CEL_VERSION_Marshal(
  const TPMS_CEL_VERSION *src,
  json_object **obj)
{
  CEL_RC r;
  int jr;
  json_object *jv = NULL, *jf = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);

  jv = json_object_new_object();
  if (!jv) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jf = json_object_new_uint64(src->major);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  jr = json_object_object_add(jv, "major", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jf = json_object_new_uint64(src->minor);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  jr = json_object_object_add(jv, "minor", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  *obj = jv;
  return CEL_RC_SUCCESS;
 fail:
  json_object_put(jv);
  return r;
}

CEL_RC
CEL_JSON_TPMS_EVENT_CELMGT_Marshal(
  const TPMS_EVENT_CELMGT *src,
  json_object **obj,
  CEL_JSON_FLAGS flags)
{
  CEL_RC r;
  int jr;
  const char *type_str = NULL, *trans_str = NULL;
  json_object *je = NULL, *jf = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);

  je = json_object_new_object();
  if (!je) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  if (flags & CEL_JSON_FLAGS_USE_NUMBERS) {
    jf = json_object_new_uint64(src->type);
  } else {
    type_str = mgt_type_to_str(src->type);
    if (!type_str) {
      r = CEL_RC_INVALID_TYPE;
      goto fail;
    }
    jf = json_object_new_string(type_str);
  }
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  jr = json_object_object_add(je, "type", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  switch (src->type) {
  case CEL_TYPE_MGMT_CEL_VERSION:
    r = CEL_JSON_TPMS_CEL_VERSION_Marshal(&src->data.cel_version, &jf);
    break;
  case CEL_TYPE_MGMT_FIRMWARE_END:
    goto out;
    break;
  case CEL_TYPE_MGMT_CEL_TIMESTAMP:
    jf = json_object_new_uint64(src->data.cel_timestamp);
    if (!jf) {
      r = CEL_RC_MEMORY;
      goto fail;
    }
    break;
  case CEL_TYPE_MGMT_STATE_TRANS:
    if (flags & CEL_JSON_FLAGS_USE_NUMBERS) {
      jf = json_object_new_uint64(src->data.state_trans);
    } else {
      trans_str = state_trans_to_str(src->data.state_trans);
      if (!trans_str) {
	r = CEL_RC_INVALID_TYPE;
	goto fail;
      }
      jf = json_object_new_string(trans_str);
    }
    break;
  default:
    r = CEL_RC_INVALID_TYPE;
    goto fail;
  }

  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  jr = json_object_object_add(je, "data", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

 out:
  *obj = je;
  return CEL_RC_SUCCESS;
 fail:
  json_object_put(je);
  return r;
}

CEL_RC
CEL_JSON_TPML_EVENT_CELMGT_Marshal(
  const TPML_EVENT_CELMGT *src,
  json_object **obj,
  CEL_JSON_FLAGS flags)
{
  CEL_RC r;
  int jr;
  json_object *jc = NULL, *je = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);

  if (src->count == 1 && !(flags & CEL_JSON_FLAGS_ALWAYS_ARRAY)) {
    r = CEL_JSON_TPMS_EVENT_CELMGT_Marshal(&src->events[0],
					   &jc,
					   flags);
    if (r) {
      goto fail;
    }
    goto out;
  }

  jc = json_object_new_array();
  if (!jc) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  for (int i=0;i < src->count;i++) {
    r = CEL_JSON_TPMS_EVENT_CELMGT_Marshal(&src->events[i],
					   &je,
					   flags);
    if (r) {
      goto fail;
    }
    jr = json_object_array_add(jc, je);
    if (jr) {
      r = CEL_RC_MEMORY;
      goto fail;
    }
  }

 out:
  *obj = jc;
  return CEL_RC_SUCCESS;
 fail:
  json_object_put(jc);
  return r;
}

CEL_RC
CEL_JSON_TPMS_CEL_EVENT_Marshal(
  const TPMS_CEL_EVENT *src,
  json_object **obj,
  CEL_JSON_FLAGS flags)
{
  int jr;
  CEL_RC r;
  const char *content_str = NULL;
  json_object *jo = NULL, *jf = NULL;
  const TPMU_EVENT_CONTENT *cont = NULL;

  CHECK_NULL(src);
  CHECK_NULL(obj);
  cont = &src->content;

  jo = json_object_new_object();
  if (!jo) {
    return CEL_RC_MEMORY;
  }

  jf = json_object_new_uint64(src->recnum);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jr = json_object_object_add(jo, "recnum", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  jf = json_object_new_uint64(src->handle);
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  if (is_nv_index(src->handle)) {
    jr = json_object_object_add(jo, "nv_index", jf);
  } else if (is_pcr(src->handle)) {
    jr = json_object_object_add(jo, "pcr", jf);
  } else {
    json_object_put(jf);
    r = CEL_RC_INVALID_VALUE;
    goto fail;
  }
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  r = CEL_JSON_TPML_DIGEST_VALUES_Marshal(&src->digests, &jf, flags);
  if (r) {
    goto fail;
  }
  jr = json_object_object_add(jo, "digests", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  if (flags & CEL_JSON_FLAGS_USE_NUMBERS) {
    jf = json_object_new_uint64(src->content_type);
  } else {
    content_str = content_type_to_str(src->content_type);
    if (!content_str) {
      r = CEL_RC_INVALID_TYPE;
      goto fail;
    }
    jf = json_object_new_string(content_str);
  }
  if (!jf) {
    r = CEL_RC_MEMORY;
    goto fail;
  }
  jr = json_object_object_add(jo, "content_type", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  switch (src->content_type) {
  case CEL_TYPE_MGMT:
    r = CEL_JSON_TPML_EVENT_CELMGT_Marshal(&cont->celmgt, &jf, flags);
    break;
  case CEL_TYPE_PCCLIENT_STD:
    r = CEL_JSON_TPMS_EVENT_PCCLIENT_STD_Marshal(&cont->pcclient_std,
						 &jf,
						 flags);
    break;
  case CEL_TYPE_IMA_TEMPLATE:
    r = CEL_JSON_TPMS_EVENT_IMA_TEMPLATE_Marshal(&cont->ima_template, &jf);
    break;
  default:
    r = CEL_RC_INVALID_TYPE;
  }
  if (r) {
    goto fail;
  }

  jr = json_object_object_add(jo, "content", jf);
  if (jr) {
    r = CEL_RC_MEMORY;
    goto fail;
  }

  *obj = jo;
  return CEL_RC_SUCCESS;
 fail:
  json_object_put(jo);
  return r;
}

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
CEL_JSON_TPMT_HA_Unmarshal(
  const json_object *obj,
  TPMT_HA *dest)
{
  CEL_RC r;
  uint64_t ti;
  const char *hn = NULL, *hexdig = NULL;
  size_t diglen;
  int hasit;
  json_object *jh = NULL, *jd = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  if (!json_object_is_type(obj, json_type_object)) {
    return CEL_RC_INVALID_TYPE;
  }

  hasit = json_object_object_get_ex(obj, "hashAlg", &jh);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  switch (json_object_get_type(jh)) {
  case json_type_int:
    ti = json_object_get_uint64(jh);
    if (ti > UINT16_MAX) {
      return CEL_RC_INVALID_VALUE;
    }
    dest->hashAlg = ti;
    break;
  case json_type_string:
    hn = json_object_get_string(jh);
    r = str_to_alg(hn, &dest->hashAlg);
    if (r) {
      return r;
    }
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }

  diglen = get_digest_size(dest->hashAlg);
  if (!diglen) {
    return CEL_RC_INVALID_TYPE;
  }

  hasit = json_object_object_get_ex(obj, "digest", &jd);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  if (!json_object_is_type(jd, json_type_string)) {
    return CEL_RC_INVALID_TYPE;
  }

  hexdig = json_object_get_string(jd);

  if (strlen(hexdig) != diglen * 2) {
    return CEL_RC_INVALID_VALUE;
  }

  r = unhexlify(hexdig, (uint8_t *) &dest->digest.sha512, diglen);
  if (r) {
    return r;
  }

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPML_DIGEST_VALUES_Unmarshal(
  const json_object *obj,
  TPML_DIGEST_VALUES *dest)
{
  CEL_RC r;
  size_t len;
  json_object *jd = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  if (!json_object_is_type(obj, json_type_array)) {
    return CEL_RC_INVALID_TYPE;
  }

  dest->count = 0;

  len = json_object_array_length(obj);
  for (size_t i=0;i < len && i < TPM2_NUM_PCR_BANKS;i++) {
    dest->count++;
    jd = json_object_array_get_idx(obj, i);
    if (!jd) {
      return CEL_RC_MEMORY;
    }
    r = CEL_JSON_TPMT_HA_Unmarshal(jd, &dest->digests[i]);
    if (r) {
      return r;
    }
  }
  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPMS_CEL_VERSION_Unmarshal(
  const json_object *obj,
  TPMS_CEL_VERSION *dest)
{
  uint64_t ti;
  int hasit;
  json_object *ja = NULL, *ji = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  hasit = json_object_object_get_ex(obj, "major", &ja);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }
  ti = json_object_get_uint64(ja);
  if (ti > UINT16_MAX) {
    return CEL_RC_INVALID_VALUE;
  }
  dest->major = ti;

  hasit = json_object_object_get_ex(obj, "minor", &ji);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }
  ti = json_object_get_uint64(ji);
  if (ti > UINT16_MAX) {
    return CEL_RC_INVALID_VALUE;
  }
  dest->minor = ti;

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPMI_STATE_TRANS_Unmarshal(
  const json_object *obj,
  TPMI_STATE_TRANS *dest)
{
  CEL_RC r;
  uint64_t ti;
  const char *ts = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  switch (json_object_get_type(obj)) {
  case json_type_int:
    ti = json_object_get_uint64(obj);
    if (ti > UINT32_MAX) {
      return CEL_RC_INVALID_VALUE;
    }
    *dest = ti;
    break;
  case json_type_string:
    ts = json_object_get_string((json_object *) obj);
    r = str_to_state_trans(ts, dest);
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
CEL_JSON_TPMS_EVENT_CELMGT_Unmarshal(
  const json_object *obj,
  TPMS_EVENT_CELMGT *dest)
{
  CEL_RC r;
  int hasit;
  uint64_t ti;
  const char *ts;
  json_object *jt = NULL, *jd = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  hasit = json_object_object_get_ex(obj, "type", &jt);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  switch (json_object_get_type(jt)) {
  case json_type_int:
    ti = json_object_get_uint64(jt);
    if (ti > UINT8_MAX) {
      return CEL_RC_INVALID_VALUE;
    }
    dest->type = ti;
    break;
  case json_type_string:
    ts = json_object_get_string(jt);
    r = str_to_mgt_type(ts, &dest->type);
    if (r) {
      return r;
    }
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }

  hasit = json_object_object_get_ex(obj, "data", &jd);
  if (!hasit && dest->type != CEL_TYPE_MGMT_FIRMWARE_END) {
    return CEL_RC_INVALID_VALUE;
  }

  switch (dest->type) {
  case CEL_TYPE_MGMT_CEL_VERSION:
    r = CEL_JSON_TPMS_CEL_VERSION_Unmarshal(jd, &dest->data.cel_version);
    break;
  case CEL_TYPE_MGMT_FIRMWARE_END:
    r = CEL_RC_SUCCESS;
    break;
  case CEL_TYPE_MGMT_CEL_TIMESTAMP:
    r = get_json_number(obj, "data", &dest->data.cel_timestamp);
    break;
  case CEL_TYPE_MGMT_STATE_TRANS:
    r = CEL_JSON_TPMI_STATE_TRANS_Unmarshal(jd, &dest->data.state_trans);
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }
  if (r) {
    return r;
  }

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPML_EVENT_CELMGT_Unmarshal(
  const json_object *obj,
  TPML_EVENT_CELMGT *dest)
{
  CEL_RC r;
  size_t len;
  json_object *je = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  dest->count = 0;
  switch (json_object_get_type(obj)) {
  case json_type_object:
    r = CEL_JSON_TPMS_EVENT_CELMGT_Unmarshal(obj, &dest->events[0]);
    if (!r) {
      dest->count++;
    }
    return r;
    break;
  case json_type_array:
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }

  len = json_object_array_length(obj);
  for (size_t i=0;i < len && i < 16;i++) {
    je = json_object_array_get_idx(obj, i);
    r = CEL_JSON_TPMS_EVENT_CELMGT_Unmarshal(je, &dest->events[i]);
    if (r) {
      return r;
    }
    dest->count++;
  }
  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPMS_EVENT_PCCLIENT_STD_Unmarshal(
  const json_object *obj,
  TPMS_EVENT_PCCLIENT_STD *dest)
{
  CEL_RC r;
  uint64_t ti;
  const char *ts = NULL, *hexevent = NULL;
  int hasit;
  uint32_t el;
  json_object *jt = NULL, *je = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  hasit = json_object_object_get_ex(obj, "event_type", &jt);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  switch (json_object_get_type(jt)) {
  case json_type_int:
    ti = json_object_get_uint64(jt);
    if (ti > UINT32_MAX) {
      return CEL_RC_INVALID_VALUE;
    }
    dest->event_type = ti;
    break;
  case json_type_string:
    ts = json_object_get_string(jt);
    r = str_to_pcclient_event(ts, &dest->event_type);
    if (r) {
      return r;
    }
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }

  hasit = json_object_object_get_ex(obj, "event_data", &je);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }
  if (!json_object_is_type(je, json_type_string)) {
    return CEL_RC_INVALID_TYPE;
  }

  hexevent = json_object_get_string(je);
  el = strlen(hexevent) / 2;

  r = unhexlify(hexevent, dest->event_data.buffer, el);
  if (r) {
    return r;
  }
  dest->event_data.size = el;

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(
  const json_object *obj,
  TPMS_EVENT_IMA_TEMPLATE *dest)
{
  CEL_RC r;
  int hasit;
  size_t len;
  const char *nstr = NULL, *hex = NULL;
  json_object *jn = NULL, *jd = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);

  hasit = json_object_object_get_ex(obj, "template_name", &jn);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }
  if (!json_object_is_type(jn, json_type_string)) {
    return CEL_RC_INVALID_TYPE;
  }
  nstr = json_object_get_string(jn);
  len = strlen(nstr);
  if (len > sizeof(dest->template_name.buffer) - 1) {
    return CEL_RC_SHORT_BUFFER;
  }
  memcpy(dest->template_name.buffer, nstr, len);
  dest->template_name.size = len;
  dest->template_name.buffer[len] = '\x00';

  hasit = json_object_object_get_ex(obj, "template_data", &jd);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }
  if (!json_object_is_type(jd, json_type_string)) {
    return CEL_RC_INVALID_TYPE;
  }

  hex = json_object_get_string(jd);
  r = unhexlify(hex,
		dest->template_data.buffer,
		sizeof(dest->template_data.buffer));
  if (r) {
    return r;
  }
  dest->template_data.size = strlen(hex) / 2;

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_JSON_TPMS_CEL_EVENT_Unmarshal(
  const json_object *obj,
  TPMS_CEL_EVENT *dest)
{
  CEL_RC r;
  int hasit;
  uint64_t ti;
  const char *ts = NULL;
  json_object *jd = NULL, *jt = NULL, *jc = NULL;
  TPMU_EVENT_CONTENT *cont = NULL;

  CHECK_NULL(obj);
  CHECK_NULL(dest);
  cont = &dest->content;

  r = get_json_number(obj, "recnum", &dest->recnum);
  if (r) {
    return r;
  }

  r = get_json_handle(obj, &dest->handle);
  if (r) {
    return r;
  }

  hasit = json_object_object_get_ex(obj, "digests", &jd);
  if (hasit) {
    r = CEL_JSON_TPML_DIGEST_VALUES_Unmarshal(jd, &dest->digests);
    if (r) {
      return r;
    }
  } else {
    dest->digests.count = 0;
  }

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
    dest->content_type = ti;
    break;
  case json_type_string:
    ts = json_object_get_string(jt);
    r = str_to_content_type(ts, &dest->content_type);
    if (r) {
      return r;
    }
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }

  hasit = json_object_object_get_ex(obj, "content", &jc);
  if (!hasit) {
    return CEL_RC_INVALID_VALUE;
  }

  switch (dest->content_type) {
  case CEL_TYPE_MGMT:
    r = CEL_JSON_TPML_EVENT_CELMGT_Unmarshal(jc, &cont->celmgt);
    break;
  case CEL_TYPE_PCCLIENT_STD:
    r = CEL_JSON_TPMS_EVENT_PCCLIENT_STD_Unmarshal(jc, &cont->pcclient_std);
    break;
  case CEL_TYPE_IMA_TEMPLATE:
    r = CEL_JSON_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(jc, &cont->ima_template);
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }
  if (r) {
    return r;
  }

  return CEL_RC_SUCCESS;
}
